package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/letsencrypt"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
)

func wildcardTestPEM(t *testing.T, name string, until time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: until, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestWildcardCertificateImportValidationAndReload(t *testing.T) {
	dir := t.TempDir()
	dp := config.NewDomainConfig("")
	dp.SetAssignedDomain("files.example.com")
	le, err := letsencrypt.NewBuilder(letsencrypt.WithDataDir(dir), letsencrypt.WithPreferredMethods(letsencrypt.ChallengeDNS01), letsencrypt.WithDNS01Provider("manual"), letsencrypt.WithDNS01Executor(func(context.Context, *letsencrypt.DNS01Request) error { return nil })).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	svc := &HTTPSCertService{le: le, certDir: le.Options().CertDir, domainProvider: dp, domainLocks: map[string]*sync.Mutex{}, certCache: map[string]*tls.Certificate{}, certIssues: map[string]CertIssueStatus{}, activeDNS01: map[string]*ActiveDNS01Challenge{}}
	cert, key := wildcardTestPEM(t, "*.files.example.com", time.Now().Add(90*24*time.Hour))
	if err := svc.ImportWildcardCertificate("files.example.com", cert, key); err != nil {
		t.Fatal(err)
	}
	first, err := svc.GetTLSCertificate("one.files.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !svc.HasUsableCertificateForServerName("two.files.example.com") {
		t.Fatal("uploaded certificate not visible to existing status checks")
	}
	keyInfo, err := os.Stat(filepath.Join(svc.certDir, "wildcard.files.example.com.key"))
	if err != nil || keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions: %v, %v", keyInfo, err)
	}
	wrongCert, wrongKey := wildcardTestPEM(t, "*.other.example.com", time.Now().Add(90*24*time.Hour))
	expiredCert, expiredKey := wildcardTestPEM(t, "*.files.example.com", time.Now().Add(-time.Second))
	for _, test := range []struct {
		name, domain string
		cert, key    []byte
	}{
		{"wrong base domain", "other.example.com", cert, key},
		{"wrong wildcard", "files.example.com", wrongCert, wrongKey},
		{"wrong key", "files.example.com", cert, wrongKey},
		{"expired", "files.example.com", expiredCert, expiredKey},
		{"oversized", "files.example.com", make([]byte, maxDomainCertificatePEM+1), key},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := svc.ImportWildcardCertificate(test.domain, test.cert, test.key); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	current, err := svc.GetTLSCertificate("one.files.example.com")
	if err != nil || !bytes.Equal(current.Certificate[0], first.Certificate[0]) {
		t.Fatal("invalid upload replaced the active certificate")
	}
	replacement, replacementKey := wildcardTestPEM(t, "*.files.example.com", time.Now().Add(90*24*time.Hour))
	if err := svc.ImportWildcardCertificate("files.example.com", replacement, replacementKey); err != nil {
		t.Fatal(err)
	}
	current, err = svc.GetTLSCertificate("one.files.example.com")
	if err != nil || bytes.Equal(current.Certificate[0], first.Certificate[0]) {
		t.Fatal("cached SNI certificate was not refreshed")
	}
}

func TestDomainCertificateUploadIsOwnerOnly(t *testing.T) {
	for _, role := range []string{certmgr.RoleDevice, certmgr.RoleOwner} {
		t.Run(role, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(time.Second))
			_ = b.SetDeadline(time.Now().Add(time.Second))
			server := &Server{}
			cert, key := wildcardTestPEM(t, "*.files.example.com", time.Now().Add(time.Hour))
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			serverConn := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{pair}})
			clientConn := tls.Client(b, &tls.Config{InsecureSkipVerify: true}) // in-memory test certificate
			builder := flatbuffers.NewBuilder(256)
			request := &fb.MessageT{Header: &fb.MessageHeaderT{Type: fb.MessageTypeEDGE_DOMAIN_CERTIFICATE_REQUEST, Seq: 42}, Body: &fb.MessageBodyT{Type: fb.MessageBodyEdgeDomainCertificateRequest, Value: &fb.EdgeDomainCertificateRequestT{Domain: "files.example.com"}}}
			builder.Finish(request.Pack(builder))
			done := make(chan error, 1)
			go func() {
				done <- server.handleDomainCertificateRequest(&Session{Conn: serverConn, Protocol: NewProtocol(), ID: "s", UserID: "device:d", Role: role}, fb.GetRootAsMessage(builder.FinishedBytes(), 0))
			}()
			response, err := NewProtocol().ReadMessage(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if response.Header(nil).Seq() != 42 {
				t.Fatal("request sequence lost")
			}
			var table flatbuffers.Table
			response.Body(&table)
			var result fb.EdgeDomainCertificateResponse
			result.Init(table.Bytes, table.Pos)
			message := string(result.ErrorMessage())
			if role == certmgr.RoleDevice && !strings.Contains(message, "permission denied") {
				t.Fatalf("device bypassed Owner gate: %s", message)
			}
			if role == certmgr.RoleOwner && !strings.Contains(message, "not enabled") {
				t.Fatalf("unexpected Owner result: %s", message)
			}
		})
	}
}

func TestCertificateUploadCancelsPendingIssuance(t *testing.T) {
	dp := config.NewDomainConfig("")
	dp.SetAssignedDomain("files.example.com")
	started := make(chan struct{})
	le, err := letsencrypt.NewBuilder(
		letsencrypt.WithDataDir(t.TempDir()),
		letsencrypt.WithPreferredMethods(letsencrypt.ChallengeDNS01),
		letsencrypt.WithDNS01Provider("manual"),
		letsencrypt.WithChallengeCredentialRequester(func(context.Context, *letsencrypt.ChallengeCredentialRequest) (*letsencrypt.ChallengeCredential, error) {
			return &letsencrypt.ChallengeCredential{Token: "test-token", KeyAuthorization: "test-value"}, nil
		}),
		letsencrypt.WithDNS01Executor(func(ctx context.Context, _ *letsencrypt.DNS01Request) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}),
	).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	svc := &HTTPSCertService{le: le, certDir: le.Options().CertDir, domainProvider: dp, domainLocks: map[string]*sync.Mutex{}, certCache: map[string]*tls.Certificate{}, certIssues: map[string]CertIssueStatus{}, activeDNS01: map[string]*ActiveDNS01Challenge{}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := svc.EnsureAssignedDomain(ctx)
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("issuance did not reach DNS-01")
	}
	cert, key := wildcardTestPEM(t, "*.files.example.com", time.Now().Add(time.Hour))
	if err := svc.ImportWildcardCertificate("files.example.com", cert, key); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("pending issuance was not canceled: %v", err)
	}
	if !svc.HasUsableCertificate("*.files.example.com") {
		t.Fatal("uploaded certificate is not ready")
	}
	if lastError, _ := svc.GetCertificateIssueStatus("*.files.example.com"); lastError != "" {
		t.Fatalf("stale issuance error after upload: %s", lastError)
	}
}

func TestStandaloneAssignedDomainUsesManualDNS01(t *testing.T) {
	dp := config.NewDomainConfig("")
	dp.SetAssignedDomain("files.example.com")
	svc := &HTTPSCertService{domainProvider: dp, activeDNS01: map[string]*ActiveDNS01Challenge{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.buildDNS01Executor(nil)(ctx, &letsencrypt.DNS01Request{Domain: "*.files.example.com", KeyAuthorization: "txt-token"})
	if err == nil || !strings.Contains(err.Error(), "manual dns-01 required") || !errors.Is(err, context.Canceled) {
		t.Fatalf("standalone assigned domain did not enter manual DNS-01: %v", err)
	}
	challenges := svc.GetActiveDNS01Challenges()
	if len(challenges) != 1 || challenges[0].RecordName != "_acme-challenge.files.example.com" || challenges[0].RecordValue != "txt-token" {
		t.Fatalf("challenge was not exposed to existing status checks: %+v", challenges)
	}
}
