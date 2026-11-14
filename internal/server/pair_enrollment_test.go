package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
)

type enrollmentIssuer struct{ request *IssueRequest }

func (i *enrollmentIssuer) Issue(_ context.Context, request *IssueRequest) (*CertIssueResult, error) {
	i.request = request
	return &CertIssueResult{ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type enrollmentInviteVerifier struct{}

func (enrollmentInviteVerifier) Peek(string) (string, string, error) {
	return "network-a", "owner", nil
}

// Exercise the real framed certificate request over TLS without opening a socket.
func enrollmentExchange(t *testing.T, server *Server, request *fb.CertRequestT, role string) fb.MessageType {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	serverConn := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13})
	clientConn := tls.Client(b, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) // In-memory test certificate only.
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		if role == "" {
			server.handleCertRequestOnly(serverConn)
		} else {
			protocol := NewProtocol()
			message, readErr := protocol.ReadMessage(serverConn)
			if readErr == nil {
				_ = server.handleClientCertRequestForSession(&Session{Conn: serverConn, Protocol: protocol, UserID: "device:test_device", DeviceID: "test_device", Role: role, ScopeClaims: []string{"network:original"}}, message)
			}
		}
	}()
	message := &fb.MessageT{Header: &fb.MessageHeaderT{Type: fb.MessageTypeCERT_REQUEST}, Body: &fb.MessageBodyT{Type: fb.MessageBodyCertRequest, Value: request}}
	builder := flatbuffers.NewBuilder(1024)
	builder.Finish(message.Pack(builder))
	protocol := NewProtocol()
	if err := protocol.WriteMessage(clientConn, builder.FinishedBytes()); err != nil {
		t.Fatal(err)
	}
	response, err := protocol.ReadMessage(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("certificate handler did not finish")
	}
	return response.Header(nil).Type()
}

func TestCertificateEnrollmentRequiresTokenAndPreservesAuthority(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "owner_attacker"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	for _, test := range []struct{ name, token, sessionRole, wantRole string }{
		{"anonymous", "", "", ""},
		{"unverified OAuth", "oauth:github:unverified", "", ""},
		{"invalid pair token", "pair:invalid", "", ""},
		{"device pair", "pair:device", "", certmgr.RoleDevice},
		{"owner pair", "pair:owner", "", certmgr.RoleOwner},
		{"invite cannot request wildcard", "invite:invite", "", certmgr.RoleDevice},
		{"renewal rejects credential switch", "pair:owner", certmgr.RoleDevice, ""},
		{"device renewal retains scopes", "", certmgr.RoleDevice, certmgr.RoleDevice},
		{"invite merges authenticated scopes", "invite:invite", certmgr.RoleDevice, certmgr.RoleDevice},
		{"invalid token whitespace", " invite:invite", "", ""},
		{"owner renewal retains role", "", certmgr.RoleOwner, certmgr.RoleOwner},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager := NewPairingManager("")
			manager.RegisterTokenForRole("device", certmgr.RoleDevice)
			manager.RegisterTokenForRole("owner", certmgr.RoleOwner)
			issuer := &enrollmentIssuer{}
			server := &Server{config: &config.Config{Node: config.NodeConfig{ID: "edge-a"}}, pairTokenVerifier: manager, inviteVerifier: enrollmentInviteVerifier{}, certIssuer: issuer}
			kind := enrollmentExchange(t, server, &fb.CertRequestT{Token: test.token, DeviceId: "test_device", Csr: csrPEM, Scopes: []string{"*"}}, test.sessionRole)
			if test.wantRole == "" {
				if kind != fb.MessageTypeERROR || issuer.request != nil {
					t.Fatalf("unauthorized issuance: response=%v request=%+v", kind, issuer.request)
				}
				return
			}
			if kind != fb.MessageTypeCERT_RESPONSE || issuer.request == nil || issuer.request.Role != test.wantRole || issuer.request.EdgeID != "edge-a" {
				t.Fatalf("wrong authorization: response=%v request=%+v", kind, issuer.request)
			}
			wantScopes := []string{"*"}
			if test.sessionRole != "" {
				wantScopes = []string{"network:original"}
				if test.token == "invite:invite" {
					wantScopes = append(wantScopes, "network:network-a")
				}
			} else if test.token == "invite:invite" {
				wantScopes = []string{"network:network-a"}
			}
			if !reflect.DeepEqual(issuer.request.Scopes, wantScopes) {
				t.Fatalf("scope escalation: got=%v want=%v", issuer.request.Scopes, wantScopes)
			}
		})
	}
}
