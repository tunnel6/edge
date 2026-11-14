package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
)

const maxDomainCertificatePEM = 256 * 1024

func (s *Server) handleDomainCertificateRequest(session *Session, msg *fb.Message) error {
	seq := msg.Header(nil).Seq()
	respond := func(err error) error {
		return session.Protocol.sendDomainCertificateResponse(session.Conn, session.ID, seq, err)
	}
	if !(sessionOwnerVerifier{session: session}).IsEdgeOwner(session.UserID) {
		return respond(fmt.Errorf("permission denied: only Edge Owner can upload domain certificates"))
	}
	if s.httpsCertSvc == nil {
		return respond(fmt.Errorf("HTTPS channels are not enabled"))
	}
	if msg.BodyType() != fb.MessageBodyEdgeDomainCertificateRequest {
		return respond(fmt.Errorf("invalid domain certificate request"))
	}
	var table flatbuffers.Table
	if !msg.Body(&table) {
		return respond(fmt.Errorf("missing domain certificate request"))
	}
	var req fb.EdgeDomainCertificateRequest
	req.Init(table.Bytes, table.Pos)
	return respond(s.httpsCertSvc.ImportWildcardCertificate(string(req.Domain()), req.CertificatePem(), req.PrivateKeyPem()))
}

// ImportWildcardCertificate uses the same files and resolver as DNS-01 issuance.
// Validate the complete material before touching the active certificate.
func (s *HTTPSCertService) ImportWildcardCertificate(domain string, certPEM, keyPEM []byte) error {
	domain = normalizeCertDomain(domain)
	assigned := normalizeCertDomain(s.AssignedBaseDomain())
	custom := ""
	if s.domainProvider != nil {
		custom = normalizeCertDomain(s.domainProvider.GetCustomDomain())
	}
	if domain == "" || (domain != assigned && domain != custom) {
		return fmt.Errorf("certificate domain must match a configured Edge domain")
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(certPEM) > maxDomainCertificatePEM || len(keyPEM) > maxDomainCertificatePEM {
		return fmt.Errorf("certificate and private key are required and must each be at most 256 KiB")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("invalid certificate or private key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid leaf certificate: %w", err)
	}
	wildcard := "*." + domain
	hasWildcard := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, wildcard) {
			hasWildcard = true
		}
	}
	if !hasWildcard || leaf.VerifyHostname("yat-cert-check."+domain) != nil {
		return fmt.Errorf("certificate must cover %s", wildcard)
	}
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate must be a currently valid server certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			serverAuth = serverAuth || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
		}
		if !serverAuth {
			return fmt.Errorf("certificate does not permit TLS server authentication")
		}
	}
	// An Owner may replace a pending manual DNS-01 request with an upload.
	s.certOperationMu.Lock()
	if s.certUploads == nil {
		s.certUploads = make(map[string]int)
	}
	s.certUploads[wildcard]++
	for _, cancel := range s.certOperations[wildcard] {
		cancel()
	}
	s.certOperationMu.Unlock()
	defer func() {
		s.certOperationMu.Lock()
		s.certUploads[wildcard]--
		if s.certUploads[wildcard] == 0 {
			delete(s.certUploads, wildcard)
		}
		s.certOperationMu.Unlock()
	}()
	unlock := s.lockDomain(wildcard)
	defer unlock()
	s.certFileMu.Lock()
	defer s.certFileMu.Unlock()
	if err := os.MkdirAll(s.certDir, 0700); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	base := filepath.Join(s.certDir, sanitizeCertDomainForFile(wildcard))
	// Stage both files before replacing either active file.
	stage := func(suffix string, data []byte, mode os.FileMode) (string, error) {
		file, err := os.CreateTemp(s.certDir, ".domain-cert-"+suffix)
		if err != nil {
			return "", err
		}
		name := file.Name()
		if err = file.Chmod(mode); err == nil {
			_, err = file.Write(data)
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(name)
			return "", err
		}
		return name, nil
	}
	certFile, err := stage("crt", certPEM, 0644)
	if err != nil {
		return fmt.Errorf("stage certificate: %w", err)
	}
	defer os.Remove(certFile)
	keyFile, err := stage("key", keyPEM, 0600)
	if err != nil {
		return fmt.Errorf("stage private key: %w", err)
	}
	defer os.Remove(keyFile)
	oldKey, oldKeyErr := os.ReadFile(base + ".key")
	if err = os.Rename(keyFile, base+".key"); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	if err = os.Rename(certFile, base+".crt"); err != nil {
		if oldKeyErr == nil {
			_ = os.WriteFile(base+".key", oldKey, 0600)
		} else {
			_ = os.Remove(base + ".key")
		}
		return fmt.Errorf("save certificate: %w", err)
	}
	_ = os.Remove(base + ".chain.crt") // Full chain is supplied in certPEM.
	_ = os.Remove(base + ".json")      // Remove metadata for a previously issued certificate.
	s.cacheMu.Lock()
	s.certCache = make(map[string]*tls.Certificate)
	s.cacheMu.Unlock()
	s.recordCertIssueSuccess(wildcard)
	s.clearChallengeStateOnCertReady(wildcard)
	return nil
}
