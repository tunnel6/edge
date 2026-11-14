package letsencrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

const TLSALPN01Protocol = "acme-tls/1"

var (
	ErrTLSALPN01HandlerRequired          = errors.New("letsencrypt: tls-alpn-01 handler is required")
	ErrTLSALPN01KeyAuthorizationRequired = errors.New("letsencrypt: tls-alpn-01 key authorization is required")
	oidPEACMEIdentifier                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
)

type TLSALPN01Handler struct {
	mu         sync.RWMutex
	challenges map[string]map[string]*tls.Certificate
}

func NewTLSALPN01Handler() *TLSALPN01Handler {
	return &TLSALPN01Handler{
		challenges: make(map[string]map[string]*tls.Certificate),
	}
}

func (h *TLSALPN01Handler) Set(domain, token, keyAuthorization string) error {
	if h == nil {
		return ErrTLSALPN01HandlerRequired
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return ErrInvalidDomain
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInvalidChallenge
	}
	keyAuthorization = strings.TrimSpace(keyAuthorization)
	if keyAuthorization == "" {
		return ErrTLSALPN01KeyAuthorizationRequired
	}

	cert, err := buildTLSALPN01ChallengeCert(domain, keyAuthorization)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	tokens := h.challenges[domain]
	if tokens == nil {
		tokens = make(map[string]*tls.Certificate)
		h.challenges[domain] = tokens
	}
	tokens[token] = cert
	return nil
}

func (h *TLSALPN01Handler) Delete(domain, token string) {
	if h == nil {
		return
	}
	domain = normalizeDomain(domain)
	token = strings.TrimSpace(token)
	if domain == "" || token == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	tokens := h.challenges[domain]
	if tokens == nil {
		return
	}
	delete(tokens, token)
	if len(tokens) == 0 {
		delete(h.challenges, domain)
	}
}

// DeleteDomain removes all tls-alpn-01 challenge tokens for the given domain.
func (h *TLSALPN01Handler) DeleteDomain(domain string) {
	if h == nil {
		return
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}

	h.mu.Lock()
	delete(h.challenges, domain)
	h.mu.Unlock()
}

func (h *TLSALPN01Handler) Resolve(hello *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	if h == nil || hello == nil {
		return nil, false
	}
	if !containsProto(hello.SupportedProtos, TLSALPN01Protocol) {
		return nil, false
	}
	domain := normalizeDomain(hello.ServerName)
	if domain == "" {
		return nil, false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	tokens := h.challenges[domain]
	if len(tokens) == 0 {
		return nil, false
	}
	for _, cert := range tokens {
		if cert != nil {
			return cert, true
		}
	}
	return nil, false
}

func containsProto(protos []string, target string) bool {
	for _, proto := range protos {
		if strings.TrimSpace(proto) == target {
			return true
		}
	}
	return false
}

func buildTLSALPN01ChallengeCert(identifier, keyAuthorization string) (*tls.Certificate, error) {
	identifier = normalizeDomain(identifier)
	if identifier == "" {
		return nil, ErrInvalidDomain
	}
	keyAuthorization = strings.TrimSpace(keyAuthorization)
	if keyAuthorization == "" {
		return nil, ErrTLSALPN01KeyAuthorizationRequired
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate tls-alpn-01 private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate tls-alpn-01 serial number: %w", err)
	}
	if serialNumber.Sign() == 0 {
		serialNumber = big.NewInt(1)
	}

	keyAuthDigest := sha256.Sum256([]byte(keyAuthorization))
	acmeExtValue, err := asn1.Marshal(keyAuthDigest[:])
	if err != nil {
		return nil, fmt.Errorf("marshal tls-alpn-01 extension value: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identifier,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidPEACMEIdentifier,
				Critical: true,
				Value:    acmeExtValue,
			},
		},
	}
	if ip := net.ParseIP(identifier); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{identifier}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create tls-alpn-01 certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal tls-alpn-01 private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse tls-alpn-01 key pair: %w", err)
	}
	return &pair, nil
}
