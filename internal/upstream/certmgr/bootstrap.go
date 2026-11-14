package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

// StandaloneBootstrapConfig contains the configuration for standalone (OSS) bootstrap.
type StandaloneBootstrapConfig struct {
	EdgeID  string
	CertDir string
	// PublicAddress is the public address of the edge (for TLS cert SAN).
	PublicAddress string
	// CustomDomain is an optional custom domain (for TLS cert SAN).
	CustomDomain string
}

// StandaloneBootstrapResult contains the result of standalone bootstrap.
type StandaloneBootstrapResult struct {
	CACertPath  string
	CAKeyPath   string
	TLSCertPath string
	TLSKeyPath  string

	CACertPEM  []byte
	CAKeyPEM   []byte
	TLSCertPEM []byte
	TLSKeyPEM  []byte

	CACert    *x509.Certificate
	TLSCert   *x509.Certificate
	ExpiresAt time.Time
}

// StandaloneBootstrap generates a self-signed CA and TLS certificate for OSS mode.
// The single CA serves as both the root CA (for FE trust) and the signing CA
// (for TLS and client certificates).
func StandaloneBootstrap(cfg *StandaloneBootstrapConfig) (*StandaloneBootstrapResult, error) {
	logger.Infof("[oss] starting standalone bootstrap, edge_id: %s", cfg.EdgeID)

	if cfg.EdgeID == "" {
		return nil, fmt.Errorf("edge_id is required for standalone bootstrap")
	}
	if cfg.CertDir == "" {
		return nil, fmt.Errorf("cert_dir is required for standalone bootstrap")
	}

	// Check for existing certs
	if result, err := loadStandaloneCerts(cfg.CertDir); err == nil && result != nil {
		if isCertValid(result.TLSCert) {
			logger.Info("[oss] existing certificates are valid, reusing",
				"ca_cn", result.CACert.Subject.CommonName,
				"tls_expires", result.TLSCert.NotAfter)
			return result, nil
		}
		logger.Info("[oss] existing certificates expired, regenerating")
	}

	// Ensure cert directory exists
	if err := os.MkdirAll(cfg.CertDir, 0700); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}

	// Generate CA
	caKey, caCert, caCertPEM, caKeyPEM, err := generateCA(cfg.EdgeID)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Generate TLS cert
	_, tlsCert, tlsCertPEM, tlsKeyPEM, err := generateTLSCert(
		caKey, caCert, cfg.EdgeID, cfg.PublicAddress, cfg.CustomDomain,
	)
	if err != nil {
		return nil, fmt.Errorf("generate TLS cert: %w", err)
	}

	// Save to disk with standard file names expected by loadLocalCertificates
	// In OSS mode, the single CA serves as both Sub-CA and Root-CA
	subCACertPath := filepath.Join(cfg.CertDir, "edge-sub-ca.crt")
	subCAKeyPath := filepath.Join(cfg.CertDir, "edge-sub-ca.key")
	rootCACertPath := filepath.Join(cfg.CertDir, "root-ca.crt")
	tlsCertPath := filepath.Join(cfg.CertDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(cfg.CertDir, "edge-tls.key")

	if err := os.WriteFile(subCACertPath, caCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("write sub CA cert: %w", err)
	}
	if err := os.WriteFile(subCAKeyPath, caKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write sub CA key: %w", err)
	}
	// Same CA cert acts as root CA in OSS mode
	if err := os.WriteFile(rootCACertPath, caCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("write root CA cert: %w", err)
	}
	if err := os.WriteFile(tlsCertPath, tlsCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("write TLS cert: %w", err)
	}
	if err := os.WriteFile(tlsKeyPath, tlsKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("write TLS key: %w", err)
	}

	logger.Info("standalone bootstrap completed",
		"ca_cn", caCert.Subject.CommonName,
		"ca_expires", caCert.NotAfter,
		"tls_expires", tlsCert.NotAfter,
		"cert_dir", cfg.CertDir,
	)

	return &StandaloneBootstrapResult{
		CACertPath:  subCACertPath,
		CAKeyPath:   subCAKeyPath,
		TLSCertPath: tlsCertPath,
		TLSKeyPath:  tlsKeyPath,
		CACertPEM:   caCertPEM,
		CAKeyPEM:    caKeyPEM,
		TLSCertPEM:  tlsCertPEM,
		TLSKeyPEM:   tlsKeyPEM,
		CACert:      caCert,
		TLSCert:     tlsCert,
		ExpiresAt:   tlsCert.NotAfter,
	}, nil
}

// loadStandaloneCerts attempts to load existing standalone certificates.
// In OSS mode, the single CA serves as both Sub-CA and Root-CA.
func loadStandaloneCerts(certDir string) (*StandaloneBootstrapResult, error) {
	// Use standard file names expected by loadLocalCertificates
	subCACertPath := filepath.Join(certDir, "edge-sub-ca.crt")
	subCAKeyPath := filepath.Join(certDir, "edge-sub-ca.key")
	tlsCertPath := filepath.Join(certDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(certDir, "edge-tls.key")

	caCertPEM, err := os.ReadFile(subCACertPath)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := os.ReadFile(subCAKeyPath)
	if err != nil {
		return nil, err
	}
	tlsCertPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, err
	}
	tlsKeyPEM, err := os.ReadFile(tlsKeyPath)
	if err != nil {
		return nil, err
	}

	caCert, err := parseCertPEM(caCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	tlsCert, err := parseCertPEM(tlsCertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse TLS cert: %w", err)
	}

	return &StandaloneBootstrapResult{
		CACertPath:  subCACertPath,
		CAKeyPath:   subCAKeyPath,
		TLSCertPath: tlsCertPath,
		TLSKeyPath:  tlsKeyPath,
		CACertPEM:   caCertPEM,
		CAKeyPEM:    caKeyPEM,
		TLSCertPEM:  tlsCertPEM,
		TLSKeyPEM:   tlsKeyPEM,
		CACert:      caCert,
		TLSCert:     tlsCert,
		ExpiresAt:   tlsCert.NotAfter,
	}, nil
}

// generateCA creates a self-signed CA certificate.
func generateCA(edgeID string) (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("yat-edge-%s-ca", edgeID),
			Organization: []string{"YAT Edge"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create CA cert: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	return caKey, caCert, caCertPEM, caKeyPEM, nil
}

// generateTLSCert creates a TLS server certificate signed by the CA.
func generateTLSCert(
	caKey *ecdsa.PrivateKey,
	caCert *x509.Certificate,
	edgeID, publicAddress, customDomain string,
) (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build SAN list
	var dnsNames []string
	var ipAddrs []net.IP

	// Always include localhost
	dnsNames = append(dnsNames, "localhost")

	// Parse public address
	if publicAddress != "" {
		host := extractHost(publicAddress)
		if ip := net.ParseIP(host); ip != nil {
			ipAddrs = append(ipAddrs, ip)
			if !ip.IsLoopback() {
				dnsNames = append(dnsNames, host)
			}
		} else {
			dnsNames = append(dnsNames, host)
		}
	}

	// Add custom domain
	if customDomain != "" {
		dnsNames = append(dnsNames, customDomain)
		dnsNames = append(dnsNames, "*."+customDomain)
	}

	tlsTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("edge-%s", edgeID),
			Organization: []string{"YAT Edge"},
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	tlsCertDER, err := x509.CreateCertificate(rand.Reader, tlsTemplate, caCert, &tlsKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create TLS cert: %w", err)
	}

	tlsCert, err := x509.ParseCertificate(tlsCertDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse TLS cert: %w", err)
	}

	tlsCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCertDER})

	tlsKeyDER, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshal TLS key: %w", err)
	}
	tlsKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: tlsKeyDER})

	return tlsKey, tlsCert, tlsCertPEM, tlsKeyPEM, nil
}

// extractHost extracts the host part from an address (host:port or [host]:port).
func extractHost(addr string) string {
	if addr == "" {
		return ""
	}
	// Handle [ipv6]:port
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]"); idx > 0 {
			return addr[1:idx]
		}
	}
	// Handle host:port
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}
