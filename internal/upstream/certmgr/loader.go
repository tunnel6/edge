package certmgr

import (
	"fmt"
	"os"
	"path/filepath"
)

// loadLocalCertificates
func loadLocalCertificates(certDir string) (*CertificateBundle, error) {
	tlsCertPath := filepath.Join(certDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(certDir, "edge-tls.key")
	subCACertPath := filepath.Join(certDir, "edge-sub-ca.crt")
	subCAKeyPath := filepath.Join(certDir, "edge-sub-ca.key")
	rootCACertPath := filepath.Join(certDir, "root-ca.crt")

	subCACertPEM, err := os.ReadFile(subCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read sub CA cert: %w", err)
	}
	rootCACertPEM, err := os.ReadFile(rootCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read root CA cert: %w", err)
	}

	var subCAKeyPEM []byte
	if data, err := os.ReadFile(subCAKeyPath); err == nil {
		subCAKeyPEM = data
	}

	var tlsCertPEM, tlsKeyPEM []byte
	if data, err := os.ReadFile(tlsCertPath); err == nil {
		tlsCertPEM = data
	}
	if data, err := os.ReadFile(tlsKeyPath); err == nil {
		tlsKeyPEM = data
	}

	subCACert, err := parseCertPEM(subCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse sub CA cert: %w", err)
	}
	rootCACert, err := parseCertPEM(rootCACertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse root CA cert: %w", err)
	}

	bundle := &CertificateBundle{
		TLSCertPath:    tlsCertPath,
		TLSKeyPath:     tlsKeyPath,
		SubCACertPath:  subCACertPath,
		SubCAKeyPath:   subCAKeyPath,
		RootCACertPath: rootCACertPath,
		SubCACertPEM:   subCACertPEM,
		SubCAKeyPEM:    subCAKeyPEM,
		RootCACertPEM:  rootCACertPEM,
		SubCACert:      subCACert,
		RootCACert:     rootCACert,
	}

	// 如果有 TLS 证书，解析它
	if len(tlsCertPEM) > 0 && len(tlsKeyPEM) > 0 {
		tlsCert, err := parseCertPEM(tlsCertPEM)
		if err != nil {
			return nil, fmt.Errorf("parse TLS cert: %w", err)
		}
		bundle.TLSCertPEM = tlsCertPEM
		bundle.TLSKeyPEM = tlsKeyPEM
		bundle.TLSCert = tlsCert
		bundle.ExpiresAt = tlsCert.NotAfter
	}

	return bundle, nil
}
