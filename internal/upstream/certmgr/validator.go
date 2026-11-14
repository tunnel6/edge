package certmgr

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"time"
)

// isCertValid
func isCertValid(cert *x509.Certificate) bool {
	now := time.Now()
	minValid := now.Add(7 * 24 * time.Hour)
	return cert.NotBefore.Before(now) && cert.NotAfter.After(minValid)
}

// NeedsCertificate
func NeedsCertificate(certDir string) bool {
	bundle, err := loadLocalCertificates(certDir)
	if err != nil {
		return true
	}
	if bundle.TLSCert == nil && bundle.HasEdgeCA() {
		return false
	}
	return !bundle.IsValid()
}

func NeedsTLSCertificate(certDir string) bool {
	bundle, err := loadLocalCertificates(certDir)
	if err != nil {
		return false
	}
	if bundle.TLSCert == nil || !isCertValid(bundle.TLSCert) {
		return bundle.HasEdgeCA()
	}
	return false
}

// CheckCertificateFiles
func CheckCertificateFiles(certDir string) error {
	tlsCertPath := filepath.Join(certDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(certDir, "edge-tls.key")
	subCACertPath := filepath.Join(certDir, "edge-sub-ca.crt")
	rootCACertPath := filepath.Join(certDir, "root-ca.crt")

	if _, err := os.Stat(tlsCertPath); os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(tlsKeyPath); os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(subCACertPath); os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(rootCACertPath); os.IsNotExist(err) {
		return err
	}

	return nil
}

// HasSubCA
func HasSubCA(certDir string) bool {
	subCACertPath := filepath.Join(certDir, "edge-sub-ca.crt")
	subCAKeyPath := filepath.Join(certDir, "edge-sub-ca.key")
	rootCACertPath := filepath.Join(certDir, "root-ca.crt")

	if _, err := os.Stat(subCACertPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(subCAKeyPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(rootCACertPath); os.IsNotExist(err) {
		return false
	}
	return true
}
