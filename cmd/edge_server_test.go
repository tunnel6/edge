package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"icool.io/yat/edge/pkg/config"
)

func TestEnsureCertificatesRegeneratesMissingTLSCertificate(t *testing.T) {
	dataDir := t.TempDir()
	writeTestCAFiles(t, dataDir)

	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.Node.ID = "edge-local-regeneration"
	cfg.Node.PublicAddress = "127.0.0.1"
	cfg.Channel.DomainConfig = *config.NewDomainConfig(dataDir)
	config.NormalizeConfig(cfg)

	edgeServer, err := NewEdgeServer(
		cfg,
		filepath.Join(dataDir, "edge.pid"),
		filepath.Join(dataDir, "edge.sock"),
	)
	if err != nil {
		t.Fatalf("NewEdgeServer() error = %v", err)
	}

	if err := edgeServer.initCertManager(); err != nil {
		t.Fatalf("initCertManager() error = %v", err)
	}
	if err := edgeServer.ensureCertificates(); err != nil {
		t.Fatalf("ensureCertificates() error = %v", err)
	}

	if !edgeServer.certReady {
		t.Fatal("expected certificates to be marked ready")
	}
	if edgeServer.certBundle == nil {
		t.Fatal("expected certificate bundle to be loaded")
	}
	if edgeServer.certBundle.TLSCert == nil {
		t.Fatal("expected TLS certificate to be regenerated")
	}
	if got, want := edgeServer.certBundle.TLSCert.Subject.CommonName, "edge_edge-local-regeneration"; got != want {
		t.Fatalf("TLS certificate common name mismatch: got=%q want=%q", got, want)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "edge-tls.crt")); err != nil {
		t.Fatalf("expected regenerated TLS certificate file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "edge-tls.key")); err != nil {
		t.Fatalf("expected regenerated TLS key file: %v", err)
	}
}

func writeTestCAFiles(t *testing.T, dir string) {
	t.Helper()

	rootCertPEM, rootCert, rootKey := createTestCA(t, "Yat Root CA", nil, nil, 1)
	subCACertPEM, _, subCAKey := createTestCA(t, "Yat Edge Sub CA", rootCert, rootKey, 2)
	subCAKeyPEM := marshalECPrivateKey(t, subCAKey)

	if err := os.WriteFile(filepath.Join(dir, "root-ca.crt"), rootCertPEM, 0644); err != nil {
		t.Fatalf("write root CA cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "edge-sub-ca.crt"), subCACertPEM, 0644); err != nil {
		t.Fatalf("write sub CA cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "edge-sub-ca.key"), subCAKeyPEM, 0600); err != nil {
		t.Fatalf("write sub CA key: %v", err)
	}
}

func createTestCA(
	t *testing.T,
	commonName string,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	serial int64,
) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Yat Test"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	issuer := parent
	issuerKey := parentKey
	if issuer == nil {
		issuer = template
		issuerKey = privKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &privKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	return certPEM, cert, privKey
}

func marshalECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
}
