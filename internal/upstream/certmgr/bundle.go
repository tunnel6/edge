package certmgr

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

// Struct
type CertificateBundle struct {
	TLSCertPath    string
	TLSKeyPath     string
	SubCACertPath  string
	SubCAKeyPath   string
	RootCACertPath string

	TLSCertPEM    []byte
	TLSKeyPEM     []byte
	SubCACertPEM  []byte
	SubCAKeyPEM   []byte
	RootCACertPEM []byte

	// Parse
	TLSCert    *x509.Certificate
	SubCACert  *x509.Certificate
	RootCACert *x509.Certificate

	ExpiresAt time.Time

	// Config
	AssignedDomain string

	edgeCA *EdgeCA
}

// Check
func (b *CertificateBundle) IsValid() bool {
	if b.TLSCert == nil {
		return false
	}
	return isCertValid(b.TLSCert)
}

// Check
func (b *CertificateBundle) NeedsRenewal(threshold time.Duration) bool {
	if b.TLSCert == nil {
		return true
	}
	return time.Until(b.TLSCert.NotAfter) < threshold
}

// Create

func (b *CertificateBundle) CreateTLSConfig() (*tls.Config, error) {
	if b == nil {
		return nil, fmt.Errorf("certificate bundle is nil")
	}
	if b.TLSCert == nil || len(b.TLSCertPEM) == 0 || len(b.TLSKeyPEM) == 0 {
		return nil, fmt.Errorf("TLS certificate or key is missing from certificate bundle")
	}
	cert, err := b.LoadCurrentTLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("load current TLS key pair: %w", err)
	}

	// 构建初始 ClientCA pool（含新旧 SubCA，支持平滑过渡）
	clientCAPool, err := b.buildClientCAPool()
	if err != nil {
		return nil, fmt.Errorf("build client CA pool: %w", err)
	}

	// 动态加载服务端 TLS 证书的公共函数
	getServerCert := func() (*tls.Certificate, error) {
		current, loadErr := b.LoadCurrentTLSCertificate()
		if loadErr != nil {
			logger.Warnf("load runtime TLS certificate failed, fallback to cached cert: %v", loadErr)
			return &cert, nil
		}
		return &current, nil
	}

	// VerifyPeerCertificate
	verifyPeerCert := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		pool, err := b.buildClientCAPool()
		if err != nil {
			return fmt.Errorf("build CA pool for verification: %w", err)
		}
		for _, rawCert := range rawCerts {
			cert, parseErr := x509.ParseCertificate(rawCert)
			if parseErr != nil {
				return fmt.Errorf("parse client certificate: %w", parseErr)
			}
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, verifyErr := cert.Verify(opts); verifyErr != nil {
				return fmt.Errorf("client certificate verification failed: %w", verifyErr)
			}
		}
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello != nil && hello.ServerName != "" {
				logger.Debugf("TLS SNI request: %s", hello.ServerName)
			}
			return getServerCert()
		},
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  clientCAPool,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"tunnel/1", "edge-health/1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			pool, poolErr := b.buildClientCAPool()
			if poolErr != nil {
				logger.Warnf("reload client CA pool failed: %v", poolErr)
				return nil, poolErr
			}
			return &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return getServerCert()
				},
				ClientAuth:            tls.RequestClientCert,
				ClientCAs:             pool,
				MinVersion:            tls.VersionTLS12,
				NextProtos:            []string{"tunnel/1", "edge-health/1"},
				VerifyPeerCertificate: verifyPeerCert,
			}, nil
		},
		VerifyPeerCertificate: verifyPeerCert,
	}, nil
}

func (b *CertificateBundle) buildClientCAPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	subCAPEM := b.SubCACertPEM
	if b.SubCACertPath != "" {
		if data, err := os.ReadFile(b.SubCACertPath); err == nil && len(data) > 0 {
			subCAPEM = data
		}
	}
	if !pool.AppendCertsFromPEM(subCAPEM) {
		return nil, fmt.Errorf("failed to append sub-CA certificate")
	}

	if b.SubCACertPath != "" {
		oldSubCAPath := filepath.Join(filepath.Dir(b.SubCACertPath), "edge-sub-ca.old.crt")
		if data, err := os.ReadFile(oldSubCAPath); err == nil && len(data) > 0 {
			pool.AppendCertsFromPEM(data)
		}
	}

	// Root CA
	if !pool.AppendCertsFromPEM(b.RootCACertPEM) {
		return nil, fmt.Errorf("failed to append root CA certificate")
	}

	return pool, nil
}

func (b *CertificateBundle) LoadCurrentTLSCertificate() (tls.Certificate, error) {
	if b == nil {
		return tls.Certificate{}, fmt.Errorf("certificate bundle is nil")
	}

	certPEM := b.TLSCertPEM
	keyPEM := b.TLSKeyPEM
	if b.TLSCertPath != "" {
		if data, err := os.ReadFile(b.TLSCertPath); err == nil && len(data) > 0 {
			certPEM = data
		}
	}
	if b.TLSKeyPath != "" {
		if data, err := os.ReadFile(b.TLSKeyPath); err == nil && len(data) > 0 {
			keyPEM = data
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return tls.Certificate{}, fmt.Errorf("TLS certificate or key is missing from certificate bundle")
	}

	return buildTLSKeyPair(certPEM, keyPEM, b.SubCACertPEM)
}

// Create

func (b *CertificateBundle) CreateClientTLSCertificate() (tls.Certificate, error) {
	cert, err := buildTLSKeyPair(b.TLSCertPEM, b.TLSKeyPEM, nil)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load X509 key pair: %w", err)
	}

	// Add
	// Verify

	return cert, nil
}

// Get
func (b *CertificateBundle) GetRootCAPool() (*x509.CertPool, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(b.RootCACertPEM) {
		return nil, fmt.Errorf("failed to append root CA certificate")
	}
	return caPool, nil
}

// Get
func (b *CertificateBundle) GetSubCAPool() (*x509.CertPool, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(b.SubCACertPEM) {
		return nil, fmt.Errorf("failed to append sub CA certificate")
	}
	return caPool, nil
}

// Get
func (b *CertificateBundle) GetExpiresAt() time.Time {
	if b.TLSCert == nil {
		return time.Time{}
	}
	return b.TLSCert.NotAfter
}

// Get
func (b *CertificateBundle) GetExpiresIn() time.Duration {
	return time.Until(b.GetExpiresAt())
}

// Check
func (b *CertificateBundle) WillExpireSoon(threshold time.Duration) bool {
	expiresIn := b.GetExpiresIn()
	return expiresIn < threshold && expiresIn > 0
}

// Get
func (b *CertificateBundle) GetEdgeCA() (*EdgeCA, error) {
	if b.edgeCA != nil {
		return b.edgeCA, nil
	}

	if len(b.SubCAKeyPEM) == 0 {
		return nil, fmt.Errorf("sub-CA private key not available, use CSR forwarding mode")
	}

	ca, err := NewEdgeCA(b.SubCAKeyPEM, b.SubCACertPEM, b.RootCACertPEM)
	if err != nil {
		return nil, err
	}

	b.edgeCA = ca
	return ca, nil
}

// Check
func (b *CertificateBundle) HasEdgeCA() bool {
	return len(b.SubCAKeyPEM) > 0
}

func (b *CertificateBundle) SameTLSMaterial(other *CertificateBundle) bool {
	if b == nil || other == nil {
		return false
	}
	if len(b.TLSCertPEM) > 0 || len(other.TLSCertPEM) > 0 {
		return bytes.Equal(b.TLSCertPEM, other.TLSCertPEM) && bytes.Equal(b.TLSKeyPEM, other.TLSKeyPEM)
	}
	if b.TLSCert == nil || other.TLSCert == nil {
		return false
	}
	return b.TLSCert.SerialNumber.Cmp(other.TLSCert.SerialNumber) == 0 &&
		b.TLSCert.NotAfter.Equal(other.TLSCert.NotAfter)
}

func buildTLSKeyPair(certPEM, keyPEM, subCACertPEM []byte) (tls.Certificate, error) {
	fullChainPEM := certPEM
	if len(subCACertPEM) > 0 && !bytes.Contains(certPEM, subCACertPEM) {
		fullChainPEM = append(append([]byte{}, certPEM...), subCACertPEM...)
	}
	return tls.X509KeyPair(fullChainPEM, keyPEM)
}
