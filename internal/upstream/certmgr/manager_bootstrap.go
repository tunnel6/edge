package certmgr

import (
	"fmt"
	"time"

	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

// bootstrap performs the certificate bootstrap for standalone mode.
// It uses local self-signed CA generation.
func (m *Manager) bootstrap() (*CertificateBundle, error) {
	edgeID := m.config.NodeID
	if edgeID == "" {
		// Generate a deterministic edge ID if not configured
		edgeID = fmt.Sprintf("edge-%d", time.Now().UnixNano()%100000)
		logger.Infof("[oss] no node_id configured, generated: %s", edgeID)
	}

	cfg := &StandaloneBootstrapConfig{
		EdgeID:        edgeID,
		CertDir:       m.config.CertDir,
		PublicAddress: m.config.PublicAddress,
		CustomDomain:  m.config.CustomDomain,
	}

	result, err := StandaloneBootstrap(cfg)
	if err != nil {
		return nil, fmt.Errorf("standalone bootstrap: %w", err)
	}

	// Convert to CertificateBundle
	// In OSS mode, the single CA serves as both root CA and sub CA
	bundle := &CertificateBundle{
		TLSCertPath:    result.TLSCertPath,
		TLSKeyPath:     result.TLSKeyPath,
		SubCACertPath:  result.CACertPath, // Single CA acts as sub CA
		SubCAKeyPath:   result.CAKeyPath,  // Single CA key for signing
		RootCACertPath: result.CACertPath, // Same cert for root CA

		TLSCertPEM:    result.TLSCertPEM,
		TLSKeyPEM:     result.TLSKeyPEM,
		SubCACertPEM:  result.CACertPEM,
		SubCAKeyPEM:   result.CAKeyPEM,
		RootCACertPEM: result.CACertPEM,

		TLSCert:    result.TLSCert,
		SubCACert:  result.CACert,
		RootCACert: result.CACert,

		ExpiresAt: result.ExpiresAt,
	}

	// Initialize EdgeCA from the single CA
	edgeCA, err := NewEdgeCA(result.CAKeyPEM, result.CACertPEM, result.CACertPEM)
	if err != nil {
		logger.Warnf("[oss] failed to initialize EdgeCA: %v", err)
	} else {
		bundle.edgeCA = edgeCA
	}

	// Save edge ID
	if err := config.SaveEdgeID(m.config.CertDir, edgeID); err != nil {
		logger.Warnf("[oss] failed to save edge_id: %v", err)
	}

	logger.Infof("[oss] bootstrap completed, tls_cert: %s, expires: %v",
		result.TLSCertPath, result.ExpiresAt)

	return bundle, nil
}
