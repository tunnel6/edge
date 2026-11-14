package certmgr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

// forceBootstrapCertificate forces a certificate refresh by regenerating self-signed certs.
func (m *Manager) forceBootstrapCertificate(_ context.Context) error {
	edgeID := strings.TrimSpace(m.config.NodeID)
	if edgeID == "" {
		// Try to load from file
		if loaded, err := config.LoadEdgeID(m.config.CertDir); err == nil && loaded != "" {
			edgeID = loaded
		} else {
			return fmt.Errorf("edge_id not available for certificate regeneration")
		}
	}

	logger.Infof("[oss] force bootstrap: regenerating certificates for edge_id=%s", edgeID)

	// Remove existing certs to force regeneration
	// (StandaloneBootstrap will check validity and reuse if valid,
	//  so we need to clear them first for a force refresh)
	clearStandaloneCerts(m.config.CertDir)

	cfg := &StandaloneBootstrapConfig{
		EdgeID:        edgeID,
		CertDir:       m.config.CertDir,
		PublicAddress: m.config.PublicAddress,
		CustomDomain:  m.config.CustomDomain,
	}

	if _, err := StandaloneBootstrap(cfg); err != nil {
		return fmt.Errorf("standalone force bootstrap failed: %w", err)
	}

	if err := config.SaveEdgeID(m.config.CertDir, edgeID); err != nil {
		logger.Warnf("[oss] failed to save edge_id after force bootstrap: %v", err)
	}

	logger.Infof("[oss] force bootstrap completed for edge_id=%s", edgeID)
	return nil
}

// clearStandaloneCerts removes existing standalone certificates to force regeneration.
func clearStandaloneCerts(certDir string) {
	files := []string{"ca.crt", "ca.key", "tls.crt", "tls.key"}
	for _, f := range files {
		path := filepath.Join(certDir, f)
		_ = os.Remove(path) // Ignore errors (file may not exist)
	}
}
