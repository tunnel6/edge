package server

import (
	"context"
	"fmt"
	"time"

	"icool.io/yat/edge/internal/upstream/certmgr"
	logger "icool.io/yat/edge/pkg/log"
)

const defaultEdgeTLSReconcileTimeout = 2 * time.Minute

func (s *Server) reconcileEdgeTLSCertificate(reason string) {
	if s == nil || s.tlsCertMgr == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultEdgeTLSReconcileTimeout)
	defer cancel()

	bundle, err := s.tlsCertMgr.EnsureCertificate(ctx)
	if err != nil {
		logger.Warnf("edge TLS reconcile failed, reason=%s, err=%v", reason, err)
		return
	}
	if bundle == nil || bundle.TLSCert == nil {
		logger.Warnf("edge TLS reconcile produced incomplete bundle, reason=%s", reason)
		return
	}

	s.mu.Lock()
	current := s.certBundle
	s.mu.Unlock()
	if current != nil && current.SameTLSMaterial(bundle) {
		return
	}

	if err := s.applyRuntimeCertificateBundle(bundle); err != nil {
		logger.Warnf("apply runtime certificate bundle failed, reason=%s, err=%v", reason, err)
		return
	}

	logger.Infof(
		"edge TLS certificate reloaded at runtime, reason=%s, serial=%s, expires=%s",
		reason,
		bundle.TLSCert.SerialNumber.String(),
		bundle.TLSCert.NotAfter.Format(time.RFC3339),
	)
}

func (s *Server) applyRuntimeCertificateBundle(bundle *certmgr.CertificateBundle) error {
	if bundle == nil || bundle.TLSCert == nil {
		return fmt.Errorf("runtime certificate bundle is incomplete")
	}

	s.mu.Lock()
	s.certBundle = bundle
	s.certIssuer = NewClientCertIssuer(bundle)
	s.mu.Unlock()
	return nil
}
