package server

import (
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

const defaultCertReconcileInterval = 90 * time.Second

func (s *Server) certReconcileLoop() {
	defer s.wg.Done()

	interval := resolveDurationEnv(
		defaultCertReconcileInterval,
		"EDGE_CERT_RETRY_INTERVAL",
		"EDGE_DOMAIN_CERT_RETRY_INTERVAL",
	)
	if interval <= 0 {
		interval = defaultCertReconcileInterval
	}

	logger.Infof("cert reconcile loop started, interval=%s", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			if !s.canRunCertReconcile() {
				continue
			}
			s.reconcileEdgeTLSCertificate("periodic_reconcile")
			// Periodically reconcile cert state so users do not need to restart
			// edge service to trigger next issuance round after transient DNS/cert failures.
			s.triggerAssignedDomainWildcardCert("periodic_reconcile")
			s.triggerCustomDomainCert("periodic_reconcile")
		}
	}
}

func (s *Server) canRunCertReconcile() bool {
	if s == nil || (s.httpsCertSvc == nil && s.tlsCertMgr == nil) {
		return false
	}
	s.mu.Lock()
	suspended := s.channelSuspended
	s.mu.Unlock()
	return !suspended
}
