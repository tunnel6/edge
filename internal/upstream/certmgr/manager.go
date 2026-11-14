package certmgr

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

type Manager struct {
	config *ManagerConfig
}

const defaultTLSRenewBefore = 30 * 24 * time.Hour
const defaultSubCARenewBefore = 30 * 24 * time.Hour // SubCA 到期前 30 天触发轮换

// Config
type ManagerConfig struct {
	CertDir       string
	NodeID        string
	PublicAddress string
	CustomDomain  string // 自定义域名
	Timeout       time.Duration
}

// Create
func NewManager(cfg *ManagerConfig) *Manager {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Manager{config: cfg}
}

func (m *Manager) EnsureCertificate(ctx context.Context) (*CertificateBundle, error) {
	// Check existing certificates
	if !NeedsCertificate(m.config.CertDir) {
		logger.Info("using existing certificates")
		bundle, err := m.LoadCertificateBundle()
		if err != nil {
			return nil, err
		}
		// Check whether TLS SAN still matches runtime address/domain config.
		if reason := m.tlsSANMismatchReason(bundle); reason != "" {
			logger.Warnf("TLS certificate SAN mismatch detected (%s), attempting certificate refresh", reason)
			if err := m.renewTLSCertificate(bundle); err != nil {
				logger.Warnf("local TLS certificate refresh failed: %v", err)
				if err := m.forceBootstrapCertificate(ctx); err != nil {
					logger.Warnf("local TLS certificate regeneration failed: %v", err)
				} else {
					return m.LoadCertificateBundle()
				}
			} else {
				return m.LoadCertificateBundle()
			}
		}
		// 检查 TLS 证书是否需要续期
		if bundle.NeedsRenewal(m.renewBefore()) {
			logger.Info("TLS certificate needs renewal, attempting local renewal")
			if err := m.renewTLSCertificate(bundle); err != nil {
				logger.Warnf("local TLS certificate renewal failed: %v", err)
				// 续期失败不阻塞，继续使用现有证书
			} else {
				// 重新加载证书
				return m.LoadCertificateBundle()
			}
		}
		// 检查 SubCA 是否需要轮换（到期前 30 天）
		if bundle.SubCACert != nil && time.Until(bundle.SubCACert.NotAfter) < m.subCARenewBefore() {
			logger.Infof("Sub-CA certificate expiring soon (expires: %s), regenerating local CA material",
				bundle.SubCACert.NotAfter.Format(time.RFC3339))
			if err := m.forceBootstrapCertificate(ctx); err != nil {
				logger.Warnf("local Sub-CA rotation failed: %v", err)
				// 不阻塞，继续使用现有证书
			} else {
				return m.LoadCertificateBundle()
			}
		}
		return bundle, nil
	}

	// Bootstrap required - uses standalone self-signed CA generation
	return m.bootstrap()
}

// signTLSCertificateLocally 使用 Sub-CA 本地签发 TLS 证书
func (m *Manager) signTLSCertificateLocally(bundle *CertificateBundle, edgeID, publicAddress string) error {
	// 获取 EdgeCA
	edgeCA, err := bundle.GetEdgeCA()
	if err != nil {
		return fmt.Errorf("get EdgeCA: %w", err)
	}

	// 签发 TLS 证书
	result, err := edgeCA.SignServerCert(&ServerCertRequest{
		EdgeID:        edgeID,
		PublicAddress: publicAddress,
		CustomDomain:  m.config.CustomDomain,
		Validity:      90 * 24 * time.Hour, // 90 天
	})
	if err != nil {
		return fmt.Errorf("sign server cert: %w", err)
	}

	// 保存证书和私钥
	tlsCertPath := filepath.Join(m.config.CertDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(m.config.CertDir, "edge-tls.key")

	if err := writeFileAtomic(tlsCertPath, result.ChainPEM, 0644); err != nil {
		return fmt.Errorf("write TLS cert: %w", err)
	}
	if err := writeFileAtomic(tlsKeyPath, result.KeyPEM, 0600); err != nil {
		return fmt.Errorf("write TLS key: %w", err)
	}

	logger.Infof("TLS certificate signed locally, serial: %s, expires: %v", result.SerialNumber, result.ExpiresAt)
	return nil
}

// renewTLSCertificate 续期 TLS 证书
func (m *Manager) renewTLSCertificate(bundle *CertificateBundle) error {
	// 检查是否有 Sub-CA 私钥
	if !bundle.HasEdgeCA() {
		return fmt.Errorf("Sub-CA private key not available, cannot renew locally")
	}

	// 获取 EdgeCA
	edgeCA, err := bundle.GetEdgeCA()
	if err != nil {
		return fmt.Errorf("get EdgeCA: %w", err)
	}

	// 从现有证书提取 edgeID
	edgeID := ""
	if bundle.TLSCert != nil {
		cn := bundle.TLSCert.Subject.CommonName
		if strings.HasPrefix(cn, "edge_") {
			edgeID = strings.TrimPrefix(cn, "edge_")
		}
	}
	if edgeID == "" {
		edgeID = m.config.NodeID
	}

	// 签发新证书
	result, err := edgeCA.SignServerCert(&ServerCertRequest{
		EdgeID:        edgeID,
		PublicAddress: m.config.PublicAddress,
		CustomDomain:  m.config.CustomDomain,
		Validity:      90 * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("sign server cert: %w", err)
	}

	// 保存证书和私钥
	tlsCertPath := filepath.Join(m.config.CertDir, "edge-tls.crt")
	tlsKeyPath := filepath.Join(m.config.CertDir, "edge-tls.key")

	if err := writeFileAtomic(tlsCertPath, result.ChainPEM, 0644); err != nil {
		return fmt.Errorf("write TLS cert: %w", err)
	}
	if err := writeFileAtomic(tlsKeyPath, result.KeyPEM, 0600); err != nil {
		return fmt.Errorf("write TLS key: %w", err)
	}

	logger.Infof("TLS certificate renewed locally, serial: %s, expires: %v", result.SerialNumber, result.ExpiresAt)
	return nil
}

func (m *Manager) LoadCertificateBundle() (*CertificateBundle, error) {
	return loadLocalCertificates(m.config.CertDir)
}

func (m *Manager) tlsSANMismatchReason(bundle *CertificateBundle) string {
	if bundle == nil || bundle.TLSCert == nil {
		return ""
	}
	if edgeID := strings.TrimSpace(m.config.NodeID); edgeID != "" {
		host := edgeID + ".edge.myproxy.dev"
		if err := bundle.TLSCert.VerifyHostname(host); err != nil {
			return fmt.Sprintf("default Edge name %q is not covered by cert SAN", host)
		}
	}

	if host := normalizeCertHost(m.config.PublicAddress); host != "" {
		if err := bundle.TLSCert.VerifyHostname(host); err != nil {
			return fmt.Sprintf("public address %q is not covered by cert SAN", host)
		}
	}

	if customDomain := normalizeCertHost(m.config.CustomDomain); customDomain != "" {
		if err := bundle.TLSCert.VerifyHostname(customDomain); err != nil {
			return fmt.Sprintf("custom domain %q is not covered by cert SAN", customDomain)
		}
	}

	return ""
}

func (m *Manager) renewBefore() time.Duration {
	return resolveDurationEnv(defaultTLSRenewBefore, "EDGE_TLS_CERT_RENEW_BEFORE", "EDGE_CERT_RENEW_BEFORE")
}

func (m *Manager) subCARenewBefore() time.Duration {
	return resolveDurationEnv(defaultSubCARenewBefore, "EDGE_SUBCA_RENEW_BEFORE")
}

func resolveDurationEnv(defaultValue time.Duration, keys ...string) time.Duration {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
		if days, err := strconv.Atoi(raw); err == nil && days > 0 {
			return time.Duration(days) * 24 * time.Hour
		}
		logger.Warnf("invalid duration env %s=%q, fallback=%s", key, raw, defaultValue)
	}
	return defaultValue
}

func normalizeCertHost(value string) string {
	host := strings.TrimSpace(value)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// forceBootstrapCertificate forces a certificate refresh.
// Implementation is build-tag selected (see manager_force_bootstrap_*.go).
