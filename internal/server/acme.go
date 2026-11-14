package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"icool.io/yat/edge/internal/channel/letsencrypt"
	channel "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	defaultCertMinRemaining       = 30 * 24 * time.Hour
	defaultDNS01PropagationWait   = 20 * time.Second
	defaultDNS01PropagationTicker = 2 * time.Second
	defaultDNS01CleanupTimeout    = 12 * time.Second
	defaultManualDNS01Wait        = 30 * time.Minute
	defaultCNAMECheckTicker       = 5 * time.Second
	defaultCNAMEPublicTimeout     = 1200 * time.Millisecond
	defaultCNAMELocalTimeout      = 1500 * time.Millisecond
)

var cnamePublicResolvers = []string{
	"1.1.1.1",
	"8.8.8.8",
	"223.5.5.5",
	"119.29.29.29",
}

// DomainProvider 用于获取 Edge 级别的域名配置
type DomainProvider interface {
	GetAssignedDomain() string
	GetCustomDomain() string
}

type HTTPSCertService struct {
	le      *letsencrypt.LetsEncrypt
	certDir string
	nodeID  string

	minRemaining time.Duration
	dns01Wait    time.Duration
	dns01Ticker  time.Duration

	domainMu       sync.Mutex
	domainLocks    map[string]*sync.Mutex
	domainProvider DomainProvider // 通过接口获取域名，不持有副本

	cacheMu   sync.RWMutex
	certCache map[string]*tls.Certificate

	certIssueMu sync.RWMutex
	certIssues  map[string]CertIssueStatus // key: normalized domain

	// Active DNS-01 challenge tracking (for status reporting to yat-fe)
	dns01ChallengeMu sync.RWMutex
	activeDNS01      map[string]*ActiveDNS01Challenge // key: recordName
	certFileMu       sync.RWMutex
	certOperationMu  sync.Mutex
	certOperationID  uint64
	certOperations   map[string]map[uint64]context.CancelFunc
	certUploads      map[string]int

	http01Handler    *letsencrypt.HTTP01Handler
	tlsALPN01Handler *letsencrypt.TLSALPN01Handler
}

// CertIssueStatus records last certificate issuance result per domain.
type CertIssueStatus struct {
	LastError string
	UpdatedAt time.Time
}

// ActiveDNS01Challenge represents a DNS-01 challenge currently in progress.
type ActiveDNS01Challenge struct {
	RecordName  string
	RecordValue string
	Domain      string
	CreatedAt   time.Time
	LastError   string
	UpdatedAt   time.Time
}

// GetActiveDNS01Challenges returns a snapshot of active DNS-01 challenges.
func (s *HTTPSCertService) GetActiveDNS01Challenges() []ActiveDNS01Challenge {
	s.dns01ChallengeMu.RLock()
	defer s.dns01ChallengeMu.RUnlock()
	out := make([]ActiveDNS01Challenge, 0, len(s.activeDNS01))
	for _, ch := range s.activeDNS01 {
		out = append(out, *ch)
	}
	return out
}

func (s *HTTPSCertService) trackDNS01Challenge(domain, recordName, recordValue string) {
	s.dns01ChallengeMu.Lock()
	defer s.dns01ChallengeMu.Unlock()
	s.activeDNS01[recordName] = &ActiveDNS01Challenge{
		RecordName:  recordName,
		RecordValue: recordValue,
		Domain:      domain,
		CreatedAt:   time.Now(),
	}
	logger.Debugf("[DNS01Track] challenge tracked: domain=%s record=%s value_len=%d active=%d",
		domain, recordName, len(strings.TrimSpace(recordValue)), len(s.activeDNS01))
}

func (s *HTTPSCertService) untrackDNS01Challenge(recordName string) {
	s.dns01ChallengeMu.Lock()
	defer s.dns01ChallengeMu.Unlock()
	delete(s.activeDNS01, recordName)
	logger.Debugf("[DNS01Track] challenge untracked: record=%s active=%d", recordName, len(s.activeDNS01))
}

func (s *HTTPSCertService) setDNS01ChallengeError(recordName, errMsg string) {
	s.dns01ChallengeMu.Lock()
	defer s.dns01ChallengeMu.Unlock()
	if ch, ok := s.activeDNS01[recordName]; ok {
		ch.LastError = errMsg
		ch.UpdatedAt = time.Now()
		logger.Debugf("[DNS01Track] challenge error: record=%s domain=%s err=%s", recordName, ch.Domain, strings.TrimSpace(errMsg))
	}
}

func (s *HTTPSCertService) clearChallengeStateOnCertReady(domain string) {
	if s == nil {
		return
	}

	domain = normalizeCertDomain(domain)
	if domain == "" {
		return
	}

	recordTarget := dns01RecordTargetDomain(domain)
	if recordTarget != "" {
		recordName := "_acme-challenge." + recordTarget
		s.untrackDNS01Challenge(recordName)
	}

	// Challenge handlers are in-memory and should not retain stale tokens after
	// certificate becomes usable.
	domainsToClear := []string{domain}
	if strings.HasPrefix(domain, "*.") {
		baseDomain := normalizeCertDomain(strings.TrimPrefix(domain, "*."))
		if baseDomain != "" {
			domainsToClear = append(domainsToClear, baseDomain)
		}
	}
	if s.http01Handler != nil {
		for _, d := range domainsToClear {
			s.http01Handler.DeleteDomain(d)
		}
	}
	if s.tlsALPN01Handler != nil {
		for _, d := range domainsToClear {
			s.tlsALPN01Handler.DeleteDomain(d)
		}
	}
}

func (s *HTTPSCertService) untrackDNS01ChallengeForDomain(req *letsencrypt.IssueRequest, issueErr error) {
	if req == nil || req.Method != letsencrypt.ChallengeDNS01 {
		return
	}
	recordTarget := dns01RecordTargetDomain(req.Domain)
	if recordTarget == "" {
		return
	}
	recordName := "_acme-challenge." + recordTarget
	if issueErr != nil {
		s.dns01ChallengeMu.Lock()
		if ch, ok := s.activeDNS01[recordName]; ok {
			errMsg := strings.TrimSpace(issueErr.Error())
			if errMsg != "" {
				ch.LastError = errMsg
			}
			ch.UpdatedAt = time.Now()
			logger.Debugf("[DNS01Track] challenge retained on issue error: domain=%s record=%s err=%s",
				ch.Domain, recordName, errMsg)
		}
		s.dns01ChallengeMu.Unlock()
		return
	}
	logger.Debugf("[DNS01Track] challenge cleanup on issue success: domain=%s record=%s", normalizeCertDomain(req.Domain), recordName)
	s.untrackDNS01Challenge(recordName)
}

type DNS01ChallengePublisher func(ctx context.Context, recordName, recordValue string) error

func NewHTTPSCertService(
	ctx context.Context,
	cfg *config.Config,
	httpProxy channel.HTTPProxyConfigurator,
	dns01Publisher DNS01ChallengePublisher,
	dns01Cleaner DNS01ChallengePublisher,
) (*HTTPSCertService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("https cert service: config is required")
	}
	if httpProxy == nil {
		return nil, fmt.Errorf("https cert service: http proxy is required")
	}

	dataDir := cfg.GetDataDir()
	accountKeyPath := filepath.Join(dataDir, "acme-account.key")
	accountKey, err := letsencrypt.LoadOrCreateACMEAccountKey(accountKeyPath)
	if err != nil {
		return nil, fmt.Errorf("https cert service: load/create acme account key: %w", err)
	}

	acmeProvider, err := letsencrypt.NewACMEProvider(accountKey, resolveACMEContactEmail())
	if err != nil {
		return nil, fmt.Errorf("https cert service: init acme provider: %w", err)
	}

	acmeDirectory := resolveACMEDirectoryURL()
	propagationWait := resolveDurationEnv(defaultDNS01PropagationWait, "EDGE_LE_DNS01_PROPAGATION_WAIT")
	propagationTicker := resolveDurationEnv(defaultDNS01PropagationTicker, "EDGE_LE_DNS01_PROPAGATION_TICKER")
	cleanupTimeout := resolveDurationEnv(defaultDNS01CleanupTimeout, "EDGE_LE_DNS01_CLEANUP_TIMEOUT")

	svc := &HTTPSCertService{
		nodeID:         strings.TrimSpace(cfg.Node.ID),
		minRemaining:   resolveRenewWindowEnv(defaultCertMinRemaining, "EDGE_DOMAIN_CERT_RENEW_BEFORE", "EDGE_LE_CERT_RENEW_BEFORE", "EDGE_CERT_RENEW_BEFORE"),
		dns01Wait:      propagationWait,
		dns01Ticker:    propagationTicker,
		domainLocks:    make(map[string]*sync.Mutex),
		certCache:      make(map[string]*tls.Certificate),
		certIssues:     make(map[string]CertIssueStatus),
		domainProvider: &cfg.Channel.DomainConfig,
		activeDNS01:    make(map[string]*ActiveDNS01Challenge),
	}

	// DEBUG: 打印 DomainConfig 的状态
	logger.Debugf("NewHTTPSCertService: GetAssignedDomain=%q, GetCustomDomain=%q",
		cfg.Channel.GetAssignedDomain(), cfg.Channel.GetCustomDomain())

	preferredMethods := buildPreferredChallengeMethods(cfg)
	hasHTTP01 := containsChallengeMethod(preferredMethods, letsencrypt.ChallengeHTTP01)
	hasTLSALPN01 := containsChallengeMethod(preferredMethods, letsencrypt.ChallengeTLSALPN01)
	var http01Handler *letsencrypt.HTTP01Handler
	var tlsALPN01Handler *letsencrypt.TLSALPN01Handler

	builderOptions := []letsencrypt.Option{
		letsencrypt.WithDataDir(dataDir),
		letsencrypt.WithACMEDirectoryURL(acmeDirectory),
		letsencrypt.WithPreferredMethods(preferredMethods...),
		letsencrypt.WithDNS01Provider("delegated"),
		letsencrypt.WithDNS01Executor(svc.buildDNS01Executor(dns01Publisher)),
		letsencrypt.WithDNS01Fallback(false),
		letsencrypt.WithChallengeCredentialRequester(acmeProvider.ChallengeCredential),
		letsencrypt.WithNewCertIssuer(func(ctx context.Context, req *letsencrypt.IssueRequest) (*letsencrypt.CertMaterial, error) {
			material, issueErr := acmeProvider.IssueCert(ctx, req)
			cleanupTLSALPN01Challenge(req, tlsALPN01Handler, svc.nodeID, issueErr)
			cleanupDNS01Record(req, dns01Cleaner, cleanupTimeout, svc.nodeID, issueErr)
			svc.untrackDNS01ChallengeForDomain(req, issueErr)
			return material, issueErr
		}),
		letsencrypt.WithRenewCertIssuer(func(ctx context.Context, req *letsencrypt.IssueRequest) (*letsencrypt.CertMaterial, error) {
			material, issueErr := acmeProvider.IssueCert(ctx, req)
			cleanupTLSALPN01Challenge(req, tlsALPN01Handler, svc.nodeID, issueErr)
			cleanupDNS01Record(req, dns01Cleaner, cleanupTimeout, svc.nodeID, issueErr)
			svc.untrackDNS01ChallengeForDomain(req, issueErr)
			return material, issueErr
		}),
		letsencrypt.WithChallengeTimeout(10 * time.Minute),
	}

	if hasHTTP01 {
		http01Handler = letsencrypt.NewHTTP01Handler()
		builderOptions = append(builderOptions,
			letsencrypt.WithHTTPListener(noopListener{}),
			letsencrypt.WithHTTP01Handler(http01Handler),
			letsencrypt.WithHTTP01Executor(func(ctx context.Context, req *letsencrypt.HTTP01Request) error {
				// Challenge token is served by HTTPProxy + HTTP01Handler; no local listener probe is needed.
				return nil
			}),
		)
	}

	if hasTLSALPN01 {
		tlsALPN01Handler = letsencrypt.NewTLSALPN01Handler()
		builderOptions = append(builderOptions,
			letsencrypt.WithHTTPSListener(noopListener{}),
			letsencrypt.WithTLSALPN01Executor(func(ctx context.Context, req *letsencrypt.TLSALPN01Request) error {
				_ = ctx
				if req == nil {
					return fmt.Errorf("tls-alpn-01 request is required")
				}
				return tlsALPN01Handler.Set(req.Domain, req.Token, req.KeyAuthorization)
			}),
		)
	}

	le, err := letsencrypt.NewBuilder(builderOptions...).Build(ctx)
	if err != nil {
		return nil, fmt.Errorf("https cert service: build letsencrypt issuer: %w", err)
	}
	svc.le = le
	svc.certDir = le.Options().CertDir
	svc.http01Handler = http01Handler
	svc.tlsALPN01Handler = tlsALPN01Handler

	if http01Handler != nil {
		httpProxy.SetACMEHTTP01Handler(http01Handler)
	}
	if tlsALPN01Handler != nil {
		httpProxy.SetACMETLSALPN01CertResolver(tlsALPN01Handler.Resolve)
	}
	logger.Infof(
		"https cert service initialized, node_id=%s, acme_directory=%s, cert_dir=%s, challenge_order=%v, assigned_domain=%s, custom_domain=%s, dns01_wait=%s, dns01_tick=%s",
		svc.nodeID,
		acmeDirectory,
		svc.certDir,
		preferredMethods,
		svc.domainProvider.GetAssignedDomain(),
		svc.domainProvider.GetCustomDomain(),
		propagationWait,
		propagationTicker,
	)
	return svc, nil
}

func buildPreferredChallengeMethods(cfg *config.Config) []letsencrypt.ChallengeMethod {
	methods := make([]letsencrypt.ChallengeMethod, 0, 3)
	if cfg != nil && cfg.Proxy.HTTP != nil && cfg.Proxy.HTTP.Enabled && cfg.Proxy.HTTP.Port == 80 {
		methods = append(methods, letsencrypt.ChallengeHTTP01)
	}
	if cfg != nil && cfg.Proxy.HTTP != nil && cfg.Proxy.HTTP.Enabled && cfg.Proxy.HTTP.HTTPSPort == 443 {
		methods = append(methods, letsencrypt.ChallengeTLSALPN01)
	}
	methods = append(methods, letsencrypt.ChallengeDNS01)
	return methods
}

func containsChallengeMethod(methods []letsencrypt.ChallengeMethod, target letsencrypt.ChallengeMethod) bool {
	for _, method := range methods {
		if method == target {
			return true
		}
	}
	return false
}

func (s *HTTPSCertService) buildDNS01Executor(publisher DNS01ChallengePublisher) letsencrypt.DNS01Executor {
	return func(ctx context.Context, req *letsencrypt.DNS01Request) error {
		if req == nil {
			return fmt.Errorf("dns-01 request is required")
		}
		domain := normalizeCertDomain(req.Domain)
		recordTarget := dns01RecordTargetDomain(domain)
		recordName := "_acme-challenge." + recordTarget
		recordValue := strings.TrimSpace(req.KeyAuthorization)

		// Track active challenge for status reporting
		if recordName != "" && recordValue != "" {
			s.trackDNS01Challenge(domain, recordName, recordValue)
		}

		var err error
		if s.isAssignedDomain(req.Domain) && publisher != nil {
			err = delegatedDNS01Executor(ctx, req, publisher, s.nodeID, s.dns01Wait, s.dns01Ticker)
		} else {
			err = manualDNS01Executor(ctx, req, s.dns01Wait, s.dns01Ticker)
		}
		if err != nil && recordName != "" {
			s.setDNS01ChallengeError(recordName, err.Error())
		}
		return err
	}
}

func (s *HTTPSCertService) AliasDomainGuidance() string {
	return fmt.Sprintf(
		"challenge order is http-01 -> tls-alpn-01 -> dns-01; for dns-01 manual mode configure TXT in edge console / yat-fe edge management panel, or upload cert files to %s/<domain>.crt and %s/<domain>.key",
		s.certDir,
		s.certDir,
	)
}

func (s *HTTPSCertService) CustomDomainGuidance() string {
	return fmt.Sprintf(
		"custom wildcard certificate uses dns-01; configure TXT in edge console / yat-fe edge management panel, or upload cert files to %s/<domain>.crt and %s/<domain>.key",
		s.certDir,
		s.certDir,
	)
}

func (s *HTTPSCertService) WildcardGuidance(baseDomain string) string {
	baseDomain = normalizeCertDomain(baseDomain)
	if baseDomain == "" {
		return "configure a channel base domain and follow the DNS-01 TXT records in Edge domain diagnostics"
	}
	return fmt.Sprintf("configure TXT for _acme-challenge.%s using Edge domain diagnostics, or upload a wildcard certificate", baseDomain)
}

func (s *HTTPSCertService) ensureWildcardForBaseDomain(ctx context.Context, baseDomain string, method letsencrypt.ChallengeMethod) (*letsencrypt.StoredCertificate, error) {
	baseDomain = normalizeCertDomain(baseDomain)
	if baseDomain == "" {
		return nil, letsencrypt.ErrInvalidDomain
	}
	return s.ensureDomain(ctx, "*."+baseDomain, method)
}

func (s *HTTPSCertService) EnsureAssignedDomain(ctx context.Context) (*letsencrypt.StoredCertificate, error) {
	return s.ensureWildcardForBaseDomain(ctx, s.AssignedBaseDomain(), "")
}

// EnsureAliasDomain issues certificate for channel alias domain.
// Challenge order follows ACME preference: http-01 -> tls-alpn-01 -> dns-01.
func (s *HTTPSCertService) EnsureAliasDomain(ctx context.Context, aliasDomain, assignedDomain string) (*letsencrypt.StoredCertificate, error) {
	aliasDomain = normalizeCertDomain(aliasDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if aliasDomain == "" {
		return nil, letsencrypt.ErrInvalidDomain
	}

	// Step 1: wait until alias CNAME points to the channel assigned domain.
	if assignedDomain != "" {
		if err := waitForCNAME(ctx, aliasDomain, assignedDomain, defaultCNAMECheckTicker); err != nil {
			return nil, fmt.Errorf("cname pre-check failed for %s -> %s: %w", aliasDomain, assignedDomain, err)
		}
		logger.Infof("cname pre-check passed, alias_domain=%s, assigned_domain=%s", aliasDomain, assignedDomain)
	}

	// Step 2: issue cert for exact alias domain with preferred challenge order.
	return s.ensureDomain(ctx, aliasDomain, "")
}

// EnsureCustomDomain issues wildcard certificate for edge-level custom domain.
// This flow remains dns-01 based.
func (s *HTTPSCertService) EnsureCustomDomain(ctx context.Context, customDomain, assignedDomain string) (*letsencrypt.StoredCertificate, error) {
	customDomain = normalizeCertDomain(customDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if customDomain == "" {
		return nil, letsencrypt.ErrInvalidDomain
	}

	// Step 1: Wait for custom-domain CNAME readiness before starting ACME.
	// Wildcard record (*.customDomain) is the primary signal; exact-domain CNAME is accepted too.
	if assignedDomain != "" {
		if err := waitForCustomDomainCNAME(ctx, customDomain, assignedDomain, defaultCNAMECheckTicker); err != nil {
			return nil, fmt.Errorf("cname pre-check failed for %s -> %s: %w", customDomain, assignedDomain, err)
		}
		logger.Infof("cname pre-check passed, custom_domain=%s, assigned_domain=%s", customDomain, assignedDomain)
	}

	// Step 2: proceed with wildcard certificate issuance via dns-01.
	return s.ensureWildcardForBaseDomain(ctx, customDomain, letsencrypt.ChallengeDNS01)
}

func extractBaseDomainFromAssignedDomain(assignedDomain string) string {
	assignedDomain = normalizeCertDomain(assignedDomain)
	if assignedDomain == "" {
		return ""
	}
	idx := strings.IndexByte(assignedDomain, '.')
	if idx <= 0 || idx+1 >= len(assignedDomain) {
		return ""
	}
	return normalizeCertDomain(assignedDomain[idx+1:])
}

func (s *HTTPSCertService) AssignedBaseDomain() string {
	if s.domainProvider == nil {
		return ""
	}
	return s.domainProvider.GetAssignedDomain()
}

func (s *HTTPSCertService) GetTLSCertificate(serverName string) (*tls.Certificate, error) {
	s.certFileMu.RLock()
	defer s.certFileMu.RUnlock()
	serverName = normalizeCertDomain(serverName)
	if serverName == "" {
		return nil, fmt.Errorf("tls server name is required")
	}

	if cert := s.getCachedCertificate(serverName); cert != nil {
		return cert, nil
	}

	for _, candidate := range s.certificateCandidates(serverName) {
		cert, err := s.loadTLSCertFromDisk(candidate)
		if err != nil {
			continue
		}
		s.cacheCertificate(serverName, cert)
		return cert, nil
	}
	return nil, fmt.Errorf("certificate not found for %s", serverName)
}

func (s *HTTPSCertService) HasUsableCertificate(serverName string) bool {
	serverName = normalizeCertDomain(serverName)
	if serverName == "" || s == nil || s.le == nil {
		return false
	}
	s.certFileMu.RLock()
	defer s.certFileMu.RUnlock()

	if _, ok := s.le.HasUsableCertificate(serverName, s.minRemaining); ok {
		return true
	}
	if _, ok := loadUploadedCertificate(s.le.Options().CertDir, serverName, 0); ok {
		return true
	}
	return false
}

func (s *HTTPSCertService) HasUsableCertificateForServerName(serverName string) bool {
	serverName = normalizeCertDomain(serverName)
	if serverName == "" || s == nil || s.le == nil {
		return false
	}
	s.certFileMu.RLock()
	defer s.certFileMu.RUnlock()

	for _, candidate := range s.certificateCandidates(serverName) {
		if _, ok := s.le.HasUsableCertificate(candidate, s.minRemaining); ok {
			return true
		}
		if _, ok := loadUploadedCertificate(s.le.Options().CertDir, candidate, 0); ok {
			return true
		}
	}
	return false
}

func (s *HTTPSCertService) recordCertIssueSuccess(domain string) {
	if s == nil {
		return
	}
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return
	}
	s.certIssueMu.Lock()
	s.certIssues[domain] = CertIssueStatus{
		LastError: "",
		UpdatedAt: time.Now(),
	}
	s.certIssueMu.Unlock()
}

func (s *HTTPSCertService) recordCertIssueError(domain string, err error) {
	if s == nil || err == nil {
		return
	}
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return
	}
	s.certIssueMu.Lock()
	s.certIssues[domain] = CertIssueStatus{
		LastError: strings.TrimSpace(err.Error()),
		UpdatedAt: time.Now(),
	}
	s.certIssueMu.Unlock()
}

func (s *HTTPSCertService) getCertIssueStatus(domain string) (CertIssueStatus, bool) {
	if s == nil {
		return CertIssueStatus{}, false
	}
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return CertIssueStatus{}, false
	}
	s.certIssueMu.RLock()
	status, ok := s.certIssues[domain]
	s.certIssueMu.RUnlock()
	return status, ok
}

// GetCertificateIssueStatus returns the latest cert issue status for an exact domain key.
func (s *HTTPSCertService) GetCertificateIssueStatus(domain string) (string, time.Time) {
	status, ok := s.getCertIssueStatus(domain)
	if !ok {
		return "", time.Time{}
	}
	return status.LastError, status.UpdatedAt
}

// GetCertificateIssueStatusForServerName returns the latest cert issue status
// across server-name candidates (exact + wildcard).
func (s *HTTPSCertService) GetCertificateIssueStatusForServerName(serverName string) (string, time.Time) {
	serverName = normalizeCertDomain(serverName)
	if serverName == "" || s == nil {
		return "", time.Time{}
	}

	var latestErr string
	var latestAt time.Time
	for _, candidate := range s.certificateCandidates(serverName) {
		status, ok := s.getCertIssueStatus(candidate)
		if !ok {
			continue
		}
		if status.UpdatedAt.After(latestAt) {
			latestAt = status.UpdatedAt
			latestErr = status.LastError
		}
	}
	return latestErr, latestAt
}

func (s *HTTPSCertService) ensureDomain(ctx context.Context, domain string, method letsencrypt.ChallengeMethod) (*letsencrypt.StoredCertificate, error) {
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return nil, letsencrypt.ErrInvalidDomain
	}
	if s.le == nil {
		return nil, fmt.Errorf("letsencrypt instance is not initialized")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.certOperationMu.Lock()
	if s.certUploads[domain] > 0 {
		s.certOperationMu.Unlock()
		cancel()
		return nil, context.Canceled
	}
	if s.certOperations == nil {
		s.certOperations = make(map[string]map[uint64]context.CancelFunc)
	}
	if s.certOperations[domain] == nil {
		s.certOperations[domain] = make(map[uint64]context.CancelFunc)
	}
	s.certOperationID++
	operationID := s.certOperationID
	s.certOperations[domain][operationID] = cancel
	s.certOperationMu.Unlock()
	defer func() {
		cancel()
		s.certOperationMu.Lock()
		delete(s.certOperations[domain], operationID)
		if len(s.certOperations[domain]) == 0 {
			delete(s.certOperations, domain)
		}
		s.certOperationMu.Unlock()
	}()

	unlock := s.lockDomain(domain)
	defer unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if cert, ok := s.le.HasUsableCertificate(domain, s.minRemaining); ok {
		s.recordCertIssueSuccess(domain)
		s.clearChallengeStateOnCertReady(domain)
		return cert, nil
	}
	if cert, ok := loadUploadedCertificate(s.le.Options().CertDir, domain, 0); ok {
		s.recordCertIssueSuccess(domain)
		s.clearChallengeStateOnCertReady(domain)
		return cert, nil
	}

	cert, err := s.le.NewCert(ctx, method, domain)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.recordCertIssueError(domain, err)
		return nil, err
	}
	s.invalidateCertificateCache(domain)
	s.recordCertIssueSuccess(domain)
	s.clearChallengeStateOnCertReady(domain)
	return cert, nil
}

func (s *HTTPSCertService) lockDomain(domain string) func() {
	domain = normalizeCertDomain(domain)

	s.domainMu.Lock()
	lock, ok := s.domainLocks[domain]
	if !ok {
		lock = &sync.Mutex{}
		s.domainLocks[domain] = lock
	}
	s.domainMu.Unlock()

	lock.Lock()
	return lock.Unlock
}

func (s *HTTPSCertService) getCachedCertificate(serverName string) *tls.Certificate {
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.certCache[serverName]
}

func (s *HTTPSCertService) cacheCertificate(serverName string, cert *tls.Certificate) {
	if cert == nil {
		return
	}
	s.cacheMu.Lock()
	s.certCache[serverName] = cert
	s.cacheMu.Unlock()
}

func (s *HTTPSCertService) invalidateCertificateCache(serverName string) {
	serverName = normalizeCertDomain(serverName)
	if serverName == "" {
		return
	}
	s.cacheMu.Lock()
	delete(s.certCache, serverName)
	s.cacheMu.Unlock()
}

func (s *HTTPSCertService) certificateCandidates(serverName string) []string {
	candidates := []string{serverName}
	seen := map[string]struct{}{serverName: {}}

	for _, baseDomain := range s.baseDomains() {
		if baseDomain == "" {
			continue
		}
		if !strings.HasSuffix(serverName, "."+baseDomain) {
			continue
		}
		wildcard := "*." + baseDomain
		if _, ok := seen[wildcard]; ok {
			continue
		}
		seen[wildcard] = struct{}{}
		candidates = append(candidates, wildcard)
	}
	return candidates
}

func (s *HTTPSCertService) baseDomains() []string {
	var out []string

	if s.domainProvider != nil {
		out = append(out, normalizeCertDomain(s.domainProvider.GetAssignedDomain()))
		if s.domainProvider.GetCustomDomain() != "" {
			out = append(out, s.domainProvider.GetCustomDomain())
		}
	}
	return out
}

func (s *HTTPSCertService) isAssignedDomain(domain string) bool {
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return false
	}
	baseDomain := s.AssignedBaseDomain()
	if baseDomain == "" {
		return false
	}
	if domain == baseDomain {
		return true
	}
	return strings.HasSuffix(domain, "."+baseDomain)
}

func (s *HTTPSCertService) loadTLSCertFromDisk(domain string) (*tls.Certificate, error) {
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	base := sanitizeCertDomainForFile(domain)
	certPath := filepath.Join(s.certDir, base+".crt")
	keyPath := filepath.Join(s.certDir, base+".key")
	chainPath := filepath.Join(s.certDir, base+".chain.crt")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if chainPEM, chainErr := os.ReadFile(chainPath); chainErr == nil && len(chainPEM) > 0 {
		certPEM = append(certPEM, chainPEM...)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

type noopListener struct{}

func (noopListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("noop listener does not accept connections")
}

func (noopListener) Close() error {
	return nil
}

func (noopListener) Addr() net.Addr {
	return staticAddr("127.0.0.1:0")
}

type staticAddr string

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return string(a) }

func normalizeCertDomain(domain string) string {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return domain
}

func sanitizeCertDomainForFile(domain string) string {
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch)
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		case ch == '.', ch == '-':
			b.WriteByte(ch)
		case ch == '*':
			b.WriteString("wildcard")
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func loadUploadedCertificate(certDir, domain string, minRemaining time.Duration) (*letsencrypt.StoredCertificate, bool) {
	if strings.TrimSpace(certDir) == "" {
		return nil, false
	}
	base := sanitizeCertDomainForFile(domain)
	// ACME-managed files must keep their renewal window and metadata semantics.
	if fileExists(filepath.Join(certDir, base+".json")) {
		return nil, false
	}
	certPath := filepath.Join(certDir, base+".crt")
	keyPath := filepath.Join(certDir, base+".key")
	chainPath := filepath.Join(certDir, base+".chain.crt")

	if !fileExists(certPath) || !fileExists(keyPath) {
		return nil, false
	}

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || time.Now().Before(leaf.NotBefore) {
		return nil, false
	}
	if strings.HasPrefix(domain, "*.") {
		hasWildcard := false
		for _, name := range leaf.DNSNames {
			hasWildcard = hasWildcard || strings.EqualFold(name, domain)
		}
		if !hasWildcard {
			return nil, false
		}
	} else if leaf.VerifyHostname(domain) != nil {
		return nil, false
	}
	notAfter := leaf.NotAfter
	if time.Until(notAfter) <= minRemaining {
		return nil, false
	}

	return &letsencrypt.StoredCertificate{
		Domain:          domain,
		CertificatePath: certPath,
		PrivateKeyPath:  keyPath,
		ChainPath:       chainPath,
		NotAfter:        notAfter,
		UpdatedAt:       time.Now(),
	}, true
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseCertNotAfter(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}

func resolveACMEDirectoryURL() string {
	if v := strings.TrimSpace(os.Getenv("EDGE_LE_ACME_DIRECTORY")); v != "" {
		return v
	}
	if parseEnvBool("EDGE_LE_STAGING", "LETSENCRYPT_STAGING") {
		return letsencrypt.DefaultACMEStagingDirectoryURL
	}
	return letsencrypt.DefaultACMEProductionDirectoryURL
}

func resolveACMEContactEmail() string {
	if v := strings.TrimSpace(os.Getenv("EDGE_LE_EMAIL")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LETSENCRYPT_EMAIL")); v != "" {
		return v
	}
	return ""
}

func parseEnvBool(keys ...string) bool {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return false
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
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
		logger.Warnf("invalid duration env %s=%q, fallback=%s", key, raw, defaultValue)
	}
	return defaultValue
}

func resolveRenewWindowEnv(defaultValue time.Duration, keys ...string) time.Duration {
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
		logger.Warnf("invalid renew-window env %s=%q, fallback=%s", key, raw, defaultValue)
	}
	return defaultValue
}

func manualDNS01Executor(
	ctx context.Context,
	req *letsencrypt.DNS01Request,
	propagationWait time.Duration,
	propagationTicker time.Duration,
) error {
	if req == nil {
		return fmt.Errorf("dns-01 request is required")
	}
	domain := normalizeCertDomain(req.Domain)
	if domain == "" {
		return letsencrypt.ErrInvalidDomain
	}
	recordValue := strings.TrimSpace(req.KeyAuthorization)
	if recordValue == "" {
		return fmt.Errorf("dns-01 record value is required")
	}

	recordTarget := dns01RecordTargetDomain(domain)
	if recordTarget == "" {
		return letsencrypt.ErrInvalidDomain
	}
	recordName := "_acme-challenge." + recordTarget
	manualWait := propagationWait
	if manualWait < defaultManualDNS01Wait {
		manualWait = defaultManualDNS01Wait
	}

	logger.Warnf(
		"manual dns-01 required, domain=%s, record=%s, value=%s, hint=configure TXT in edge console or yat-fe edge management panel",
		domain, recordName, recordValue,
	)

	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, manualWait)
		defer cancel()
	}

	if err := waitForTXTRecord(waitCtx, recordName, recordValue, manualWait, propagationTicker); err != nil {
		return fmt.Errorf(
			"manual dns-01 required for %s: create TXT %s = %s in edge console or yat-fe edge management panel: %w",
			domain, recordName, recordValue, err,
		)
	}
	return nil
}

// delegatedDNS01Executor delegates DNS-01 challenge to external provider.
// Edge initiates LE dns-01 challenge and waits for TXT record to be provisioned.
func delegatedDNS01Executor(
	ctx context.Context,
	req *letsencrypt.DNS01Request,
	publisher DNS01ChallengePublisher,
	nodeID string,
	propagationWait time.Duration,
	propagationTicker time.Duration,
) error {
	if req == nil {
		return fmt.Errorf("dns-01 request is required")
	}
	domain := normalizeCertDomain(req.Domain)
	if domain == "" {
		return letsencrypt.ErrInvalidDomain
	}
	recordValue := strings.TrimSpace(req.KeyAuthorization)
	if recordValue == "" {
		return fmt.Errorf("dns-01 record value is required")
	}

	recordTarget := dns01RecordTargetDomain(domain)
	if recordTarget == "" {
		return letsencrypt.ErrInvalidDomain
	}
	recordName := "_acme-challenge." + recordTarget
	if publisher != nil {
		logger.Infof("dns-01 publish start, node_id=%s, domain=%s, record=%s, order_url=%s", nodeID, domain, recordName, req.ACMEOrderURL)
		if err := publisher(ctx, recordName, recordValue); err != nil {
			return fmt.Errorf("publish dns-01 challenge: %w", err)
		}
		logger.Infof("dns-01 publish success, node_id=%s, domain=%s, record=%s", nodeID, domain, recordName)
	}
	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, propagationWait)
		defer cancel()
	}

	logger.Infof(
		"dns-01 propagation check start, node_id=%s, domain=%s, record=%s, timeout=%s, order_url=%s",
		nodeID, domain, recordName, propagationWait, req.ACMEOrderURL,
	)
	if err := waitForTXTRecord(waitCtx, recordName, recordValue, propagationWait, propagationTicker); err != nil {
		return fmt.Errorf("dns-01 delegation not implemented or TXT not provisioned for %s: %w", recordName, err)
	}
	logger.Infof("dns-01 propagation check success, node_id=%s, domain=%s, record=%s", nodeID, domain, recordName)
	return nil
}

func waitForTXTRecord(ctx context.Context, fqdn, value string, propagationWait, propagationTicker time.Duration) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("dns record value is required")
	}
	if propagationWait <= 0 {
		propagationWait = defaultDNS01PropagationWait
	}
	if propagationTicker <= 0 {
		propagationTicker = defaultDNS01PropagationTicker
	}

	deadline := time.Now().Add(propagationWait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	for {
		records, err := net.DefaultResolver.LookupTXT(ctx, fqdn)
		if err == nil {
			for _, record := range records {
				if strings.TrimSpace(record) == value {
					return nil
				}
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("dns record not propagated yet: %s", fqdn)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(propagationTicker):
		}
	}
}

// CNAME status constants for EdgeStatusPush.cname_status field.
const (
	CnameStatusUnknown  uint8 = 0
	CnameStatusChecking uint8 = 1
	CnameStatusMatched  uint8 = 2
	CnameStatusMismatch uint8 = 3
	CnameStatusNotFound uint8 = 4
	CnameStatusError    uint8 = 5
)

// CheckCNAMEOnce performs a single, non-blocking CNAME lookup to verify that
// a wildcard record *.customDomain points to assignedDomain (or its parent).
// Returns one of the CnameStatus* constants.
func CheckCNAMEOnce(customDomain, assignedDomain string) uint8 {
	customDomain = normalizeCertDomain(customDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if customDomain == "" || assignedDomain == "" {
		return CnameStatusUnknown
	}

	// Wildcard DNS record *.customDomain does not match the bare domain itself,
	// so we probe a synthetic subdomain to verify the wildcard is in effect.
	probeDomain := "_yat-probe." + customDomain

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cname, _, err := lookupCNAMEWithPriority(ctx, probeDomain)
	if err != nil {
		return CnameStatusError
	}
	if cname == "" {
		return CnameStatusNotFound
	}

	if matchesAssignedDomainCNAME(cname, assignedDomain) {
		return CnameStatusMatched
	}

	return CnameStatusMismatch
}

// waitForCNAME polls DNS until customDomain has a CNAME pointing to assignedDomain (or its parent).
// This ensures the user has configured DNS before we start the ACME DNS-01 challenge.
func waitForCNAME(ctx context.Context, customDomain, assignedDomain string, ticker time.Duration) error {
	customDomain = normalizeCertDomain(customDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if ticker <= 0 {
		ticker = defaultCNAMECheckTicker
	}
	assignedBase := assignedDomainBase(assignedDomain)

	logger.Infof(
		"cname pre-check start, custom_domain=%s, expected_target=%s (or *.%s), resolvers=%v -> local",
		customDomain,
		assignedDomain,
		assignedBase,
		cnamePublicResolvers,
	)

	for {
		cname, source, err := lookupCNAMEWithPriority(ctx, customDomain)
		if err != nil {
			logger.Debugf("cname pre-check lookup error, custom_domain=%s, err=%v", customDomain, err)
		}
		if err == nil && cname != "" {
			if matchesAssignedDomainCNAME(cname, assignedDomain) {
				return nil
			}
			logger.Debugf(
				"cname pre-check mismatch, custom_domain=%s, resolver=%s, got=%s, want=%s",
				customDomain,
				source,
				cname,
				assignedDomain,
			)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("cname not resolved: configure CNAME %s -> %s: %w", customDomain, assignedDomain, ctx.Err())
		case <-time.After(ticker):
		}
	}
}

// waitForCustomDomainCNAME polls DNS until either:
// 1) customDomain itself points to assignedDomain, or
// 2) wildcard probe host (_yat-probe.customDomain) points to assignedDomain.
// For custom-domain wildcard certificate flow, wildcard CNAME is the primary signal.
func waitForCustomDomainCNAME(ctx context.Context, customDomain, assignedDomain string, ticker time.Duration) error {
	customDomain = normalizeCertDomain(customDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if customDomain == "" || assignedDomain == "" {
		return letsencrypt.ErrInvalidDomain
	}
	if ticker <= 0 {
		ticker = defaultCNAMECheckTicker
	}

	wildcardProbe := "_yat-probe." + customDomain
	assignedBase := assignedDomainBase(assignedDomain)

	logger.Infof(
		"custom-domain cname pre-check start, custom_domain=%s wildcard_probe=%s expected_target=%s (or *.%s), resolvers=%v -> local",
		customDomain,
		wildcardProbe,
		assignedDomain,
		assignedBase,
		cnamePublicResolvers,
	)

	for {
		customCNAME, customSource, customErr := lookupCNAMEWithPriority(ctx, customDomain)
		if customErr == nil && customCNAME != "" && matchesAssignedDomainCNAME(customCNAME, assignedDomain) {
			return nil
		}
		if customErr != nil {
			logger.Debugf("custom-domain cname pre-check lookup error, domain=%s, err=%v", customDomain, customErr)
		}

		wildcardCNAME, wildcardSource, wildcardErr := lookupCNAMEWithPriority(ctx, wildcardProbe)
		if wildcardErr == nil && wildcardCNAME != "" && matchesAssignedDomainCNAME(wildcardCNAME, assignedDomain) {
			return nil
		}
		if wildcardErr != nil {
			logger.Debugf("custom-domain wildcard pre-check lookup error, domain=%s, err=%v", wildcardProbe, wildcardErr)
		}

		logger.Debugf(
			"custom-domain cname pre-check pending, custom_domain=%s custom_resolver=%s custom_cname=%s wildcard_probe=%s wildcard_resolver=%s wildcard_cname=%s expected=%s",
			customDomain,
			customSource,
			customCNAME,
			wildcardProbe,
			wildcardSource,
			wildcardCNAME,
			assignedDomain,
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"cname not resolved: configure CNAME *.%s -> %s (or %s -> %s): %w",
				customDomain,
				assignedDomain,
				customDomain,
				assignedDomain,
				ctx.Err(),
			)
		case <-time.After(ticker):
		}
	}
}

func assignedDomainBase(assignedDomain string) string {
	assignedDomain = normalizeCertDomain(assignedDomain)
	if assignedDomain == "" {
		return ""
	}
	if idx := strings.IndexByte(assignedDomain, '.'); idx > 0 && idx+1 < len(assignedDomain) {
		return assignedDomain[idx+1:]
	}
	return assignedDomain
}

func matchesAssignedDomainCNAME(cname, assignedDomain string) bool {
	cname = normalizeCertDomain(cname)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if cname == "" || assignedDomain == "" {
		return false
	}
	assignedBase := assignedDomainBase(assignedDomain)
	return cname == assignedDomain || cname == assignedBase || strings.HasSuffix(cname, "."+assignedBase)
}

func lookupCNAMEWithPriority(ctx context.Context, domain string) (string, string, error) {
	domain = normalizeCertDomain(domain)
	if domain == "" {
		return "", "", nil
	}

	var lastErr error
	for _, dnsServer := range cnamePublicResolvers {
		resolver := resolverForDNSServer(dnsServer)
		cname, err := lookupCNAMEWithResolver(ctx, resolver, domain, defaultCNAMEPublicTimeout)
		if err == nil && cname != "" {
			return cname, dnsServer, nil
		}
		if err != nil && !isDNSLookupMiss(err) {
			lastErr = err
		}
	}

	cname, err := lookupCNAMEWithResolver(ctx, net.DefaultResolver, domain, defaultCNAMELocalTimeout)
	if err == nil && cname != "" {
		return cname, "local", nil
	}
	if err != nil && !isDNSLookupMiss(err) {
		lastErr = err
	}

	return "", "", lastErr
}

func resolverForDNSServer(dnsServer string) *net.Resolver {
	serverAddr := dnsServer
	if _, _, err := net.SplitHostPort(serverAddr); err != nil {
		serverAddr = net.JoinHostPort(serverAddr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, network, serverAddr)
		},
	}
}

func lookupCNAMEWithResolver(
	ctx context.Context,
	resolver *net.Resolver,
	domain string,
	timeout time.Duration,
) (string, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	queryCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		queryCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	cname, err := resolver.LookupCNAME(queryCtx, domain)
	if err != nil {
		return "", err
	}
	return normalizeCertDomain(cname), nil
}

func isDNSLookupMiss(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return true
		}
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "no such host") ||
		strings.Contains(errText, "nxdomain") ||
		strings.Contains(errText, "server misbehaving")
}

func cleanupDNS01Record(
	req *letsencrypt.IssueRequest,
	cleaner DNS01ChallengePublisher,
	timeout time.Duration,
	nodeID string,
	issueErr error,
) {
	if cleaner == nil || req == nil || req.Method != letsencrypt.ChallengeDNS01 {
		return
	}

	recordTarget := dns01RecordTargetDomain(req.Domain)
	if recordTarget == "" {
		return
	}
	recordName := "_acme-challenge." + recordTarget
	recordValue := strings.TrimSpace(req.KeyAuthorization)
	if recordValue == "" {
		return
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := cleaner(cleanupCtx, recordName, recordValue); err != nil {
		logger.Warnf(
			"dns-01 cleanup failed, node_id=%s, domain=%s, record=%s, order_url=%s, issue_err=%v, err=%v",
			nodeID, req.Domain, recordName, req.ACMEOrderURL, issueErr, err,
		)
		return
	}
	logger.Infof(
		"dns-01 cleanup success, node_id=%s, domain=%s, record=%s, order_url=%s, issue_err=%v",
		nodeID, req.Domain, recordName, req.ACMEOrderURL, issueErr,
	)
}

func dns01RecordTargetDomain(domain string) string {
	domain = normalizeCertDomain(domain)
	domain = strings.TrimPrefix(domain, "*.")
	return normalizeCertDomain(domain)
}

func cleanupTLSALPN01Challenge(
	req *letsencrypt.IssueRequest,
	handler *letsencrypt.TLSALPN01Handler,
	nodeID string,
	issueErr error,
) {
	if handler == nil || req == nil || req.Method != letsencrypt.ChallengeTLSALPN01 {
		return
	}

	domain := normalizeCertDomain(req.Domain)
	token := strings.TrimSpace(req.Token)
	if domain == "" || token == "" {
		return
	}

	handler.Delete(domain, token)
	logger.Infof(
		"tls-alpn-01 challenge cleanup success, node_id=%s, domain=%s, token=%s, order_url=%s, issue_err=%v",
		nodeID, domain, token, req.ACMEOrderURL, issueErr,
	)
}
