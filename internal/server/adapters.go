package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/internal/server/handler"
	"icool.io/yat/edge/pkg/config"
)

// Interface
type protocolAdapter struct {
	p *Protocol
}

func (a *protocolAdapter) SendError(conn net.Conn, errCode fbMsg.ErrorCode, errMsg, sessionID string) error {
	return a.p.SendError(conn, errCode, errMsg, sessionID)
}

func (a *protocolAdapter) SendEdgeOnlineResponse(conn net.Conn, success bool, errCode uint32, errMsg, sessionID string) error {
	return a.p.SendEdgeOnlineResponse(conn, success, errCode, errMsg, sessionID)
}

func (a *protocolAdapter) SendEdgeOfflineResponse(conn net.Conn, success bool, errCode uint32, errMsg, sessionID string) error {
	return a.p.SendEdgeOfflineResponse(conn, success, errCode, errMsg, sessionID)
}

func (a *protocolAdapter) WriteMessage(conn net.Conn, data []byte) error {
	return a.p.WriteMessage(conn, data)
}

func (a *protocolAdapter) GetBuilder() handler.Builder {
	return a.p.builder
}

// Interface
func (a *protocolAdapter) SendEdgeStatusPush(conn interface{}, status *handler.EdgeStatusInfo, sessionID string) error {
	netConn, ok := conn.(net.Conn)
	if !ok {
		return nil
	}
	return a.p.SendEdgeStatusPush(netConn, status, sessionID)
}

func (a *protocolAdapter) SendTunnelStatusResponse(conn interface{}, status *handler.TunnelStatusInfo, sessionID string) error {
	netConn, ok := conn.(net.Conn)
	if !ok {
		return nil
	}
	return a.p.SendTunnelStatusResponse(netConn, status, sessionID)
}

// Interface
type statusManagerAdapter struct {
	source interface {
		GetStatus() *channel.EdgeServiceStatus
	}
}

func (a *statusManagerAdapter) GetStatus() *handler.EdgeServiceStatus {
	if a.source == nil {
		return nil
	}
	status := a.source.GetStatus()
	if status == nil {
		return nil
	}

	return convertServiceStatus(status)
}

func convertServiceStatus(status *channel.EdgeServiceStatus) *handler.EdgeServiceStatus {
	channels := make([]handler.ChannelStatus, 0, len(status.Targets))
	for _, t := range status.Targets {
		channels = append(channels, handler.ChannelStatus{
			ID:             t.ID,
			Type:           typeStringToUint8(t.Type),
			SessionID:      t.SessionID,
			UserID:         t.UserID,
			DeviceID:       t.DeviceID,
			ActorRole:      t.ActorRole,
			ActorSessionID: t.ActorSessionID,
			ActorDeviceID:  t.ActorDeviceID,
			Domain:         t.Domain,
			Subdomain:      t.Subdomain,
			AliasDomain:    t.AliasDomain,
			Port:           t.Port,
			LocalAddr:      t.LocalAddr,
			State:          t.State,
			BytesIn:        t.BytesIn,
			BytesOut:       t.BytesOut,
			Connections:    t.Connections,
			ActiveConns:    t.ActiveConns,
			CreatedAt:      t.CreatedAt,
			ChannelKey:     t.ChannelKey,
			Protocol:       t.Protocol,
			LinkType:       t.LinkType,
			RemoteEndpoint: t.RemoteEndpoint,
		})
	}

	return &handler.EdgeServiceStatus{
		EdgeID:                     status.EdgeID,
		Online:                     status.Online,
		Uptime:                     status.Uptime,
		LastUpdated:                status.LastUpdated,
		WireGuardRelayRuntimeReady: status.WireGuardRelayRuntimeReady,
		Channels:                   channels,
		Stats: handler.ServiceStats{
			TotalSessions:    status.Stats.TotalSessions,
			ActiveSessions:   status.Stats.ActiveSessions,
			TotalChannels:    status.Stats.TotalTargets,
			ActiveChannels:   status.Stats.ActiveTargets,
			TotalBytesIn:     status.Stats.TotalBytesIn,
			TotalBytesOut:    status.Stats.TotalBytesOut,
			TotalConnections: status.Stats.TotalConnections,
			TotalRequests:    status.Stats.TotalRequests,
			TotalErrors:      status.Stats.TotalErrors,
		},
	}
}

func typeStringToUint8(t string) uint8 {
	switch t {
	case "HTTP":
		return uint8(fbMsg.ChannelTypeHTTP)
	case "HTTPS":
		return uint8(fbMsg.ChannelTypeHTTPS)
	case "TCP":
		return uint8(fbMsg.ChannelTypeTCP)
	case "UDP":
		return uint8(fbMsg.ChannelTypeUDP)
	case "WIREGUARD":
		return uint8(fbMsg.ChannelTypeWIREGUARD)
	default:
		return uint8(fbMsg.ChannelTypeUNKNOWN)
	}
}

// dns01ChallengeAdapter adapts HTTPSCertService to handler.DNS01ChallengeProvider.
type dns01ChallengeAdapter struct {
	svc *HTTPSCertService
}

func (a *dns01ChallengeAdapter) GetActiveDNS01Challenges() []handler.DNS01ChallengeStatusInfo {
	if a.svc == nil {
		return nil
	}
	challenges := a.svc.GetActiveDNS01Challenges()
	out := make([]handler.DNS01ChallengeStatusInfo, len(challenges))
	for i, ch := range challenges {
		out[i] = handler.DNS01ChallengeStatusInfo{
			RecordName:  ch.RecordName,
			RecordValue: ch.RecordValue,
			Domain:      ch.Domain,
			CreatedAt:   uint64(ch.CreatedAt.UnixMilli()),
			LastError:   ch.LastError,
			UpdatedAt:   uint64(ch.UpdatedAt.UnixMilli()),
		}
	}
	return out
}

// cnameCheckerAdapter adapts DomainProvider + cached CnameStatus to handler.CnameChecker.
type cnameCheckerAdapter struct {
	dp *config.DomainConfig
}

func (a *cnameCheckerAdapter) CheckCNAMEOnce() uint8 {
	if a.dp == nil {
		return CnameStatusUnknown
	}
	customDomain := strings.TrimSpace(a.dp.GetCustomDomain())
	assignedDomain := strings.TrimSpace(a.dp.GetAssignedDomain())
	return CheckCNAMEOnce(customDomain, assignedDomain)
}

// domainStatusAdapter adapts DomainConfig to handler.DomainStatusProvider.
type domainStatusAdapter struct {
	dp      *config.DomainConfig
	certSvc *HTTPSCertService

	mu              sync.Mutex
	lastRefreshedAt time.Time
	assignedCache   handler.DomainStatusInfo
	customCache     handler.DomainStatusInfo
	refreshInterval time.Duration
}

const defaultDomainStatusRefreshInterval = 5 * time.Second

func (a *domainStatusAdapter) refreshIfNeeded() {
	if a.dp == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	interval := a.refreshInterval
	if interval <= 0 {
		interval = defaultDomainStatusRefreshInterval
	}
	if !a.lastRefreshedAt.IsZero() && time.Since(a.lastRefreshedAt) < interval {
		return
	}

	assignedDomain := strings.TrimSpace(a.dp.GetAssignedDomain())
	customDomain := strings.TrimSpace(a.dp.GetCustomDomain())

	a.assignedCache = a.buildAssignedDomainStatus(assignedDomain)
	a.customCache = a.buildCustomDomainStatus(customDomain, assignedDomain)
	a.lastRefreshedAt = time.Now()
}

func (a *domainStatusAdapter) buildAssignedDomainStatus(assignedDomain string) handler.DomainStatusInfo {
	if assignedDomain == "" {
		return handler.DomainStatusInfo{}
	}

	dnsStatus, dnsErr := resolveDomainDNSStatusWithFallback(assignedDomain, false)
	out := handler.DomainStatusInfo{
		DNSStatus: dnsStatus,
		UpdatedAt: uint64(time.Now().UnixMilli()),
	}
	if dnsErr != "" {
		out.Error = dnsErr
	}

	certReady := a.hasCertForDomain(assignedDomain)
	if a.certSvc == nil {
		out.CertStatus = config.CertStatusUnknown
	} else if certReady {
		out.CertStatus = config.CertStatusReady
		if out.DNSStatus == 0 {
			out.DNSStatus = config.DNSStatusResolved
		}
	} else {
		out.CertStatus = config.CertStatusMissing
		out.CertLastError, _ = a.resolveCertIssueStatusForDomain(assignedDomain)
	}

	return out
}

func (a *domainStatusAdapter) buildCustomDomainStatus(customDomain, assignedDomain string) handler.DomainStatusInfo {
	if customDomain == "" {
		return handler.DomainStatusInfo{}
	}

	out := handler.DomainStatusInfo{
		UpdatedAt: uint64(time.Now().UnixMilli()),
	}
	if assignedDomain != "" {
		switch CheckCNAMEOnce(customDomain, assignedDomain) {
		case CnameStatusMatched:
			out.DNSStatus = config.DNSStatusResolved
		case CnameStatusMismatch:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname mismatch: %s must point to %s", customDomain, assignedDomain)
		case CnameStatusNotFound:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname not found: %s", customDomain)
		case CnameStatusError:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname lookup failed: %s", customDomain)
		default:
			out.DNSStatus = config.DNSStatusUnknown
		}
	} else {
		dnsStatus, dnsErr := resolveDomainDNSStatus(customDomain)
		out.DNSStatus = dnsStatus
		out.Error = dnsErr
	}

	certReady := a.hasCertForDomain(customDomain)
	if certReady {
		out.CertStatus = config.CertStatusReady
	} else {
		out.CertStatus = config.CertStatusMissing
		out.CertLastError, _ = a.resolveCertIssueStatusForDomain(customDomain)
	}

	return out
}

func (a *domainStatusAdapter) hasCertForDomain(domain string) bool {
	if a.certSvc == nil {
		return false
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}

	if a.certSvc.HasUsableCertificate(domain) {
		return true
	}
	if a.certSvc.HasUsableCertificate("*." + domain) {
		return true
	}
	return false
}

func (a *domainStatusAdapter) hasCertForHost(serverName string) bool {
	if a.certSvc == nil {
		return false
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return false
	}
	return a.certSvc.HasUsableCertificateForServerName(serverName)
}

func (a *domainStatusAdapter) resolveCertIssueStatusForDomain(domain string) (string, uint64) {
	if a.certSvc == nil {
		return "", 0
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", 0
	}

	exactErr, exactAt := a.certSvc.GetCertificateIssueStatus(domain)
	wildcardErr, wildcardAt := a.certSvc.GetCertificateIssueStatus("*." + domain)
	if wildcardAt.After(exactAt) {
		return wildcardErr, uint64(wildcardAt.UnixMilli())
	}
	return exactErr, uint64(exactAt.UnixMilli())
}

func (a *domainStatusAdapter) resolveCertIssueStatusForHost(serverName string) (string, uint64) {
	if a.certSvc == nil {
		return "", 0
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return "", 0
	}
	lastErr, updatedAt := a.certSvc.GetCertificateIssueStatusForServerName(serverName)
	return lastErr, uint64(updatedAt.UnixMilli())
}

func resolveDomainDNSStatus(domain string) (uint8, string) {
	return resolveDomainDNSStatusWithFallback(domain, true)
}

func resolveDomainDNSStatusWithFallback(domain string, allowApex bool) (uint8, string) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return config.DNSStatusUnknown, ""
	}

	probe := "_yat-probe." + domain
	ctxCNAME, cancelCNAME := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCNAME()

	if cname, _, err := lookupCNAMEWithPriority(ctxCNAME, probe); err == nil && strings.TrimSpace(cname) != "" {
		return config.DNSStatusResolved, ""
	}
	ctxWildcard, cancelWildcard := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelWildcard()
	if addrs, _, err := lookupHostWithPriority(ctxWildcard, probe); err == nil && len(addrs) > 0 {
		return config.DNSStatusResolved, ""
	}
	if !allowApex {
		return config.DNSStatusFailed, fmt.Sprintf("wildcard DNS lookup failed: *.%s", domain)
	}

	ctxHost, cancelHost := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelHost()
	addrs, _, err := lookupHostWithPriority(ctxHost, domain)
	if err == nil && len(addrs) > 0 {
		return config.DNSStatusResolved, ""
	}

	if err != nil {
		return config.DNSStatusFailed, err.Error()
	}
	return config.DNSStatusFailed, fmt.Sprintf("dns lookup failed: %s", domain)
}

func lookupHostWithPriority(ctx context.Context, domain string) ([]string, string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, "", nil
	}

	var lastErr error
	for _, dnsServer := range cnamePublicResolvers {
		resolver := resolverForDNSServer(dnsServer)
		queryCtx, cancel := context.WithTimeout(ctx, defaultCNAMEPublicTimeout)
		addrs, err := resolver.LookupHost(queryCtx, domain)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs, dnsServer, nil
		}
		if err != nil && !isDNSLookupMiss(err) {
			lastErr = err
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, defaultCNAMELocalTimeout)
	addrs, err := net.DefaultResolver.LookupHost(queryCtx, domain)
	cancel()
	if err == nil && len(addrs) > 0 {
		return addrs, "local", nil
	}
	if err != nil && !isDNSLookupMiss(err) {
		lastErr = err
	}

	return nil, "", lastErr
}

func (a *domainStatusAdapter) GetAssignedDomainStatus() handler.DomainStatusInfo {
	if a.dp == nil {
		return handler.DomainStatusInfo{}
	}
	a.refreshIfNeeded()
	return a.assignedCache
}

func (a *domainStatusAdapter) GetCustomDomainStatus() handler.DomainStatusInfo {
	if a.dp == nil {
		return handler.DomainStatusInfo{}
	}
	a.refreshIfNeeded()
	if a.dp.GetCustomDomain() == "" {
		return a.assignedCache
	}
	return a.customCache
}

func (a *domainStatusAdapter) GetChannelDomainStatus(channelDomain string) handler.DomainStatusInfo {
	channelDomain = strings.TrimSpace(channelDomain)
	if channelDomain == "" {
		return handler.DomainStatusInfo{}
	}

	dnsStatus, dnsErr := resolveDomainDNSStatus(channelDomain)
	out := handler.DomainStatusInfo{
		DNSStatus: dnsStatus,
		UpdatedAt: uint64(time.Now().UnixMilli()),
	}
	if dnsErr != "" {
		out.Error = dnsErr
	}

	if a.hasCertForHost(channelDomain) {
		out.CertStatus = config.CertStatusReady
		if out.DNSStatus == config.DNSStatusUnknown {
			out.DNSStatus = config.DNSStatusResolved
		}
	} else {
		out.CertStatus = config.CertStatusMissing
		out.CertLastError, _ = a.resolveCertIssueStatusForHost(channelDomain)
	}
	return out
}

func (a *domainStatusAdapter) GetChannelAliasDomainStatus(aliasDomain, assignedDomain string) handler.DomainStatusInfo {
	aliasDomain = strings.TrimSpace(aliasDomain)
	assignedDomain = strings.TrimSpace(assignedDomain)
	if aliasDomain == "" {
		return handler.DomainStatusInfo{}
	}

	out := handler.DomainStatusInfo{
		UpdatedAt: uint64(time.Now().UnixMilli()),
	}
	if assignedDomain != "" {
		switch CheckCNAMEForAliasOnce(aliasDomain, assignedDomain) {
		case CnameStatusMatched:
			out.DNSStatus = config.DNSStatusResolved
		case CnameStatusMismatch:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname mismatch: %s must point to %s", aliasDomain, assignedDomain)
		case CnameStatusNotFound:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname not found: %s", aliasDomain)
		case CnameStatusError:
			out.DNSStatus = config.DNSStatusFailed
			out.Error = fmt.Sprintf("cname lookup failed: %s", aliasDomain)
		default:
			out.DNSStatus = config.DNSStatusUnknown
		}
	} else {
		dnsStatus, dnsErr := resolveDomainDNSStatus(aliasDomain)
		out.DNSStatus = dnsStatus
		out.Error = dnsErr
	}

	if a.hasCertForHost(aliasDomain) {
		out.CertStatus = config.CertStatusReady
		if out.DNSStatus == config.DNSStatusUnknown {
			out.DNSStatus = config.DNSStatusResolved
		}
	} else {
		out.CertStatus = config.CertStatusMissing
		out.CertLastError, _ = a.resolveCertIssueStatusForHost(aliasDomain)
	}
	return out
}

// CheckCNAMEForAliasOnce verifies aliasDomain itself points to assignedDomain.
// Unlike CheckCNAMEOnce (wildcard probe), alias-domain check must query the
// exact host because channel alias is a concrete host record.
func CheckCNAMEForAliasOnce(aliasDomain, assignedDomain string) uint8 {
	aliasDomain = normalizeCertDomain(aliasDomain)
	assignedDomain = normalizeCertDomain(assignedDomain)
	if aliasDomain == "" || assignedDomain == "" {
		return CnameStatusUnknown
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cname, _, err := lookupCNAMEWithPriority(ctx, aliasDomain)
	if err != nil {
		return CnameStatusError
	}
	if cname == "" {
		return CnameStatusNotFound
	}

	assignedBase := assignedDomain
	if idx := strings.IndexByte(assignedDomain, '.'); idx > 0 && idx+1 < len(assignedDomain) {
		assignedBase = assignedDomain[idx+1:]
	}
	if cname == assignedDomain || cname == assignedBase || strings.HasSuffix(cname, "."+assignedBase) {
		return CnameStatusMatched
	}
	return CnameStatusMismatch
}
