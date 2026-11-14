package handler

import (
	"fmt"
	"sort"
	"strings"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	logger "icool.io/yat/edge/pkg/log"
)

// Send
type EdgeStatusInfo struct {
	EdgeID                     string
	Online                     bool
	Uptime                     uint64
	PortUsage                  PortUsageInfo
	Stats                      ServiceStatsInfo
	Timestamp                  uint64
	SupportedProtocols         []string
	ActiveSessions             int32
	IsOwnerView                bool
	DNS01Challenges            []DNS01ChallengeStatusInfo
	CnameStatus                uint8
	AssignedDNSStatus          DomainStatusInfo
	CustomDNSStatus            DomainStatusInfo
	DomainRuntime              DomainRuntimeInfo
	WireGuardRelayRuntimeReady bool
}

// TunnelStatusInfo contains runtime status for one tunnel.
type TunnelStatusInfo struct {
	Success         bool
	TunnelID        string
	EdgeID          string
	Online          bool
	Uptime          uint64
	Timestamp       uint64
	TotalBytesIn    uint64
	TotalBytesOut   uint64
	Channels        []ChannelStatusInfo
	DNS01Challenges []DNS01ChallengeStatusInfo
	CnameStatus     uint8
	CustomDNSStatus DomainStatusInfo
	DomainRuntime   DomainRuntimeInfo
	ErrorCode       uint32
	ErrorMessage    string
}

// ChannelStatusInfo carries per-channel runtime/domain status.
type ChannelStatusInfo struct {
	ID                string
	SessionID         string
	UserID            string
	DeviceID          string
	ActorRole         uint8
	ActorSessionID    string
	ActorDeviceID     string
	Domain            string
	Subdomain         string
	AliasDomain       string
	DomainStatus      DomainStatusInfo
	AliasDomainStatus DomainStatusInfo
	ChannelKey        string
	Protocol          string
	LinkType          string
	RemoteEndpoint    string
	LocalAddr         string
	State             string
	BytesIn           uint64
	BytesOut          uint64
	ActiveConns       int32
	CreatedAt         uint64
}

// DomainStatusInfo holds cached DNS/cert status for a domain.
type DomainStatusInfo struct {
	DNSStatus     uint8
	CertStatus    uint8
	Error         string
	CertLastError string
	UpdatedAt     uint64
}

// DNS01ChallengeStatusInfo represents an active DNS-01 challenge for status reporting.
type DNS01ChallengeStatusInfo struct {
	RecordName  string
	RecordValue string
	Domain      string
	CreatedAt   uint64 // unix millis
	LastError   string
	UpdatedAt   uint64 // unix millis
}

// Info
type PortUsageInfo struct {
	TCPUsed   int32
	TCPTotal  int32
	TCPRange  string
	UDPUsed   int32
	UDPTotal  int32
	UDPRange  string
	HTTPPort  uint16
	HTTPSPort uint16
}

// Stats
type ServiceStatsInfo struct {
	TotalSessions    uint32
	ActiveSessions   uint32
	TotalChannels    uint32
	ActiveChannels   uint32
	TotalBytesIn     uint64
	TotalBytesOut    uint64
	TotalConnections uint64
	TotalRequests    uint64
	TotalErrors      uint64
}

// Send
type StatusSender interface {
	SendEdgeStatusPush(conn interface{}, status *EdgeStatusInfo, sessionID string) error
}

// TunnelStatusSender sends one-tunnel status response.
type TunnelStatusSender interface {
	SendTunnelStatusResponse(conn interface{}, status *TunnelStatusInfo, sessionID string) error
}

// Handle
func HandleEdgeStatusRequest(ctx *Context, req *fbMsg.EdgeStatusRequest) error {
	detailLevel := uint8(0)
	if req != nil {
		detailLevel = req.DetailLevel()
	}

	// Check
	isOwner := false
	if ctx.OwnerVerifier != nil {
		isOwner = ctx.OwnerVerifier.IsEdgeOwner(ctx.UserID)
	}

	// Get
	status := ctx.StatusManager.GetStatus()
	if status == nil {
		logger.Warnf("status manager returned nil status")
		return ctx.Protocol.SendError(ctx.Conn, fbMsg.ErrorCodeINTERNAL_ERROR, "status not available", ctx.SessionID)
	}

	// Build
	statusInfo := buildEdgeStatusInfo(ctx, status, isOwner, detailLevel)

	// Send
	if sender, ok := ctx.Protocol.(StatusSender); ok {
		return sender.SendEdgeStatusPush(ctx.Conn, statusInfo, ctx.SessionID)
	}

	// Send
	logger.Warnf("protocol does not support SendEdgeStatusPush, using fallback")
	return ctx.Protocol.SendError(ctx.Conn, fbMsg.ErrorCodeUNKNOWN, "status request processed", ctx.SessionID)
}

// HandleTunnelStatusRequest handles one-tunnel status request.
func HandleTunnelStatusRequest(ctx *Context, req *fbMsg.TunnelStatusRequest) error {
	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	if tunnelID == "" {
		return ctx.Protocol.SendError(ctx.Conn, fbMsg.ErrorCodeINVALID_MESSAGE, "tunnel_id is required", ctx.SessionID)
	}

	isOwner := false
	if ctx.OwnerVerifier != nil {
		isOwner = ctx.OwnerVerifier.IsEdgeOwner(ctx.UserID)
	}

	status := ctx.StatusManager.GetStatus()
	if status == nil {
		logger.Warnf("status manager returned nil status")
		return ctx.Protocol.SendError(ctx.Conn, fbMsg.ErrorCodeINTERNAL_ERROR, "status not available", ctx.SessionID)
	}

	tunnelStatus := buildTunnelStatusInfo(ctx, status, isOwner, tunnelID)
	if sender, ok := ctx.Protocol.(TunnelStatusSender); ok {
		return sender.SendTunnelStatusResponse(ctx.Conn, tunnelStatus, ctx.SessionID)
	}

	logger.Warnf("protocol does not support SendTunnelStatusResponse, using fallback")
	return ctx.Protocol.SendError(ctx.Conn, fbMsg.ErrorCodeUNKNOWN, "tunnel status request processed", ctx.SessionID)
}

// BuildEdgeStatusInfo projects an immutable service snapshot for one authenticated session.
// Both requested status and periodic pushes use the same visibility rules.
func BuildEdgeStatusInfo(ctx *Context, status *EdgeServiceStatus, isOwner bool) *EdgeStatusInfo {
	return buildEdgeStatusInfo(ctx, status, isOwner, 0)
}

// Build
func buildEdgeStatusInfo(ctx *Context, status *EdgeServiceStatus, isOwner bool, _ uint8) *EdgeStatusInfo {
	info := &EdgeStatusInfo{
		EdgeID:                     status.EdgeID,
		Online:                     status.Online,
		Uptime:                     uint64(status.Uptime),
		Timestamp:                  uint64(time.Now().UnixMilli()),
		IsOwnerView:                isOwner,
		WireGuardRelayRuntimeReady: status.WireGuardRelayRuntimeReady,
	}

	info.SupportedProtocols = make([]string, 0, 5)
	if ctx.Config != nil {
		if ctx.Config.Proxy.HTTP != nil && ctx.Config.Proxy.HTTP.Enabled {
			info.SupportedProtocols = append(info.SupportedProtocols, "http")
			if ctx.Config.Proxy.HTTP.HTTPSPort > 0 {
				info.SupportedProtocols = append(info.SupportedProtocols, "https")
			}
		}
		if ctx.Config.Proxy.TCP != nil && ctx.Config.Proxy.TCP.Enabled {
			info.SupportedProtocols = append(info.SupportedProtocols, "tcp")
		}
		if ctx.Config.Proxy.UDP != nil && ctx.Config.Proxy.UDP.Enabled {
			info.SupportedProtocols = append(info.SupportedProtocols, "udp")
		}
		if ctx.Config.Proxy.WireGuard != nil && ctx.Config.Proxy.WireGuard.Enabled {
			info.SupportedProtocols = append(info.SupportedProtocols, "wireguard")
		}
	}

	// Info
	if ctx.Config != nil {
		httpPort := uint16(0)
		httpsPort := uint16(0)
		tcpMin := uint16(0)
		tcpMax := uint16(0)
		udpMin := uint16(0)
		udpMax := uint16(0)
		if ctx.Config.Proxy.HTTP != nil {
			httpPort = ctx.Config.Proxy.HTTP.Port
			httpsPort = ctx.Config.Proxy.HTTP.HTTPSPort
		}
		if ctx.Config.Proxy.TCP != nil {
			tcpMin = ctx.Config.Proxy.TCP.PortMin
			tcpMax = ctx.Config.Proxy.TCP.PortMax
		}
		if ctx.Config.Proxy.UDP != nil {
			udpMin = ctx.Config.Proxy.UDP.PortMin
			udpMax = ctx.Config.Proxy.UDP.PortMax
		}
		tcpRange := ""
		tcpTotal := int32(0)
		if ctx.Config.Proxy.TCP != nil && ctx.Config.Proxy.TCP.Enabled && tcpMin > 0 && tcpMax >= tcpMin {
			tcpRange = fmt.Sprintf("%d-%d", tcpMin, tcpMax)
			tcpTotal = int32(tcpMax - tcpMin + 1)
		}

		udpRange := ""
		udpTotal := int32(0)
		if ctx.Config.Proxy.UDP != nil && ctx.Config.Proxy.UDP.Enabled && udpMin > 0 && udpMax >= udpMin {
			udpRange = fmt.Sprintf("%d-%d", udpMin, udpMax)
			udpTotal = int32(udpMax - udpMin + 1)
		}

		info.PortUsage = PortUsageInfo{
			TCPTotal:  tcpTotal,
			TCPRange:  tcpRange,
			UDPTotal:  udpTotal,
			UDPRange:  udpRange,
			HTTPPort:  httpPort,
			HTTPSPort: httpsPort,
		}
	}

	// Stats
	info.Stats = ServiceStatsInfo{
		TotalSessions:    status.Stats.TotalSessions,
		TotalChannels:    status.Stats.TotalChannels,
		TotalBytesIn:     status.Stats.TotalBytesIn,
		TotalBytesOut:    status.Stats.TotalBytesOut,
		TotalConnections: status.Stats.TotalConnections,
		TotalRequests:    status.Stats.TotalRequests,
		TotalErrors:      status.Stats.TotalErrors,
	}

	// Info
	if isOwner {
		info.ActiveSessions = int32(status.Stats.ActiveSessions)
		info.Stats.ActiveSessions = status.Stats.ActiveSessions
		info.Stats.ActiveChannels = status.Stats.ActiveChannels
		if ctx.DNS01ChallengeProvider != nil {
			rawChallenges := ctx.DNS01ChallengeProvider.GetActiveDNS01Challenges()
			customDomain := ""
			if ctx != nil && ctx.Config != nil {
				customDomain = ctx.Config.Channel.GetCustomDomain()
				if customDomain == "" {
					customDomain = ctx.Config.Channel.GetAssignedDomain()
				}
			}
			info.DNS01Challenges = filterEdgeChallenges(customDomain, rawChallenges)
		}
	}

	visibleChannelCount := 0
	tcpUsed := int32(0)
	udpUsed := int32(0)
	for _, ch := range status.Channels {
		if !isOwner && !channelVisibleToRequester(ctx, ch) {
			continue
		}

		visibleChannelCount++
		switch ch.Type {
		case uint8(fbMsg.ChannelTypeTCP):
			tcpUsed++
		case uint8(fbMsg.ChannelTypeUDP), uint8(fbMsg.ChannelTypeWIREGUARD):
			udpUsed++
		}

	}

	info.PortUsage.TCPUsed = tcpUsed
	info.PortUsage.UDPUsed = udpUsed

	if !isOwner {
		// For non-owner views, expose active channel count based on caller-visible channels
		// even when channels are omitted in low detail responses.
		info.Stats.ActiveChannels = uint32(visibleChannelCount)
	}

	// CNAME status (available to all clients)
	if ctx.CnameChecker != nil {
		info.CnameStatus = ctx.CnameChecker.CheckCNAMEOnce()
	}

	// Cached domain DNS/cert status (available to all clients)
	if ctx.DomainStatusProvider != nil {
		info.AssignedDNSStatus = ctx.DomainStatusProvider.GetAssignedDomainStatus()
		info.CustomDNSStatus = ctx.DomainStatusProvider.GetCustomDomainStatus()
	}
	if ctx.Config != nil && ctx.Config.Channel.BaseDomain != "" && ctx.Config.Channel.GetCustomDomain() == "" {
		if info.AssignedDNSStatus.DNSStatus == 1 {
			info.CnameStatus = cnameStatusMatched
		} else {
			info.CnameStatus = cnameStatusNotFound
		}
	}

	info.DomainRuntime = buildDomainRuntimeInfo(
		ctx,
		isOwner,
		info.CnameStatus,
		info.CustomDNSStatus,
		info.DNS01Challenges,
	)

	return info
}

func buildTunnelStatusInfo(ctx *Context, status *EdgeServiceStatus, isOwner bool, tunnelID string) *TunnelStatusInfo {
	info := &TunnelStatusInfo{
		Success:     true,
		TunnelID:    tunnelID,
		EdgeID:      status.EdgeID,
		Online:      status.Online,
		Uptime:      uint64(status.Uptime),
		Timestamp:   uint64(time.Now().UnixMilli()),
		CnameStatus: 0,
	}

	matchedChannels := 0
	tunnelAliasDomains := make(map[string]struct{})
	aliasRoutingRecordByKey := make(map[string]DomainRecordInfo)
	aliasDomainResolved := false
	aliasDomainStatusResolved := false
	aliasDomainAggregateStatus := DomainStatusInfo{}

	for _, ch := range status.Channels {
		if !channelMatchesTunnel(ch, tunnelID) {
			continue
		}
		if !isOwner && !channelVisibleToRequester(ctx, ch) {
			continue
		}
		matchedChannels++
		info.TotalBytesIn = info.TotalBytesIn + ch.BytesIn
		info.TotalBytesOut = info.TotalBytesOut + ch.BytesOut

		trackVisibleChallengeDomain(tunnelAliasDomains, ch.AliasDomain)

		channelInfo := ChannelStatusInfo{
			ID:             ch.ID,
			SessionID:      ch.SessionID,
			UserID:         ch.UserID,
			DeviceID:       ch.DeviceID,
			ActorRole:      ch.ActorRole,
			ActorSessionID: ch.ActorSessionID,
			ActorDeviceID:  ch.ActorDeviceID,
			Domain:         ch.Domain,
			Subdomain:      ch.Subdomain,
			AliasDomain:    ch.AliasDomain,
			ChannelKey:     ch.ChannelKey,
			Protocol:       ch.Protocol,
			LinkType:       ch.LinkType,
			RemoteEndpoint: ch.RemoteEndpoint,
			LocalAddr:      ch.LocalAddr,
			State:          ch.State,
			BytesIn:        ch.BytesIn,
			BytesOut:       ch.BytesOut,
			ActiveConns:    ch.ActiveConns,
			CreatedAt:      uint64(ch.CreatedAt),
		}

		if ctx.DomainStatusProvider != nil {
			channelInfo.DomainStatus = ctx.DomainStatusProvider.GetChannelDomainStatus(ch.Domain)
			channelInfo.AliasDomainStatus = ctx.DomainStatusProvider.GetChannelAliasDomainStatus(ch.AliasDomain, ch.Domain)

			if strings.TrimSpace(ch.AliasDomain) != "" {
				channelAliasCnameStatus := inferCnameStatusFromAliasDomainStatus(channelInfo.AliasDomainStatus)
				if !aliasDomainResolved {
					info.CnameStatus = channelAliasCnameStatus
					aliasDomainResolved = true
				} else {
					info.CnameStatus = mergeAliasCnameStatusForTunnel(info.CnameStatus, channelAliasCnameStatus)
				}

				aliasDomainAggregateStatus = mergeAliasDomainStatusForTunnel(aliasDomainAggregateStatus, channelInfo.AliasDomainStatus)
				aliasDomainStatusResolved = true
			}
		}
		if record, ok := buildAliasRoutingCNAMERecord(ch.AliasDomain, ch.Domain); ok {
			recordKey := normalizeChallengeDomain(record.RecordName) + "->" + normalizeChallengeDomain(record.RecordValue)
			aliasRoutingRecordByKey[recordKey] = record
		}

		info.Channels = append(info.Channels, channelInfo)
	}

	if matchedChannels == 0 {
		info.Success = false
		info.ErrorCode = uint32(fbMsg.ErrorCodeCHANNEL_NOT_FOUND)
		info.ErrorMessage = "tunnel not found or no visible channels"
		return info
	}

	if ctx.DNS01ChallengeProvider != nil {
		activeChallenges := ctx.DNS01ChallengeProvider.GetActiveDNS01Challenges()
		if len(activeChallenges) > 0 {
			info.DNS01Challenges = filterTunnelChallenges(tunnelAliasDomains, activeChallenges)
		}
	}

	if ctx.DomainStatusProvider != nil {
		info.CustomDNSStatus = ctx.DomainStatusProvider.GetCustomDomainStatus()
	}

	aliasRoutingRecords := make([]DomainRecordInfo, 0, len(aliasRoutingRecordByKey))
	for _, record := range aliasRoutingRecordByKey {
		aliasRoutingRecords = append(aliasRoutingRecords, record)
	}
	sort.Slice(aliasRoutingRecords, func(i, j int) bool {
		leftName := strings.TrimSpace(aliasRoutingRecords[i].RecordName)
		rightName := strings.TrimSpace(aliasRoutingRecords[j].RecordName)
		if leftName == rightName {
			return strings.TrimSpace(aliasRoutingRecords[i].RecordValue) < strings.TrimSpace(aliasRoutingRecords[j].RecordValue)
		}
		return leftName < rightName
	})

	if !aliasDomainStatusResolved {
		aliasDomainAggregateStatus = DomainStatusInfo{}
	}

	info.DomainRuntime = buildTunnelAliasDomainRuntimeInfo(
		isOwner,
		info.CnameStatus,
		aliasDomainAggregateStatus,
		aliasRoutingRecords,
		info.DNS01Challenges,
	)

	return info
}

func inferCnameStatusFromAliasDomainStatus(status DomainStatusInfo) uint8 {
	if status.DNSStatus == 0 {
		return 0
	}
	if status.DNSStatus == 1 {
		return 2
	}

	errText := strings.ToLower(strings.TrimSpace(status.Error))
	switch {
	case strings.Contains(errText, "mismatch"):
		return 3
	case strings.Contains(errText, "not found"):
		return 4
	case errText != "":
		return 5
	default:
		return 0
	}
}

func channelMatchesTunnel(ch ChannelStatus, tunnelID string) bool {
	channelID := strings.TrimSpace(ch.ID)
	if channelID == "" || tunnelID == "" {
		return false
	}
	return channelID == tunnelID || strings.HasPrefix(channelID, tunnelID+":")
}

func normalizeChallengeDomain(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimSuffix(value, ".")
	value = strings.TrimPrefix(value, "*.")
	return value
}

func trackVisibleChallengeDomain(visible map[string]struct{}, raw string) {
	normalized := normalizeChallengeDomain(raw)
	if normalized == "" {
		return
	}
	visible[normalized] = struct{}{}
}

func challengeMatchesTargetDomains(challenge DNS01ChallengeStatusInfo, targets map[string]struct{}) bool {
	if len(targets) == 0 {
		return false
	}

	challengeDomain := normalizeChallengeDomain(challenge.Domain)
	if challengeDomain != "" {
		if _, ok := targets[challengeDomain]; ok {
			return true
		}
	}

	recordTarget := normalizeChallengeDomain(strings.TrimPrefix(challenge.RecordName, "_acme-challenge."))
	if recordTarget != "" {
		if _, ok := targets[recordTarget]; ok {
			return true
		}
	}

	return false
}

func filterTunnelChallenges(
	tunnelAliasDomains map[string]struct{},
	challenges []DNS01ChallengeStatusInfo,
) []DNS01ChallengeStatusInfo {
	if len(challenges) == 0 || len(tunnelAliasDomains) == 0 {
		return nil
	}

	filtered := make([]DNS01ChallengeStatusInfo, 0, len(challenges))
	for _, challenge := range challenges {
		if challengeMatchesTargetDomains(challenge, tunnelAliasDomains) {
			filtered = append(filtered, challenge)
		}
	}
	return filtered
}

func mergeAliasCnameStatusForTunnel(current, next uint8) uint8 {
	cnameSeverity := func(status uint8) int {
		switch status {
		case cnameStatusError:
			return 6
		case cnameStatusMismatch:
			return 5
		case cnameStatusNotFound:
			return 4
		case cnameStatusChecking:
			return 3
		case cnameStatusUnknown:
			return 2
		case cnameStatusMatched:
			return 1
		default:
			return 0
		}
	}

	if cnameSeverity(next) > cnameSeverity(current) {
		return next
	}
	return current
}

func mergeAliasDomainStatusForTunnel(current, next DomainStatusInfo) DomainStatusInfo {
	if next.DNSStatus == 2 {
		current.DNSStatus = 2
	} else if next.DNSStatus == 1 && current.DNSStatus != 2 {
		current.DNSStatus = 1
	}

	if next.CertStatus == 2 {
		current.CertStatus = 2
	} else if next.CertStatus == 1 && current.CertStatus != 2 {
		current.CertStatus = 1
	}

	if current.Error == "" {
		current.Error = strings.TrimSpace(next.Error)
	}
	if current.CertLastError == "" {
		current.CertLastError = strings.TrimSpace(next.CertLastError)
	}
	if next.UpdatedAt > current.UpdatedAt {
		current.UpdatedAt = next.UpdatedAt
	}

	return current
}

func buildAliasRoutingCNAMERecord(aliasDomain, assignedDomain string) (DomainRecordInfo, bool) {
	alias := strings.TrimSpace(aliasDomain)
	assigned := strings.TrimSpace(assignedDomain)
	if alias == "" || assigned == "" {
		return DomainRecordInfo{}, false
	}
	return DomainRecordInfo{
		RecordType:  DomainRecordTypeCNAME,
		RecordName:  alias,
		RecordValue: assigned,
		TTL:         0,
		Source:      "routing",
	}, true
}

func filterEdgeChallenges(customDomainRaw string, challenges []DNS01ChallengeStatusInfo) []DNS01ChallengeStatusInfo {
	if len(challenges) == 0 {
		return nil
	}

	customDomain := normalizeChallengeDomain(customDomainRaw)
	if customDomain == "" {
		return nil
	}

	filtered := make([]DNS01ChallengeStatusInfo, 0, len(challenges))
	for _, challenge := range challenges {
		challengeDomain := normalizeChallengeDomain(challenge.Domain)
		if challengeDomain == customDomain {
			filtered = append(filtered, challenge)
			continue
		}

		recordTarget := normalizeChallengeDomain(strings.TrimPrefix(challenge.RecordName, "_acme-challenge."))
		if recordTarget == customDomain {
			filtered = append(filtered, challenge)
		}
	}

	return filtered
}

func channelVisibleToRequester(ctx *Context, ch ChannelStatus) bool {
	if ctx == nil {
		return false
	}

	requestUserID := strings.TrimSpace(ctx.UserID)
	requestSessionID := strings.TrimSpace(ctx.SessionID)
	requestDeviceID := strings.TrimSpace(ctx.DeviceID)

	if requestUserID != "" && strings.TrimSpace(ch.UserID) == requestUserID {
		return true
	}

	if requestSessionID != "" {
		if strings.TrimSpace(ch.SessionID) == requestSessionID {
			return true
		}
		if strings.TrimSpace(ch.ActorSessionID) == requestSessionID {
			return true
		}
	}

	if requestDeviceID != "" {
		if strings.TrimSpace(ch.DeviceID) == requestDeviceID {
			return true
		}
		if strings.TrimSpace(ch.ActorDeviceID) == requestDeviceID {
			return true
		}
	}

	return false
}
