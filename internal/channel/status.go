package channel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/ice"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	logger "icool.io/yat/edge/pkg/log"
)

// Status
type EdgeServiceStatus struct {
	EdgeID                     string                               `json:"edge_id"`
	Online                     bool                                 `json:"online"`
	StartTime                  int64                                `json:"start_time"`
	Uptime                     int64                                `json:"uptime"`
	Targets                    []TargetInfo                         `json:"targets"`
	PortUsage                  PortUsageStatus                      `json:"port_usage"`
	Stats                      ServiceStats                         `json:"stats"`
	P2P                        map[string]map[string]string         `json:"p2p,omitempty"`
	P2PSessions                map[string]map[string]P2PSessionInfo `json:"p2p_sessions,omitempty"`
	SubdomainResolution        *SubdomainResolutionStats            `json:"subdomain_resolution,omitempty"`
	ICE                        *ice.ControllerSnapshot              `json:"ice,omitempty"`
	ICEStats                   *ice.ICEStats                        `json:"ice_stats,omitempty"`
	WireGuardEnabled           bool                                 `json:"wireguard_enabled"`
	WireGuardRelayEnabled      bool                                 `json:"wireguard_relay_enabled"`
	WireGuardInterfacePrefix   string                               `json:"wireguard_interface_prefix,omitempty"`
	WireGuardListenPortBase    int                                  `json:"wireguard_listen_port_base"`
	WireGuardKeyDir            string                               `json:"wireguard_key_dir,omitempty"`
	WireGuardPublicEndpoint    string                               `json:"wireguard_public_endpoint,omitempty"`
	WireGuardRelayRuntimeReady bool                                 `json:"wireguard_relay_runtime_ready"`
	LastUpdated                int64                                `json:"last_updated"`
}

type SubdomainResolutionStats struct {
	StartTotal                    uint64 `json:"start_total,omitempty"`
	StartFieldTotal               uint64 `json:"start_field_total,omitempty"`
	StartMetadataFallbackTotal    uint64 `json:"start_metadata_fallback_total,omitempty"`
	StartNoneTotal                uint64 `json:"start_none_total,omitempty"`
	JoinHintTotal                 uint64 `json:"join_hint_total,omitempty"`
	JoinHintFieldTotal            uint64 `json:"join_hint_field_total,omitempty"`
	JoinHintMetadataFallbackTotal uint64 `json:"join_hint_metadata_fallback_total,omitempty"`
	JoinHintNoneTotal             uint64 `json:"join_hint_none_total,omitempty"`
	JoinHintMismatchTotal         uint64 `json:"join_hint_mismatch_total,omitempty"`
	UpdatedAtUnix                 int64  `json:"updated_at,omitempty"`
}

type P2PSessionInfo struct {
	Status             string            `json:"status"`
	PathState          string            `json:"path_state,omitempty"`
	PathType           string            `json:"path_type,omitempty"`
	LinkType           string            `json:"link_type,omitempty"`
	PreferredLinks     []string          `json:"preferred_links,omitempty"`
	AllowRelayFallback bool              `json:"allow_relay_fallback,omitempty"`
	RequireDirect      bool              `json:"require_direct,omitempty"`
	LastError          string            `json:"last_error,omitempty"`
	FallbackReason     string            `json:"fallback_reason,omitempty"`
	NATTypes           map[string]string `json:"nat_types,omitempty"`
	PublicAddrs        map[string]string `json:"public_addrs,omitempty"`
	CreatedAt          int64             `json:"created_at,omitempty"`
	UpdatedAt          int64             `json:"updated_at,omitempty"`
}

// Info
type TargetInfo struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	SessionID          string   `json:"session_id"`
	UserID             string   `json:"user_id"`
	DeviceID           string   `json:"device_id"`
	Hostname           string   `json:"hostname,omitempty"`
	ActorRole          uint8    `json:"actor_role"`
	ActorSessionID     string   `json:"actor_session_id"`
	ActorDeviceID      string   `json:"actor_device_id"`
	ActorHostname      string   `json:"actor_hostname,omitempty"`
	Domain             string   `json:"domain,omitempty"`
	Subdomain          string   `json:"subdomain,omitempty"`
	AliasDomain        string   `json:"alias_domain,omitempty"`
	Port               uint16   `json:"port,omitempty"`
	LocalAddr          string   `json:"local_addr"`
	State              string   `json:"state"`
	BytesIn            uint64   `json:"bytes_in"`
	BytesOut           uint64   `json:"bytes_out"`
	Connections        uint64   `json:"connections"`
	ActiveConns        int32    `json:"active_conns"`
	Requests           uint64   `json:"requests"`
	CreatedAt          int64    `json:"created_at"`
	ChannelKey         string   `json:"channel_key,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	LinkType           string   `json:"link_type,omitempty"`
	PreferredLinks     []string `json:"preferred_links,omitempty"`
	AllowRelayFallback bool     `json:"allow_relay_fallback,omitempty"`
	RequireDirect      bool     `json:"require_direct,omitempty"`
	RemoteEndpoint     string   `json:"remote_endpoint,omitempty"`
	// ConnRemoteAddr 是该 channel 所属 session.Conn 的对端地址（客户端到 edge 的真实 host:port），
	// 仅 runtime 存在，用于 CLI 等订阅者展示。
	ConnRemoteAddr string `json:"conn_remote_addr,omitempty"`
}

// Status
type PortUsageStatus struct {
	TCPUsed   int    `json:"tcp_used"`
	TCPTotal  int    `json:"tcp_total"`
	TCPRange  string `json:"tcp_range"`
	UDPUsed   int    `json:"udp_used"`
	UDPTotal  int    `json:"udp_total"`
	UDPRange  string `json:"udp_range"`
	HTTPPort  uint16 `json:"http_port"`
	HTTPSPort uint16 `json:"https_port"`
}

// Stats
type ServiceStats struct {
	TotalSessions    uint32 `json:"total_sessions"`
	ActiveSessions   uint32 `json:"active_sessions"`
	TotalTargets     uint32 `json:"total_targets"`
	ActiveTargets    uint32 `json:"active_targets"`
	TotalBytesIn     uint64 `json:"total_bytes_in"`
	TotalBytesOut    uint64 `json:"total_bytes_out"`
	TotalConnections uint64 `json:"total_connections"`
	TotalRequests    uint64 `json:"total_requests"`
	TotalErrors      uint64 `json:"total_errors"`
}

// Status
type StatusManager struct {
	edgeID                     string
	statusFile                 string
	startTime                  time.Time
	online                     bool
	wireguardRelayRuntimeReady bool
	wireguardEnabled           bool
	wireguardRelayEnabled      bool
	wireguardInterfacePrefix   string
	wireguardListenPortBase    int
	wireguardKeyDir            string
	wireguardPublicEndpoint    string

	registry                         *Registry
	p2p                              *p2p.Runtime
	iceCtrl                          *ice.Controller
	subdomainResolutionStatsProvider func() *SubdomainResolutionStats

	// Config
	tcpPortMin uint16
	tcpPortMax uint16
	udpPortMin uint16
	udpPortMax uint16
	httpPort   uint16
	httpsPort  uint16

	// Stats
	stats ServiceStats

	// Status
	onStatusChange func(*EdgeServiceStatus)

	mu sync.RWMutex
}

// Status
type StatusManagerConfig struct {
	EdgeID                           string
	StatusDir                        string
	Registry                         *Registry
	P2PRuntime                       *p2p.Runtime
	ICEController                    *ice.Controller
	SubdomainResolutionStatsProvider func() *SubdomainResolutionStats
	WireGuardEnabled                 bool
	WireGuardRelayEnabled            bool
	WireGuardInterfacePrefix         string
	WireGuardListenPortBase          int
	WireGuardKeyDir                  string
	WireGuardPublicEndpoint          string
	WireGuardRelayRuntimeReady       bool
	TCPPortMin                       uint16
	TCPPortMax                       uint16
	UDPPortMin                       uint16
	UDPPortMax                       uint16
	HTTPPort                         uint16
	HTTPSPort                        uint16
}

// Create
func NewStatusManager(config *StatusManagerConfig) *StatusManager {
	statusFile := ""
	if config.StatusDir != "" {
		statusFile = filepath.Join(config.StatusDir, "status.json")
	}

	return &StatusManager{
		edgeID:                           config.EdgeID,
		statusFile:                       statusFile,
		startTime:                        time.Now(),
		wireguardRelayRuntimeReady:       config.WireGuardRelayRuntimeReady,
		wireguardEnabled:                 config.WireGuardEnabled,
		wireguardRelayEnabled:            config.WireGuardRelayEnabled,
		wireguardInterfacePrefix:         config.WireGuardInterfacePrefix,
		wireguardListenPortBase:          config.WireGuardListenPortBase,
		wireguardKeyDir:                  config.WireGuardKeyDir,
		wireguardPublicEndpoint:          config.WireGuardPublicEndpoint,
		registry:                         config.Registry,
		p2p:                              config.P2PRuntime,
		iceCtrl:                          config.ICEController,
		subdomainResolutionStatsProvider: config.SubdomainResolutionStatsProvider,
		tcpPortMin:                       config.TCPPortMin,
		tcpPortMax:                       config.TCPPortMax,
		udpPortMin:                       config.UDPPortMin,
		udpPortMax:                       config.UDPPortMax,
		httpPort:                         config.HTTPPort,
		httpsPort:                        config.HTTPSPort,
	}
}

// Set
func (m *StatusManager) SetOnline(online bool) {
	m.mu.Lock()
	m.online = online
	m.mu.Unlock()

	m.NotifyStatusChange()
}

// IsOnline returns current online status.
func (m *StatusManager) IsOnline() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.online
}

// NotifyStatusChange persists current status and notifies subscribers.
func (m *StatusManager) NotifyStatusChange() {
	m.saveStatus()

	m.mu.RLock()
	callback := m.onStatusChange
	m.mu.RUnlock()

	if callback != nil {
		callback(m.GetStatus())
	}
}

// Set
func (m *StatusManager) SetStatusChangeCallback(callback func(*EdgeServiceStatus)) {
	m.mu.Lock()
	m.onStatusChange = callback
	m.mu.Unlock()
}

func (m *StatusManager) SetP2PRuntime(runtime *p2p.Runtime) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.p2p = runtime
}

func (m *StatusManager) SetICEController(controller *ice.Controller) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.iceCtrl = controller
}

func (m *StatusManager) SetSubdomainResolutionStatsProvider(provider func() *SubdomainResolutionStats) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subdomainResolutionStatsProvider = provider
}

func (m *StatusManager) SetWireGuardRelayRuntimeReady(ready bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wireguardRelayRuntimeReady = ready
}

func (m *StatusManager) SetWireGuardConfig(enabled, relayEnabled bool, interfacePrefix string, listenPortBase int, keyDir, publicEndpoint string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wireguardEnabled = enabled
	m.wireguardRelayEnabled = relayEnabled
	m.wireguardInterfacePrefix = interfacePrefix
	m.wireguardListenPortBase = listenPortBase
	m.wireguardKeyDir = keyDir
	m.wireguardPublicEndpoint = publicEndpoint
}

// Get
func (m *StatusManager) GetStatus() *EdgeServiceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()

	status := &EdgeServiceStatus{
		EdgeID:                     m.edgeID,
		Online:                     m.online,
		StartTime:                  m.startTime.Unix(),
		Uptime:                     int64(now.Sub(m.startTime).Seconds()),
		WireGuardEnabled:           m.wireguardEnabled,
		WireGuardRelayEnabled:      m.wireguardRelayEnabled,
		WireGuardInterfacePrefix:   m.wireguardInterfacePrefix,
		WireGuardListenPortBase:    m.wireguardListenPortBase,
		WireGuardKeyDir:            m.wireguardKeyDir,
		WireGuardPublicEndpoint:    m.wireguardPublicEndpoint,
		WireGuardRelayRuntimeReady: m.wireguardRelayRuntimeReady,
		LastUpdated:                now.Unix(),
	}

	if m.registry != nil {
		status.Targets = m.getTargetInfos()
		status.Stats = m.getServiceStats()
	}
	if m.p2p != nil {
		status.P2P = m.getP2PStatuses()
		status.P2PSessions = m.getP2PSessionInfos()
	}
	if m.iceCtrl != nil {
		status.ICE = m.iceCtrl.Snapshot()
		iceStats := m.iceCtrl.Stats()
		status.ICEStats = &iceStats
	}
	if m.subdomainResolutionStatsProvider != nil {
		status.SubdomainResolution = m.subdomainResolutionStatsProvider()
	}

	status.PortUsage = m.getPortUsage()

	return status
}

func (m *StatusManager) getTargetInfos() []TargetInfo {
	if m.registry == nil {
		return nil
	}

	targets := m.registry.GetAllTargets()
	allStats := m.registry.GetAllStats()

	infos := make([]TargetInfo, 0, len(targets))
	for id, t := range targets {
		if t == nil {
			continue
		}
		stats := allStats[id]
		infos = append(infos, TargetInfo{
			ID:                 id,
			Type:               typeToString(t.Type),
			SessionID:          t.SessionID,
			UserID:             t.UserID,
			DeviceID:           t.DeviceID,
			Hostname:           t.Hostname,
			ActorRole:          uint8(t.ActorRole),
			ActorSessionID:     t.ActorSessionID,
			ActorDeviceID:      t.ActorDeviceID,
			ActorHostname:      t.ActorHostname,
			Domain:             t.Domain,
			Subdomain:          t.Subdomain,
			AliasDomain:        t.AliasDomain,
			Port:               t.Port,
			LocalAddr:          t.LocalAddr,
			State:              t.GetState().String(),
			BytesIn:            stats.BytesIn,
			BytesOut:           stats.BytesOut,
			Connections:        stats.Connections,
			ActiveConns:        stats.ActiveConns,
			Requests:           stats.Requests,
			CreatedAt:          t.CreatedAt.Unix(),
			ChannelKey:         t.ChannelKey,
			Protocol:           t.Protocol,
			LinkType:           t.LinkType,
			PreferredLinks:     cloneStringSlice(t.PreferredLinks),
			AllowRelayFallback: t.AllowRelayFallback,
			RequireDirect:      t.RequireDirect,
			RemoteEndpoint:     t.RemoteEndpoint,
			ConnRemoteAddr:     t.ConnRemoteAddr,
		})
	}

	return infos
}

// Get
func (m *StatusManager) getServiceStats() ServiceStats {
	stats := ServiceStats{}

	if m.registry == nil {
		return stats
	}

	allStats := m.registry.GetAllStats()
	stats.ActiveTargets = uint32(len(allStats))

	for _, s := range allStats {
		stats.TotalBytesIn += s.BytesIn
		stats.TotalBytesOut += s.BytesOut
		stats.TotalConnections += s.Connections
		stats.TotalRequests += s.Requests
		stats.TotalErrors += s.Errors
	}

	return stats
}

func (m *StatusManager) getP2PStatuses() map[string]map[string]string {
	if m.p2p == nil {
		return nil
	}
	snapshot := m.p2p.Snapshot()
	if len(snapshot) == 0 {
		return nil
	}

	out := make(map[string]map[string]string, len(snapshot))
	for namespace, sessions := range snapshot {
		if len(sessions) == 0 {
			continue
		}
		ns := make(map[string]string, len(sessions))
		for sessionID, state := range sessions {
			ns[sessionID] = p2pStatusToString(state)
		}
		out[namespace] = ns
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (m *StatusManager) getP2PSessionInfos() map[string]map[string]P2PSessionInfo {
	if m.p2p == nil {
		return nil
	}
	snapshot := m.p2p.SnapshotSessions()
	if len(snapshot) == 0 {
		return nil
	}
	out := make(map[string]map[string]P2PSessionInfo, len(snapshot))
	for namespace, sessions := range snapshot {
		if len(sessions) == 0 {
			continue
		}
		ns := make(map[string]P2PSessionInfo, len(sessions))
		for sessionID, session := range sessions {
			if session == nil {
				continue
			}
			pathState := p2pPathStateToString(session)
			info := P2PSessionInfo{
				Status:             p2pStatusToString(session.Status),
				PathState:          pathState,
				PathType:           p2pPathTypeToString(session.PathType),
				LinkType:           p2pPathTypeToLinkType(session.PathType),
				PreferredLinks:     cloneStringSlice(session.PreferredLinks),
				AllowRelayFallback: session.AllowRelayFallback,
				RequireDirect:      session.RequireDirect,
				LastError:          session.LastError,
				CreatedAt:          session.CreatedAt.Unix(),
				UpdatedAt:          session.UpdatedAt.Unix(),
			}
			if pathState == "fallback" && session.LastError != "" {
				info.FallbackReason = session.LastError
			}
			ns[sessionID] = info
		}
		if len(ns) == 0 {
			continue
		}
		out[namespace] = ns
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func cloneStringSlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}

// Get
func (m *StatusManager) getPortUsage() PortUsageStatus {
	usage := PortUsageStatus{
		TCPTotal:  int(m.tcpPortMax - m.tcpPortMin + 1),
		TCPRange:  formatPortRange(m.tcpPortMin, m.tcpPortMax),
		UDPTotal:  int(m.udpPortMax - m.udpPortMin + 1),
		UDPRange:  formatPortRange(m.udpPortMin, m.udpPortMax),
		HTTPPort:  m.httpPort,
		HTTPSPort: m.httpsPort,
	}

	if m.registry != nil {
		counts := m.registry.CountByType()
		usage.TCPUsed = counts[fbMsg.ChannelTypeTCP]
		usage.UDPUsed = counts[fbMsg.ChannelTypeUDP] + counts[fbMsg.ChannelTypeWIREGUARD]
	}

	return usage
}

// Status
func (m *StatusManager) saveStatus() {
	if m.statusFile == "" {
		return
	}

	status := m.GetStatus()

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		logger.Errorf("marshal status failed: %v", err)
		return
	}

	dir := filepath.Dir(m.statusFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Errorf("create status dir failed: %v", err)
		return
	}

	if err := os.WriteFile(m.statusFile, data, 0644); err != nil {
		logger.Errorf("write status file failed: %v", err)
		return
	}

	logger.Debugf("status saved to %s", m.statusFile)
}

// Status
func (m *StatusManager) LoadStatus() (*EdgeServiceStatus, error) {
	if m.statusFile == "" {
		return nil, nil
	}

	data, err := os.ReadFile(m.statusFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var status EdgeServiceStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// Update
func (m *StatusManager) UpdateStats(sessions, targets uint32, bytesIn, bytesOut uint64) {
	m.mu.Lock()
	m.stats.ActiveSessions = sessions
	m.stats.ActiveTargets = targets
	m.stats.TotalBytesIn = bytesIn
	m.stats.TotalBytesOut = bytesOut
	m.mu.Unlock()
}

// Function

func typeToString(t fbMsg.ChannelType) string {
	switch t {
	case fbMsg.ChannelTypeHTTP:
		return "HTTP"
	case fbMsg.ChannelTypeHTTPS:
		return "HTTPS"
	case fbMsg.ChannelTypeTCP:
		return "TCP"
	case fbMsg.ChannelTypeUDP:
		return "UDP"
	case fbMsg.ChannelTypeWIREGUARD:
		return "WIREGUARD"
	default:
		return "UNKNOWN"
	}
}

func p2pStatusToString(status p2p.SessionStatus) string {
	switch status {
	case p2p.SessionStatusNew:
		return "new"
	case p2p.SessionStatusGathering:
		return "gathering"
	case p2p.SessionStatusPunching:
		return "punching"
	case p2p.SessionStatusEstablishing:
		return "establishing"
	case p2p.SessionStatusConnected:
		return "connected"
	case p2p.SessionStatusFailed:
		return "failed"
	case p2p.SessionStatusClosed:
		return "closed"
	default:
		return "unknown"
	}
}

func p2pPathTypeToString(pathType p2p.PathType) string {
	switch pathType {
	case p2p.PathDirect:
		return "direct"
	case p2p.PathRelay:
		return "relay"
	case p2p.PathLegacy:
		return "legacy"
	default:
		return "unknown"
	}
}

func p2pPathTypeToLinkType(pathType p2p.PathType) string {
	switch pathType {
	case p2p.PathDirect:
		return "p2p"
	case p2p.PathRelay:
		return "relay"
	case p2p.PathLegacy:
		return "wireguard"
	default:
		return ""
	}
}

func p2pPathStateToString(session *p2p.Session) string {
	if session == nil {
		return "unknown"
	}

	switch session.Status {
	case p2p.SessionStatusConnected:
		if session.PathType == p2p.PathRelay {
			return "fallback"
		}
		return "connected"
	case p2p.SessionStatusFailed:
		return "failed"
	case p2p.SessionStatusClosed:
		return "closed"
	case p2p.SessionStatusNew,
		p2p.SessionStatusGathering,
		p2p.SessionStatusPunching,
		p2p.SessionStatusEstablishing:
		if session.PathType == p2p.PathRelay && session.Status == p2p.SessionStatusEstablishing {
			return "fallback"
		}
		return "negotiating"
	default:
		return "unknown"
	}
}

func formatPortRange(min, max uint16) string {
	if min == 0 && max == 0 {
		return ""
	}
	return fmt.Sprintf("%d-%d", min, max)
}
