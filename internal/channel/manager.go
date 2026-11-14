package channel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/ice"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	chtype "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
	logger "icool.io/yat/edge/pkg/log"
)

// =================================================================================
// Types & Interfaces
// =================================================================================

// Re-export from types/.
type Service = chtype.Service
type ChannelCreateAckBuilder = chtype.ChannelCreateAckBuilder
type ClientPusher = chtype.ClientPusher
type DomainProvider = chtype.DomainProvider
type HTTPProxyConfigurator = chtype.HTTPProxyConfigurator

// =================================================================================
// Struct & Constructor
// =================================================================================

type ChannelManager struct {
	config *Config
	tunnel TunnelSender

	// Components
	registry                   *Registry
	tunnelStore                *TunnelDefinitionStore
	httpProxy                  HTTPProxyConfigurator
	wgCoordinator              wireGuardCoordinator
	p2pRuntime                 *p2p.Runtime
	wgP2P                      *p2p.Coordinator
	iceController              *ice.Controller
	wgHandler                  wireGuardHandler
	wgPathService              *wireGuardPathService
	statusMgr                  *StatusManager
	wireguardRelayRuntimeReady bool

	// inviteVerifier is set during setupWireGuard and exposes invite
	// token validation to the Server's cert request flow.
	inviteVerifier interface {
		Peek(tokenStr string) (networkID string, ownerUserID string, err error)
	}

	clientPusher      ClientPusher
	servicesByType    map[fbMsg.ChannelType]Service
	createAckBuilders map[fbMsg.ChannelType]ChannelCreateAckBuilder
	managedServices   []Service
	subdomainStats    tunnelSubdomainResolutionCounters
	started           bool
	mu                sync.RWMutex
}

// Create
func NewChannelManager(cfg *Config, tunnel TunnelSender, clientPusher ClientPusher) (*ChannelManager, error) {
	m := &ChannelManager{
		config:            cfg,
		tunnel:            tunnel,
		clientPusher:      clientPusher,
		p2pRuntime:        p2p.NewRuntime(),
		servicesByType:    make(map[fbMsg.ChannelType]Service),
		createAckBuilders: make(map[fbMsg.ChannelType]ChannelCreateAckBuilder),
		managedServices:   make([]Service, 0),
	}

	if err := m.ApplyConfig(cfg); err != nil {
		return nil, err
	}

	return m, nil
}

// =================================================================================
// Lifecycle Management
// =================================================================================

// Update
func (m *ChannelManager) ApplyConfig(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg == nil || cfg.DomainProvider == nil {
		return fmt.Errorf("channel manager: config and DomainProvider are required")
	}
	if err := m.checkWireGuardPathConfig(cfg); err != nil {
		return err
	}

	m.config = cfg
	m.managedServices = make([]Service, 0)
	m.servicesByType = make(map[fbMsg.ChannelType]Service)
	m.createAckBuilders = make(map[fbMsg.ChannelType]ChannelCreateAckBuilder)

	if m.p2pRuntime == nil {
		m.p2pRuntime = p2p.NewRuntime()
	} else if m.wgPathService == nil {
		m.p2pRuntime.Reset()
	}
	m.p2pRuntime.Ensure(p2p.NamespaceWireGuard)
	m.managedServices = append(m.managedServices, m.p2pRuntime)

	// Deterministic contract: DomainProvider is mandatory. Channel domains must
	// always be subdomain + assignedDomain; without a domain provider we cannot
	// produce a valid address and must refuse to start.
	if cfg.DomainProvider == nil {
		return fmt.Errorf("channel manager: DomainProvider is required")
	}

	resourceCfg := &ResourceConfig{
		TCPPortMin: uint16(cfg.TCPPortMin),
		TCPPortMax: uint16(cfg.TCPPortMax),
		UDPPortMin: uint16(cfg.UDPPortMin),
		UDPPortMax: uint16(cfg.UDPPortMax),
	}

	registryCfg := &RegistryConfig{
		ResourceConfig:       resourceCfg,
		DomainProvider:       cfg.DomainProvider,
		HTTPPort:             uint16(cfg.HTTPPort),
		HTTPSPort:            uint16(cfg.HTTPSPort),
		MaxTargetsPerSession: cfg.MaxTargetsPerSession,
		MaxTargets:           cfg.MaxTargets,
	}

	if m.registry == nil {
		m.registry = NewRegistry(registryCfg)
	}
	if err := m.ensureStoresLocked(cfg); err != nil {
		logger.Warnf("failed to ensure channel stores: %v", err)
	}
	m.registry.ClearRuntimes()
	m.httpProxy = nil
	if m.wgPathService == nil {
		m.wgHandler = nil
		m.wgP2P = nil
	}

	if err := m.activateProtocols(cfg); err != nil {
		return err
	}

	if m.statusMgr == nil {
		m.statusMgr = NewStatusManager(&StatusManagerConfig{
			EdgeID:                           cfg.EdgeID,
			StatusDir:                        cfg.StatusDir,
			Registry:                         m.registry,
			P2PRuntime:                       m.p2pRuntime,
			ICEController:                    m.iceController,
			SubdomainResolutionStatsProvider: m.GetSubdomainResolutionStats,
			WireGuardEnabled:                 cfg.WireGuardEnabled,
			WireGuardRelayEnabled:            cfg.WireGuardRelayEnabled,
			WireGuardInterfacePrefix:         cfg.WireGuardInterfacePrefix,
			WireGuardListenPortBase:          cfg.WireGuardListenPortBase,
			WireGuardKeyDir:                  cfg.WireGuardKeyDir,
			WireGuardPublicEndpoint:          cfg.WireGuardPublicEndpoint,
			WireGuardRelayRuntimeReady:       m.wireguardRelayRuntimeReady,
			TCPPortMin:                       uint16(cfg.TCPPortMin),
			TCPPortMax:                       uint16(cfg.TCPPortMax),
			UDPPortMin:                       uint16(cfg.UDPPortMin),
			UDPPortMax:                       uint16(cfg.UDPPortMax),
			HTTPPort:                         uint16(cfg.HTTPPort),
			HTTPSPort:                        uint16(cfg.HTTPSPort),
		})
	} else {
		m.statusMgr.SetP2PRuntime(m.p2pRuntime)
		m.statusMgr.SetICEController(m.iceController)
		m.statusMgr.SetSubdomainResolutionStatsProvider(m.GetSubdomainResolutionStats)
	}
	m.statusMgr.SetWireGuardConfig(
		cfg.WireGuardEnabled,
		cfg.WireGuardRelayEnabled,
		cfg.WireGuardInterfacePrefix,
		cfg.WireGuardListenPortBase,
		cfg.WireGuardKeyDir,
		cfg.WireGuardPublicEndpoint,
	)
	m.statusMgr.SetWireGuardRelayRuntimeReady(m.wireguardRelayRuntimeReady)

	return nil
}

func (m *ChannelManager) ensureStoresLocked(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("channel manager: config is required")
	}
	if m.registry == nil {
		return fmt.Errorf("channel manager: registry is not initialized")
	}

	statusDir := strings.TrimSpace(cfg.StatusDir)
	if statusDir != "" {
		if err := os.MkdirAll(statusDir, 0755); err != nil {
			return fmt.Errorf("ensure status dir %s: %w", statusDir, err)
		}
	}

	if !m.registry.HasStore() {
		channelDBPath := filepath.Join(cfg.StatusDir, "channels.db")
		channelStore, err := NewChannelStore(channelDBPath)
		if err != nil {
			logger.Warnf("failed to init channel store (%s): %v", channelDBPath, err)
		} else {
			m.registry.SetStore(channelStore)
			logger.Infof("channel store initialized: %s", channelDBPath)
		}
	}

	if m.tunnelStore == nil {
		tunnelDBPath := filepath.Join(cfg.StatusDir, "tunnels.db")
		tunnelStore, err := NewTunnelDefinitionStore(tunnelDBPath)
		if err != nil {
			logger.Warnf("failed to init tunnel definition store (%s): %v", tunnelDBPath, err)
		} else {
			m.tunnelStore = tunnelStore
			logger.Infof("tunnel definition store initialized: %s", tunnelDBPath)
		}
	}

	return nil
}

func (m *ChannelManager) activateProtocols(cfg *Config) error {
	if cfg.HTTPProxyEnabled {
		if err := m.setupHTTP(cfg); err != nil {
			return fmt.Errorf("setup http: %w", err)
		}
	}
	if cfg.TCPProxyEnabled {
		if err := m.setupTCP(cfg); err != nil {
			return fmt.Errorf("setup tcp: %w", err)
		}
	}
	if cfg.UDPProxyEnabled {
		if err := m.setupUDP(cfg); err != nil {
			return fmt.Errorf("setup udp: %w", err)
		}
	}
	if cfg.WireGuardEnabled {
		if err := m.setupWireGuard(cfg); err != nil {
			return fmt.Errorf("setup wireguard: %w", err)
		}
	}
	if cfg.ICEConfig != nil {
		if err := m.setupICE(cfg); err != nil {
			return fmt.Errorf("setup ice: %w", err)
		}
	}
	return nil
}

// Start
func (m *ChannelManager) Start() error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	services := append([]Service(nil), m.managedServices...)
	m.mu.Unlock()

	logger.Info("starting channel services...")
	rollback := func(cause error, count int) error {
		failures := []error{cause}
		for i := count - 1; i >= 0; i-- {
			if err := services[i].Stop(); err != nil {
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}
	for i, s := range services {
		if err := s.Start(); err != nil {
			return rollback(fmt.Errorf("start service failed: %w", err), i+1)
		}
	}

	m.mu.RLock()
	iceCtrl := m.iceController
	m.mu.RUnlock()
	if iceCtrl != nil {
		if err := iceCtrl.Start(); err != nil {
			iceCtrl.Stop()
			return rollback(fmt.Errorf("start ice controller failed: %w", err), len(services))
		}
	}

	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	m.NotifyStatusChange()
	return nil
}

// Stop
func (m *ChannelManager) Stop() error {
	m.mu.Lock()
	services := append([]Service(nil), m.managedServices...)
	m.started = false
	m.mu.Unlock()

	logger.Info("stopping channel services...")
	m.mu.RLock()
	iceCtrl := m.iceController
	m.mu.RUnlock()
	if iceCtrl != nil {
		iceCtrl.Stop()
	}
	var failures []error
	for i := len(services) - 1; i >= 0; i-- {
		if err := services[i].Stop(); err != nil {
			logger.Warnf("stop service failed: %v", err)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// SwitchAssignedDomain 热切换 edge assignedDomain，不中断已建立 channel。
func (m *ChannelManager) SwitchAssignedDomain(newAssignedDomain string) error {
	newAssignedDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(newAssignedDomain)), ".")

	m.mu.Lock()
	dp := m.config.DomainProvider
	var oldAssignedDomain string
	if dp != nil {
		oldAssignedDomain = dp.GetAssignedDomain()
	}
	registry := m.registry
	statusMgr := m.statusMgr
	m.mu.Unlock()

	if registry == nil {
		return nil
	}

	updated, err := registry.SwitchAssignedDomain(newAssignedDomain)
	if err != nil {
		return err
	}

	if statusMgr != nil {
		statusMgr.NotifyStatusChange()
	}
	logger.Infof("assigned domain switched: %s -> %s, updated_http_channels=%d", oldAssignedDomain, newAssignedDomain, updated)
	return nil
}

// AddService registers an externally managed service for lifecycle control.
func (m *ChannelManager) AddService(s Service) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s != nil {
		m.managedServices = append(m.managedServices, s)
	}
}

// =================================================================================
// Service Management (Ensure & Check)
// =================================================================================

// capabilityChannelTypes maps capability strings to the channel types they require.
func capabilityChannelTypes(capability string) []fbMsg.ChannelType {
	switch capability {
	case "http":
		return []fbMsg.ChannelType{fbMsg.ChannelTypeHTTP}
	case "https":
		return []fbMsg.ChannelType{fbMsg.ChannelTypeHTTP, fbMsg.ChannelTypeHTTPS}
	case "tcp":
		return []fbMsg.ChannelType{fbMsg.ChannelTypeTCP}
	case "udp":
		return []fbMsg.ChannelType{fbMsg.ChannelTypeUDP}
	case "wireguard", "wg":
		return []fbMsg.ChannelType{fbMsg.ChannelTypeWIREGUARD}
	default:
		return nil
	}
}

// disabledMessage returns the error message for a disabled channel type.
func disabledMessage(typ fbMsg.ChannelType) string {
	switch typ {
	case fbMsg.ChannelTypeHTTP:
		return "http proxy disabled"
	case fbMsg.ChannelTypeHTTPS:
		return "https proxy disabled"
	case fbMsg.ChannelTypeTCP:
		return "tcp proxy disabled"
	case fbMsg.ChannelTypeUDP:
		return "udp proxy disabled"
	case fbMsg.ChannelTypeWIREGUARD:
		return "wireguard disabled"
	default:
		return ""
	}
}

func (m *ChannelManager) EnsureForCapabilities(caps []string) error {
	var firstErr error
	for _, c := range caps {
		capability := strings.ToLower(strings.TrimSpace(c))
		if capability == "" {
			continue
		}
		for _, typ := range capabilityChannelTypes(capability) {
			if err := m.EnsureService(typ); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (m *ChannelManager) EnsureForChannelType(typ fbMsg.ChannelType) error {
	return m.EnsureService(typ)
}

func (m *ChannelManager) SupportsChannelType(typ fbMsg.ChannelType) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.servicesByType[typ]
	return ok
}

func (m *ChannelManager) EnsureService(typ fbMsg.ChannelType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	service, ok := m.servicesByType[typ]
	if !ok || service == nil {
		if msg := disabledMessage(typ); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return nil
	}

	if !m.isManagedService(service) {
		if err := service.Start(); err != nil {
			return err
		}
		m.managedServices = append(m.managedServices, service)
	}
	return nil
}

func (m *ChannelManager) isManagedService(s Service) bool {
	for _, svc := range m.managedServices {
		if svc == s {
			return true
		}
	}
	return false
}

// =================================================================================
// Component Access (Getters)
// =================================================================================

func (m *ChannelManager) GetHTTPProxyConfigurator() HTTPProxyConfigurator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.httpProxy
}

func (m *ChannelManager) Create(req *CreateRequest) (*CreateResult, error) {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return nil, fmt.Errorf("registry not initialized")
	}
	result, err := registry.Create(req)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (m *ChannelManager) Close(channelID string) error {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return fmt.Errorf("registry not initialized")
	}
	if err := registry.Close(channelID); err != nil {
		return err
	}
	return nil
}

func (m *ChannelManager) Get(channelID string) *Channel {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return nil
	}
	return registry.Get(channelID)
}

func (m *ChannelManager) CloseBySession(sessionID string) {
	m.mu.RLock()
	registry := m.registry
	iceCtrl := m.iceController
	m.mu.RUnlock()

	var targets []*Channel
	if registry != nil {
		targets = registry.GetBySession(sessionID)
	}

	if iceCtrl != nil {
		clientIDs := make(map[string]struct{})
		for _, target := range targets {
			if clientID := targetClientID(target); clientID != "" {
				clientIDs[clientID] = struct{}{}
			}
		}
		for clientID := range clientIDs {
			iceCtrl.OnClientSessionDisconnected(clientID)
		}
		// Backward compatibility: older ICE sessions may still be keyed by
		// transport session ID.
		iceCtrl.OnClientSessionDisconnected(sessionID)
	}

	if registry == nil {
		return
	}
	for _, target := range targets {
		if target == nil || strings.TrimSpace(target.ID) == "" {
			continue
		}
		if err := m.Close(target.ID); err != nil {
			logger.Warnf("close channel by session failed, session=%s, channel=%s, err=%v", sessionID, target.ID, err)
		}
	}
}

func (m *ChannelManager) TouchSessionChannels(sessionID string) {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return
	}
	registry.TouchSessionChannels(sessionID)
}

// HandleSessionDisconnect updates the legacy observation ledger. Product
// presence is read from the current session index, so an old disconnect cannot
// make a replacement control session appear offline or revoke membership.
func (m *ChannelManager) HandleSessionDisconnect(deviceID string) {
	m.mu.RLock()
	coordinator := m.wgCoordinator
	handler := m.wgHandler
	m.mu.RUnlock()
	if coordinator == nil {
		return
	}
	if err := coordinator.HandleDeviceDisconnect(deviceID); err != nil {
		logger.Debugf("handle session disconnect: device=%s err=%v", deviceID, err)
	}
	if handler == nil {
		return
	}
	// A temporary WG leave may have been pushed while this mTLS session was
	// still current, so the product projection correctly showed it online.
	// Publish a fresh snapshot after removing the session to expose offline
	// presence to the remaining peers without changing membership.
	for _, network := range coordinator.ListNetworks() {
		if network == nil {
			continue
		}
		for _, member := range coordinator.ListNetworkMembers(network.ID) {
			if member == nil || member.ClientID != deviceID {
				continue
			}
			if err := handler.PushNetworkEvent(network.ID, fbMsg.WGNetworkEventActionUPSERT); err != nil {
				logger.Debugf("push member disconnect presence failed: device=%s network=%s err=%v", deviceID, network.ID, err)
			}
			break
		}
	}
}

// aliasDomainPolicy returns the normalized alias-domain policy from the current config.
// Falls back to "optional" when config is nil or the value is unknown.
func (m *ChannelManager) aliasDomainPolicy() string {
	m.mu.RLock()
	cfg := m.config
	m.mu.RUnlock()
	if cfg == nil {
		return aliasDomainPolicyOptional
	}
	return normalizeAliasDomainPolicy(cfg.AliasDomainPolicy)
}

// Alias domain policy constants (keep in sync with pkg/config).
const (
	aliasDomainPolicyDisabled = "disabled"
	aliasDomainPolicyOptional = "optional"
	aliasDomainPolicyRequired = "required"
)

func normalizeAliasDomainPolicy(policy string) string {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case aliasDomainPolicyDisabled:
		return aliasDomainPolicyDisabled
	case aliasDomainPolicyRequired:
		return aliasDomainPolicyRequired
	case aliasDomainPolicyOptional, "":
		return aliasDomainPolicyOptional
	default:
		return aliasDomainPolicyOptional
	}
}

// validateAliasDomainPolicy enforces alias-domain presence/absence rules according to policy.
// Only HTTP / HTTPS channel types participate; other channel types always pass.
// Returns (errorMessage, ok). When ok is false, errorMessage explains the rejection reason.
func validateAliasDomainPolicy(policy string, channelType fbMsg.ChannelType, aliasDomain string) (string, bool) {
	if channelType != fbMsg.ChannelTypeHTTP && channelType != fbMsg.ChannelTypeHTTPS {
		return "", true
	}
	alias := strings.TrimSpace(aliasDomain)
	switch policy {
	case aliasDomainPolicyDisabled:
		if alias != "" {
			return "alias_domain is not allowed on this edge (policy=disabled)", false
		}
	case aliasDomainPolicyRequired:
		if alias == "" {
			return "alias_domain is required on this edge (policy=required)", false
		}
	}
	return "", true
}

func (m *ChannelManager) Count() int {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return 0
	}
	return registry.Count()
}

func (m *ChannelManager) GetAllStats() map[string]ChannelStats {
	m.mu.RLock()
	registry := m.registry
	m.mu.RUnlock()
	if registry == nil {
		return map[string]ChannelStats{}
	}
	return registry.GetAllStats()
}

func (m *ChannelManager) GetStatus() *EdgeServiceStatus {
	m.mu.RLock()
	statusMgr := m.statusMgr
	m.mu.RUnlock()
	if statusMgr == nil {
		return nil
	}
	return statusMgr.GetStatus()
}

func (m *ChannelManager) GetP2PSnapshot() map[string]map[string]p2p.SessionStatus {
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.Snapshot()
}

func (m *ChannelManager) GetP2PNamespaceSnapshot(namespace string) map[string]p2p.SessionStatus {
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.SnapshotNamespace(namespace)
}

func (m *ChannelManager) GetP2PSessionSnapshots() map[string]map[string]*p2p.Session {
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.SnapshotSessions()
}

func (m *ChannelManager) GetP2PNamespaceSessionSnapshot(namespace string) map[string]*p2p.Session {
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil
	}
	return runtime.SnapshotNamespaceSessions(namespace)
}

func (m *ChannelManager) GetP2PNamespaceSession(namespace, sessionID string) (*p2p.Session, bool) {
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return nil, false
	}
	return runtime.GetNamespaceSession(namespace, sessionID)
}

func (m *ChannelManager) GetTunnelStore() *TunnelDefinitionStore {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tunnelStore
}

// GetWGRelayManager returns the WireGuard relay manager, or nil if WireGuard
// is not configured or the coordinator does not expose a relay manager.
func (m *ChannelManager) GetWGRelayManager() relay.RelayManager {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.wgCoordinator == nil {
		return nil
	}
	return m.wgCoordinator.GetRelayManager()
}

// GetWGNetworkMembers returns the in-memory member list for a network from
// the running WireGuard coordinator, with client presence projected from the
// current authenticated control session rather than relay handshake freshness.
func (m *ChannelManager) GetWGNetworkMembers(networkID string) []*wireguard.NetworkMember {
	m.mu.RLock()
	coordinator := m.wgCoordinator
	controls, _ := m.clientPusher.(chtype.CurrentClientSessionReader)
	m.mu.RUnlock()
	if coordinator == nil {
		return nil
	}
	overview, err := coordinator.GetNetworkOverview(networkID)
	if err != nil || overview == nil {
		return nil
	}
	return wireguard.MembersWithControlPresence(overview.Members, controls)
}

func (m *ChannelManager) SetStatusChangeCallback(callback func(*EdgeServiceStatus)) {
	m.mu.RLock()
	statusMgr := m.statusMgr
	m.mu.RUnlock()
	if statusMgr == nil {
		return
	}
	statusMgr.SetStatusChangeCallback(callback)
}

func (m *ChannelManager) NotifyStatusChange() {
	m.mu.RLock()
	statusMgr := m.statusMgr
	m.mu.RUnlock()
	if statusMgr == nil {
		return
	}
	statusMgr.NotifyStatusChange()
}

func (m *ChannelManager) SetOnline(online bool) {
	m.mu.RLock()
	statusMgr := m.statusMgr
	m.mu.RUnlock()
	if statusMgr == nil {
		return
	}
	statusMgr.SetOnline(online)
}

// IsOnline returns current online status.
func (m *ChannelManager) IsOnline() bool {
	m.mu.RLock()
	statusMgr := m.statusMgr
	m.mu.RUnlock()
	if statusMgr == nil {
		return false
	}
	return statusMgr.IsOnline()
}

// =================================================================================
// Message Dispatcher
// =================================================================================

func (m *ChannelManager) HandleMessage(ctx *HandlerContext, msg *fbMsg.Message) (bool, error) {
	msgType := msg.Header(nil).Type()

	switch msgType {

	case fbMsg.MessageTypeTUNNEL_START_REQUEST:
		return true, m.HandleTunnelStart(ctx, msg)

	case fbMsg.MessageTypeTUNNEL_STOP_REQUEST:
		return true, m.HandleTunnelStop(ctx, msg)

	case fbMsg.MessageTypeTUNNEL_JOIN_REQUEST:
		return true, m.HandleTunnelJoin(ctx, msg)

	case fbMsg.MessageTypeTUNNEL_LEAVE_REQUEST:
		return true, m.HandleTunnelLeave(ctx, msg)

	case fbMsg.MessageTypeDATA_PACKET:
		return true, m.HandleDataPacket(ctx, msg)

	case fbMsg.MessageTypeWG_CREATE_NETWORK,
		fbMsg.MessageTypeWG_JOIN_NETWORK,
		fbMsg.MessageTypeWG_LEAVE_NETWORK,
		fbMsg.MessageTypeWG_LIST_MEMBERS,
		fbMsg.MessageTypeWG_LIST_NETWORKS,
		fbMsg.MessageTypeWG_GET_NETWORK,
		fbMsg.MessageTypeWG_DELETE_NETWORK,
		fbMsg.MessageTypeWG_NETWORK_RUNTIME_REQUEST,
		fbMsg.MessageTypeWG_LIST_AVAILABLE_DEVICES,
		fbMsg.MessageTypeWG_CREATE_SESSION,
		fbMsg.MessageTypeWG_GATHER_INFO,
		fbMsg.MessageTypeWG_PUNCH_INFO,
		fbMsg.MessageTypeWG_UPDATE_NETWORK_CIDR,
		fbMsg.MessageTypeWG_UPDATE_MEMBER,
		fbMsg.MessageTypeWG_UPDATE_NETWORK_RELAY_MODE,
		fbMsg.MessageTypeWG_PATH_RUNTIME,
		fbMsg.MessageTypeWG_PATH_REPORT,
		fbMsg.MessageTypeWG_PATH_REQUEST,
		fbMsg.MessageTypeWG_CREATE_INVITE:
		return true, m.handleWireGuardMessage(ctx, msg)

	case fbMsg.MessageTypeICE_PUNCH_RESULT,
		fbMsg.MessageTypeICE_QUIC_CONNECTED:
		return true, m.handleICEMessage(ctx, msg)

	default:
		return false, nil
	}
}

// =================================================================================
// Message Handlers (Business Logic)
// =================================================================================

func normalizeActorRole(raw uint8) fbMsg.TunnelActorRole {
	switch fbMsg.TunnelActorRole(raw) {
	case fbMsg.TunnelActorRolePUBLISHER, fbMsg.TunnelActorRoleCONSUMER, fbMsg.TunnelActorRoleCONTROLLER:
		return fbMsg.TunnelActorRole(raw)
	default:
		return fbMsg.TunnelActorRolePUBLISHER
	}
}

func (m *ChannelManager) HandleDataPacket(ctx *HandlerContext, msg *fbMsg.Message) error {
	req := new(fbMsg.DataPacket)
	table := new(flatbuffers.Table)
	msg.Body(table)
	req.Init(table.Bytes, table.Pos)

	channelID := string(req.ChannelId())
	connectionID := string(req.ConnectionId())
	seq := req.Seq()
	flags := req.Flags()

	data := req.DataBytes()
	if err := m.registry.HandleDataPacket(channelID, connectionID, seq, data, flags); err != nil {
		return nil
	}

	return ctx.Protocol.SendDataAck(ctx.Conn, channelID, connectionID, seq, ctx.SessionID)
}

// connRemoteAddrFromCtx 从 HandlerContext 中的 session.Conn 取客户端到 edge 的真实 host:port。
func connRemoteAddrFromCtx(ctx *HandlerContext) string {
	if ctx == nil || ctx.Conn == nil {
		return ""
	}
	addr := ctx.Conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// GetInviteVerifier returns the invite token verifier, or nil if WireGuard
// is not set up yet.
func (m *ChannelManager) GetInviteVerifier() interface {
	Peek(tokenStr string) (networkID string, ownerUserID string, err error)
} {
	return m.inviteVerifier
}
