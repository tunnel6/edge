package channel

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"runtime"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/httpproxy"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	"icool.io/yat/edge/internal/channel/tcpproxy"
	chtype "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/udpproxy"
	"icool.io/yat/edge/internal/channel/wireguard"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
	logger "icool.io/yat/edge/pkg/log"
)

// wgOnlineDeviceListerAdapter 把 channel/types.OnlineDevice 适配为 wireguard.OnlineDeviceInfo，
// 避免 wireguard 包反向依赖 channel/types。
type wgOnlineDeviceListerAdapter struct {
	lister chtype.OnlineDeviceLister
}

func (a *wgOnlineDeviceListerAdapter) ListOnlineDevicesByUser(userID string) []wireguard.OnlineDeviceInfo {
	src := a.lister.ListOnlineDevicesByUser(userID)
	if len(src) == 0 {
		return nil
	}
	out := make([]wireguard.OnlineDeviceInfo, 0, len(src))
	for _, d := range src {
		out = append(out, wireguard.OnlineDeviceInfo{
			ClientID:   d.ClientID,
			DeviceID:   d.DeviceID,
			Hostname:   d.Hostname,
			LastActive: d.LastActive,
		})
	}
	return out
}

// inviteVerifierAdapter adapts wireguard.InviteStore to the
// server.InviteTokenVerifier interface, avoiding a circular import.
type inviteVerifierAdapter struct {
	store *wireguard.InviteStore
}

func (a *inviteVerifierAdapter) Peek(tokenStr string) (networkID string, ownerUserID string, err error) {
	tok, err := a.store.Peek(tokenStr)
	if err != nil {
		return "", "", err
	}
	return tok.NetworkID, tok.OwnerUserID, nil
}

func (m *ChannelManager) setupHTTP(cfg *Config) error {
	httpAddr := cfg.HTTPProxyAddr
	if httpAddr == "" {
		httpAddr = fmt.Sprintf(":%d", cfg.HTTPPort)
	}
	proxy := httpproxy.New(&httpproxy.Config{
		Addr:           httpAddr,
		HTTPPort:       uint16(cfg.HTTPPort),
		HTTPSPort:      uint16(cfg.HTTPSPort),
		DomainProvider: cfg.DomainProvider,
		Timeout:        cfg.HTTPProxyTimeout,
		HTTPBufferSize: cfg.HTTPBufferSize,
		HTTPBufferLock: cfg.HTTPBufferLock,
	})
	proxy.SetTunnel(m.tunnel)
	m.httpProxy = proxy

	m.registry.SetRuntime(fbMsg.ChannelTypeHTTP, proxy)
	m.servicesByType[fbMsg.ChannelTypeHTTP] = proxy
	m.createAckBuilders[fbMsg.ChannelTypeHTTP] = proxy
	if cfg.HTTPSPort > 0 {
		m.registry.SetRuntime(fbMsg.ChannelTypeHTTPS, proxy)
		m.servicesByType[fbMsg.ChannelTypeHTTPS] = proxy
		m.createAckBuilders[fbMsg.ChannelTypeHTTPS] = proxy
	}

	if cfg.EagerStartHTTPProxy {
		m.managedServices = append(m.managedServices, proxy)
	}
	return nil
}

func (m *ChannelManager) setupTCP(_ *Config) error {
	proxy := tcpproxy.New(m.tunnel)
	m.registry.SetRuntime(fbMsg.ChannelTypeTCP, proxy)
	m.servicesByType[fbMsg.ChannelTypeTCP] = proxy
	return nil
}

func (m *ChannelManager) setupUDP(_ *Config) error {
	proxy := udpproxy.New(m.tunnel)
	m.registry.SetRuntime(fbMsg.ChannelTypeUDP, proxy)
	m.servicesByType[fbMsg.ChannelTypeUDP] = proxy
	return nil
}

type wireGuardHandler interface {
	HandleCreateNetwork(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleJoinNetwork(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleLeaveNetwork(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleListMembers(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleListNetworks(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleGetNetwork(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleDeleteNetwork(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleNetworkRuntimeRequest(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleListAvailableDevices(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleGatherInfo(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleUpdateNetworkCIDR(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleUpdateMember(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleUpdateRelayMode(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	HandleCreateInvite(sess wireguard.HandlerSession, msg *fbMsg.Message) error
	PushNetworkEvent(networkID string, action fbMsg.WGNetworkEventAction) error
	PushGatherInfo(sessionID, clientID string) error
}

type wireGuardCoordinator interface {
	Service
	wireguard.HandlerCoordinator
	GetRelayManager() relay.RelayManager
	SetRelayEndpointChangeCallback(fn func(networkID, publicKey, endpoint string))
	SetHeartbeatTimeoutCallback(fn func(networkID, publicKey string))
	SetLANGatherPusher(pusher func(networkID, clientID string) error)
	ApplyObservedEndpoint(networkID, publicKey, endpoint string) (bool, error)
	SetMemberOnlineByPublicKey(networkID, publicKey string) (error, bool)
	HandleHeartbeatTimeout(networkID, publicKey string) error
	HandleDeviceDisconnect(deviceID string) error
	HandleDeviceConnect(deviceID string) int
}

func (m *ChannelManager) setupWireGuard(cfg *Config) error {
	if m.wgCoordinator == nil {
		wgDBPath := filepath.Join(cfg.StatusDir, "wireguard.db")
		wgStore, err := wireguard.NewSQLiteStorage(wgDBPath)
		if err != nil {
			logger.Warnf("failed to init WireGuard sqlite storage: %v", err)
		}

		wgCoordinator := wireguard.NewMeshCoordinator()
		if wgStore != nil {
			wgCoordinator.SetStorage(wgStore)
			if err := wireguard.RecoverFromStorage(context.Background(), wgCoordinator, wgStore); err != nil {
				logger.Warnf("failed to recover WireGuard state from storage: %v", err)
			}
		}

		// Initialize the WG observation runtime on Linux regardless of the
		// business relay flag. Disabled networks still need an observation-only
		// interface so clients can bootstrap and publish their UDP endpoint.
		if runtime.GOOS == "linux" {
			// wireguardRelayRuntimeReady reports business relay capability; the
			// observer itself may be ready even when this flag is false.
			m.wireguardRelayRuntimeReady = false
			relayCfg := &relay.Config{
				InterfacePrefix:   cfg.WireGuardInterfacePrefix,
				ListenPortBase:    cfg.WireGuardListenPortBase,
				KeyDir:            cfg.WireGuardKeyDir,
				PublicEndpoint:    cfg.WireGuardPublicEndpoint,
				ObserveInterval:   5,
				ForwarderStrategy: relay.ForwarderStrategy(cfg.WireGuardForwarderStrategy),
				DefaultPeerRate:   cfg.WireGuardDefaultPeerRate,
				DefaultPeerCeil:   cfg.WireGuardDefaultPeerCeil,
			}
			if relayCfg.InterfacePrefix == "" {
				relayCfg.InterfacePrefix = "wg-yat0"
			}
			if relayCfg.ListenPortBase == 0 {
				relayCfg.ListenPortBase = 58021
			}
			if relayCfg.KeyDir == "" {
				relayCfg.KeyDir = filepath.Join(cfg.StatusDir, "wireguard", "keys")
			}
			if relayCfg.PublicEndpoint == "" {
				logger.Warn("WireGuard public address is empty; clients need the Edge public directory address to bootstrap UDP observation")
			}

			rm, err := relay.NewLinuxRelayManager(relayCfg)
			if err != nil {
				logger.Warnf("failed to create WireGuard observation runtime: %v", err)
			} else {
				// Inject rate limit persistence store.
				if wgStore != nil {
					rm.SetPeerRateLimitStore(wgStore)
				}
				wgCoordinator.SetRelayForwardingEnabled(cfg.WireGuardRelayEnabled)
				wgCoordinator.SetRelayManager(rm)
				m.wireguardRelayRuntimeReady = cfg.WireGuardRelayEnabled
				if cfg.WireGuardRelayEnabled {
					logger.Info("WireGuard observation and business relay runtime initialized")
				} else {
					logger.Info("WireGuard observation runtime initialized (business relay disabled)")
				}
			}
		}

		m.wgCoordinator = wgCoordinator
	}
	// Configuration reloads may change business relay availability while the
	// observer coordinator and interfaces stay alive. Keep the two capabilities
	// independent: observer remains active, while this flag controls whether
	// per-peer relay forwarding may be created for relay-enabled networks.
	if runtime, ok := m.wgCoordinator.(interface {
		SetRelayForwardingEnabled(bool) error
		RelayForwardingReady() bool
	}); ok {
		if err := runtime.SetRelayForwardingEnabled(cfg.WireGuardRelayEnabled); err != nil {
			m.wireguardRelayRuntimeReady = false
			return fmt.Errorf("reconcile WireGuard forwarding: %w", err)
		}
		m.wireguardRelayRuntimeReady = runtime.RelayForwardingReady()
	}

	m.servicesByType[fbMsg.ChannelTypeWIREGUARD] = m.wgCoordinator
	m.managedServices = append(m.managedServices, m.wgCoordinator)

	logger.Infof("setupWireGuard: wgHandler_is_nil=%v clientPusher_is_nil=%v",
		m.wgHandler == nil, m.clientPusher == nil)

	if m.wgHandler == nil && m.clientPusher != nil {
		logger.Info("setupWireGuard: entering handler creation block")
		if m.p2pRuntime == nil {
			m.p2pRuntime = p2p.NewRuntime()
		}
		m.wgP2P = m.p2pRuntime.Ensure(p2p.NamespaceWireGuard)
		logger.Infof("setupWireGuard: p2p ready, wgP2P=%v", m.wgP2P != nil)

		// 若底层 clientPusher 同时实现在线设备枚举（server.SessionManager），桥接给 WG handler。
		var deviceLister wireguard.OnlineDeviceLister
		if lister, ok := m.clientPusher.(chtype.OnlineDeviceLister); ok {
			deviceLister = &wgOnlineDeviceListerAdapter{lister: lister}
		}

		// Reconnect leaves the relay observation ledger unchanged. Product
		// presence is projected from current authenticated control sessions.
		if notifier, ok := m.clientPusher.(chtype.ClientConnectNotifier); ok {
			notifier.SetOnClientConnect(func(userID, deviceID string) {
				m.wgCoordinator.HandleDeviceConnect(deviceID)
			})
		}

		handler := wireguard.NewWireGuardHandler(m.wgCoordinator, m.clientPusher, m.wgP2P, cfg.EdgeID, deviceLister)
		m.wgHandler = handler
		// Wire the invite store into the ChannelManager so the Server's
		// cert request flow can validate invite tokens for scoped certs.
		m.inviteVerifier = &inviteVerifierAdapter{store: handler.GetInviteStore()}
		logger.Info("setupWireGuard: handler created, wiring callbacks")
		// P2P adapter wiring removed (S5-B2): old session mechanism was dead code.
		// Wire the LAN gather pusher so same-NAT detection can request
		// LAN endpoint reports from clients. The session ID is encoded as
		// "lan:<networkID>" so the handler can bypass session lookup.
		m.wgCoordinator.SetLANGatherPusher(func(networkID, clientID string) error {
			return handler.PushGatherInfo("lan:"+networkID, clientID)
		})
		// Session callback wiring removed (S5-B1): EnsureDirectSessions and
		// RecoverFailedSessionsForObserver were dead code — clients only accept
		// "lan:" prefixed gather, "auto-" sessions were always dropped.
		// PeerSession state machine and P2P adapter removal continues in S5-B2.

		// WireGuard endpoint observation is also required by disabled networks:
		// those networks do not publish a business relay member, but their
		// observation-only interface still reports the canonical direct endpoint.
		// Do not gate this callback on the config flag; a coordinator can retain
		// an already-created relay/observation runtime across config reloads.
		coordinator := m.wgCoordinator
		coordinator.SetRelayEndpointChangeCallback(func(networkID, publicKey, endpoint string) {
			// Update WG observation liveness independently of control presence.
			if err, _ := coordinator.SetMemberOnlineByPublicKey(networkID, publicKey); err != nil {
				logger.Debugf("set member online via observation: network=%s public_key=%s err=%v", networkID, publicKey, err)
			}
			changed, err := coordinator.ApplyObservedEndpoint(networkID, publicKey, endpoint)
			if err != nil {
				logger.Warnf("failed to update member endpoint: %v", err)
				return
			}
			if !changed {
				return
			}
			logger.Infof("WireGuard UDP observation updated: network=%s public_key=%s observed_endpoint=%s source=wgctrl", networkID, publicKey, endpoint)
			if err := handler.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE); err != nil {
				logger.Warnf("failed to push endpoint update for network %s: %v", networkID, err)
			}
		})

		// A stale handshake updates the WG observation ledger; the pushed
		// product presence still follows the authenticated control session.
		coordinator.SetHeartbeatTimeoutCallback(func(networkID, publicKey string) {
			if err := coordinator.HandleHeartbeatTimeout(networkID, publicKey); err != nil {
				logger.Warnf("failed to handle heartbeat timeout: network=%s public_key=%s err=%v", networkID, publicKey, err)
				return
			}
			logger.Infof("WireGuard heartbeat timeout: network=%s public_key=%s source=wgctrl", networkID, publicKey)
			if err := handler.PushNetworkEvent(networkID, fbMsg.WGNetworkEventActionRUNTIME_UPDATE); err != nil {
				logger.Warnf("failed to push heartbeat timeout event for network %s: %v", networkID, err)
			}
		})

		logger.Info("WireGuard handler initialized")
	}
	return m.setupWireGuardPathService(cfg)
}

func (m *ChannelManager) handleWireGuardMessage(ctx *HandlerContext, msg *fbMsg.Message) error {
	m.mu.RLock()
	handler := m.wgHandler
	m.mu.RUnlock()

	if handler == nil {
		return fmt.Errorf("wireguard disabled")
	}
	if _, ok := ctx.Conn.(*tls.Conn); !ok {
		return fmt.Errorf("wireguard requires tls connection")
	}

	// Build a session snapshot for WG handlers.
	sess := wireguard.HandlerSession{
		SessionID:    ctx.SessionID,
		UserID:       ctx.UserID,
		DeviceID:     ctx.DeviceID,
		Hostname:     ctx.Hostname,
		Capabilities: ctx.Capabilities,
		ScopeClaims:  ctx.ScopeClaims,
		Conn:         ctx.Conn,
	}

	switch msg.Header(nil).Type() {
	case fbMsg.MessageTypeWG_PATH_RUNTIME, fbMsg.MessageTypeWG_PATH_REPORT, fbMsg.MessageTypeWG_PATH_REQUEST:
		pathHandler, ok := handler.(interface {
			HandlePathControl(wireguard.HandlerSession, *fbMsg.Message) error
		})
		if !ok {
			return fmt.Errorf("WG path coordination is not enabled")
		}
		return pathHandler.HandlePathControl(sess, msg)
	case fbMsg.MessageTypeWG_CREATE_NETWORK:
		return handler.HandleCreateNetwork(sess, msg)
	case fbMsg.MessageTypeWG_JOIN_NETWORK:
		return handler.HandleJoinNetwork(sess, msg)
	case fbMsg.MessageTypeWG_LEAVE_NETWORK:
		return handler.HandleLeaveNetwork(sess, msg)
	case fbMsg.MessageTypeWG_LIST_MEMBERS:
		return handler.HandleListMembers(sess, msg)
	case fbMsg.MessageTypeWG_LIST_NETWORKS:
		return handler.HandleListNetworks(sess, msg)
	case fbMsg.MessageTypeWG_GET_NETWORK:
		return handler.HandleGetNetwork(sess, msg)
	case fbMsg.MessageTypeWG_DELETE_NETWORK:
		return handler.HandleDeleteNetwork(sess, msg)
	case fbMsg.MessageTypeWG_NETWORK_RUNTIME_REQUEST:
		return handler.HandleNetworkRuntimeRequest(sess, msg)
	case fbMsg.MessageTypeWG_LIST_AVAILABLE_DEVICES:
		return handler.HandleListAvailableDevices(sess, msg)
	// WG_CREATE_SESSION and WG_PUNCH_INFO dispatch removed (S5-B1):
	// old session mechanism was dead code; LAN gather uses WG_GATHER_INFO.
	case fbMsg.MessageTypeWG_GATHER_INFO:
		return handler.HandleGatherInfo(sess, msg)
	case fbMsg.MessageTypeWG_UPDATE_NETWORK_CIDR:
		return handler.HandleUpdateNetworkCIDR(sess, msg)
	case fbMsg.MessageTypeWG_UPDATE_MEMBER:
		return handler.HandleUpdateMember(sess, msg)
	case fbMsg.MessageTypeWG_UPDATE_NETWORK_RELAY_MODE:
		return handler.HandleUpdateRelayMode(sess, msg)
	case fbMsg.MessageTypeWG_CREATE_INVITE:
		return handler.HandleCreateInvite(sess, msg)
	default:
		return fmt.Errorf("unsupported wireguard message type: %v", msg.Header(nil).Type())
	}
}
