package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/uuid"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/internal/channel/ice"
	chtype "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/server/handler"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

const certChallengeOperationTimeout = 30 * time.Minute

// =================================================================================
// Struct & Constructor
// =================================================================================

// Server Tunnel server
type Server struct {
	config       *config.Config
	listener     net.Listener
	tlsConfig    *tls.Config
	certBundle   *certmgr.CertificateBundle // Certificate bundle (for local issuance)
	tlsCertMgr   *certmgr.Manager
	sessions     *SessionManager
	certIssuer   ClientCertIssuer        // Client certificate issuer (local EdgeCA signing)
	channelMgr   *channel.ChannelManager // Channel manager
	httpsCertSvc *HTTPSCertService       // HTTPS certificate orchestration (Let's Encrypt)
	opts         serverOptions

	// inviteVerifier validates invite tokens for scoped cert issuance.
	// Set by the channel manager during WireGuard setup.
	inviteVerifier InviteTokenVerifier

	// pairTokenVerifier validates one-time pairing tokens.
	// Set by EdgeServer during startup when PairingManager is created.
	pairTokenVerifier PairTokenVerifier

	wg      sync.WaitGroup
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
	// Tracks all accepted tunnel connections (including pre-auth) so Stop can
	// force-close them and unblock goroutines waiting on reads.
	activeConns sync.Map // map[net.Conn]struct{}

	channelSuspended bool
	shuttingDown     bool

	managementMu           sync.Mutex
	certTriggerMu          sync.Mutex
	assignedCertTriggering bool
	customDomainTriggering bool

	// Async broadcast hub for push messages (edge status, tunnel events).
	// Uses a ring buffer so that late-joining subscribers can catch up.
	broadcaster *PushBroadcaster
}

// NewServer Create Tunnel server
func NewServer(cfg *config.Config, certBundle *certmgr.CertificateBundle, optFns ...ServerOption) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	if certBundle == nil {
		return nil, fmt.Errorf("certificate bundle is nil")
	}

	opts := defaultServerOptions()
	for _, fn := range optFns {
		if fn != nil {
			fn(&opts)
		}
	}
	// Owner-saved configuration wins over deployment/CLI values and options.
	managed, err := config.LoadManagementConfig(cfg.GetDataDir())
	if err != nil {
		return nil, fmt.Errorf("load management config: %w", err)
	}
	managed.ApplyAtStartup(cfg)
	applyManagementOptions(managed, cfg, &opts)

	dataDir := cfg.GetDataDir()
	tlsCertMgr := certmgr.NewManager(&certmgr.ManagerConfig{
		CertDir:       dataDir,
		NodeID:        cfg.Node.ID,
		PublicAddress: cfg.Node.PublicAddress,
		CustomDomain:  cfg.Channel.GetCustomDomain(),
		Timeout:       60 * time.Second,
	})

	// Ensure Node.ID is not empty: prioritize config, otherwise read from local file
	if cfg.Node.ID == "" {
		if edgeID, err := config.LoadEdgeID(dataDir); err == nil {
			cfg.Node.ID = edgeID
			logger.Infof("loaded edge_id from local file: %s", edgeID)
		} else {
			logger.Warnf("failed to load edge_id from local file: %v", err)
		}
	}

	// If NodeID is empty, extract from certificate
	if cfg.Node.ID == "" && certBundle.TLSCert != nil {
		// Extract NodeID from certificate CN (format: edge_<node-id>)
		if strings.HasPrefix(certBundle.TLSCert.Subject.CommonName, "edge_") {
			cfg.Node.ID = strings.TrimPrefix(certBundle.TLSCert.Subject.CommonName, "edge_")
			logger.Infof("extracted node_id from certificate: %s", cfg.Node.ID)
		}
	}

	// Create TLS configuration (for Tunnel Server)
	tlsConfig, err := certBundle.CreateTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("create TLS config: %w", err)
	}
	tlsConfig.ServerName = ""

	// Resource pool configuration
	tcpPortMin := uint16(0)
	tcpPortMax := uint16(0)
	udpPortMin := uint16(0)
	udpPortMax := uint16(0)
	if cfg.Proxy.TCP != nil {
		tcpPortMin = cfg.Proxy.TCP.PortMin
		tcpPortMax = cfg.Proxy.TCP.PortMax
	}
	if cfg.Proxy.UDP != nil {
		udpPortMin = cfg.Proxy.UDP.PortMin
		udpPortMax = cfg.Proxy.UDP.PortMax
	}
	resourceCfg := &channel.ResourceConfig{
		TCPPortMin: tcpPortMin,
		TCPPortMax: tcpPortMax,
		UDPPortMin: udpPortMin,
		UDPPortMax: udpPortMax,
	}

	if opts.resourceTCPPortMin != nil {
		resourceCfg.TCPPortMin = *opts.resourceTCPPortMin
	}
	if opts.resourceTCPPortMax != nil {
		resourceCfg.TCPPortMax = *opts.resourceTCPPortMax
	}
	if opts.resourceUDPPortMin != nil {
		resourceCfg.UDPPortMin = *opts.resourceUDPPortMin
	}
	if opts.resourceUDPPortMax != nil {
		resourceCfg.UDPPortMax = *opts.resourceUDPPortMax
	}

	// Registry configuration
	httpPort := uint16(0)
	httpsPort := uint16(0)
	if cfg.Proxy.HTTP != nil {
		httpPort = cfg.Proxy.HTTP.Port
		httpsPort = cfg.Proxy.HTTP.HTTPSPort
	}
	registryCfg := &channel.RegistryConfig{
		HTTPPort:             httpPort,
		HTTPSPort:            httpsPort,
		MaxTargetsPerSession: cfg.Channel.MaxChannelsPerSession,
		MaxTargets:           cfg.Channel.MaxTotalChannels,
	}
	if opts.registryHTTPPort != nil {
		registryCfg.HTTPPort = *opts.registryHTTPPort
	}
	if opts.registryHTTPSPort != nil {
		registryCfg.HTTPSPort = *opts.registryHTTPSPort
	}
	if opts.registryMaxTargetsPerSession != nil {
		registryCfg.MaxTargetsPerSession = *opts.registryMaxTargetsPerSession
	}
	if opts.registryMaxTargets != nil {
		registryCfg.MaxTargets = *opts.registryMaxTargets
	}
	if registryCfg.HTTPPort == 0 && opts.registryHTTPPort == nil {
		registryCfg.HTTPPort = 80
	}
	if registryCfg.MaxTargetsPerSession == 0 && opts.registryMaxTargetsPerSession == nil {
		registryCfg.MaxTargetsPerSession = 10
	}
	if registryCfg.MaxTargets == 0 && opts.registryMaxTargets == nil {
		registryCfg.MaxTargets = 1000
	}

	sessionMgr := NewSessionManager(cfg.Tunnel.MaxSessions)

	// Create TunnelSender
	tunnelSender := channel.NewTunnelSender(sessionMgr)

	// Construct channel configuration
	httpAddr := strings.TrimSpace(cfg.Proxy.HTTP.Addr)
	if httpAddr == "" {
		httpAddr = fmt.Sprintf(":%d", registryCfg.HTTPPort)
	}
	if opts.httpProxyAddr != nil {
		httpAddr = *opts.httpProxyAddr
	}
	httpTimeout := cfg.Proxy.HTTP.Timeout
	if httpTimeout <= 0 {
		httpTimeout = 30 * time.Second
	}
	if opts.httpProxyTimeout != nil {
		httpTimeout = *opts.httpProxyTimeout
	}
	httpBufferSize := config.DefaultHTTPBufferSizeBytes
	if cfg.Proxy.HTTP.Buffer != "" {
		if parsed, parseErr := config.ParseByteSize(cfg.Proxy.HTTP.Buffer); parseErr != nil {
			logger.Warnf("invalid config proxy.http.buffer=%q, fallback to default: %v", cfg.Proxy.HTTP.Buffer, parseErr)
		} else {
			httpBufferSize = parsed
		}
	}
	if opts.httpBufferSize != nil {
		httpBufferSize = *opts.httpBufferSize
	}
	httpBufferLock := cfg.Proxy.HTTP.BufferLock
	if opts.httpBufferLock != nil {
		httpBufferLock = *opts.httpBufferLock
	}
	httpProxyEnabled := cfg.Proxy.HTTP.Enabled
	if opts.httpProxyEnabledSet {
		httpProxyEnabled = opts.httpProxyEnabled
	}
	tcpProxyEnabled := cfg.Proxy.TCP != nil && cfg.Proxy.TCP.Enabled
	if opts.tcpProxyEnabledSet {
		tcpProxyEnabled = opts.tcpProxyEnabled
	}
	udpProxyEnabled := cfg.Proxy.UDP != nil && cfg.Proxy.UDP.Enabled
	if opts.udpProxyEnabledSet {
		udpProxyEnabled = opts.udpProxyEnabled
	}
	wireGuardEnabled := cfg.Proxy.WireGuard != nil && cfg.Proxy.WireGuard.Enabled
	if opts.wireGuardEnabledSet {
		wireGuardEnabled = opts.wireGuardEnabled
	}
	// 将经 server option 解析后的最终启用状态回写到 cfg，使其成为单一真相源。
	// edge status 上报（handler/status.go 读 cfg.Proxy.*.Enabled）据此反映运行时实际能力，
	// 否则 --channel.wireguard.enable=1 这类 option 覆盖不会体现在 SupportedProtocols 中。
	if opts.httpProxyEnabledSet && cfg.Proxy.HTTP != nil {
		cfg.Proxy.HTTP.Enabled = httpProxyEnabled
	}
	if err := cfg.ValidateChannelDomain(); err != nil {
		return nil, err
	}
	if opts.tcpProxyEnabledSet && cfg.Proxy.TCP != nil {
		cfg.Proxy.TCP.Enabled = tcpProxyEnabled
	}
	if opts.udpProxyEnabledSet && cfg.Proxy.UDP != nil {
		cfg.Proxy.UDP.Enabled = udpProxyEnabled
	}
	if opts.wireGuardEnabledSet && cfg.Proxy.WireGuard != nil {
		cfg.Proxy.WireGuard.Enabled = wireGuardEnabled
	}
	wireGuardRelayEnabled, wireGuardInterfacePrefix, wireGuardListenPortBase, wireGuardKeyDir, wireGuardPublicEndpoint, wireGuardForwarderStrategy, wireGuardDefaultPeerRate, wireGuardDefaultPeerCeil :=
		resolveWireGuardRelaySettings(cfg, opts)
	eagerStartHTTPProxy := cfg.Proxy.HTTP.EagerStart
	if opts.eagerStartHTTPProxySet {
		eagerStartHTTPProxy = opts.eagerStartHTTPProxy
	}

	channelCfg := &channel.Config{
		// Registry config
		HTTPPort:             int(registryCfg.HTTPPort),
		HTTPSPort:            int(registryCfg.HTTPSPort),
		MaxTargetsPerSession: registryCfg.MaxTargetsPerSession,
		MaxTargets:           registryCfg.MaxTargets,

		// Resource config - 使用 DomainProvider 替代 AssignedDomain
		DomainProvider: &cfg.Channel.DomainConfig,
		TCPPortMin:     int(resourceCfg.TCPPortMin),
		TCPPortMax:     int(resourceCfg.TCPPortMax),
		UDPPortMin:     int(resourceCfg.UDPPortMin),
		UDPPortMax:     int(resourceCfg.UDPPortMax),

		// Proxy specific
		HTTPProxyEnabled:           httpProxyEnabled,
		HTTPProxyAddr:              httpAddr,
		HTTPProxyTimeout:           httpTimeout,
		HTTPBufferSize:             httpBufferSize,
		HTTPBufferLock:             httpBufferLock,
		EagerStartHTTPProxy:        eagerStartHTTPProxy,
		TCPProxyEnabled:            tcpProxyEnabled,
		UDPProxyEnabled:            udpProxyEnabled,
		WireGuardEnabled:           wireGuardEnabled,
		WireGuardRelayEnabled:      wireGuardRelayEnabled,
		WireGuardInterfacePrefix:   wireGuardInterfacePrefix,
		WireGuardListenPortBase:    wireGuardListenPortBase,
		WireGuardKeyDir:            wireGuardKeyDir,
		WireGuardPublicEndpoint:    wireGuardPublicEndpoint,
		WireGuardForwarderStrategy: wireGuardForwarderStrategy,
		WireGuardDefaultPeerRate:   wireGuardDefaultPeerRate,
		WireGuardDefaultPeerCeil:   wireGuardDefaultPeerCeil,

		// Status Manager
		EdgeID:    cfg.Node.ID,
		StatusDir: dataDir,

		// Alias domain policy from edge config
		AliasDomainPolicy: cfg.Channel.GetAliasDomainPolicy(),
	}
	if cfg.Proxy.WireGuard != nil {
		channelCfg.WireGuardPathCoordination = cfg.Proxy.WireGuard.PathCoordination
	}

	iceEnabled := cfg.Proxy.ICE.Enabled
	if opts.p2pEnabledSet {
		iceEnabled = opts.p2pEnabled
	}
	iceUDPAddrOverride := ""
	if opts.p2pUDPAddr != nil && strings.TrimSpace(*opts.p2pUDPAddr) != "" {
		iceUDPAddrOverride = strings.TrimSpace(*opts.p2pUDPAddr)
	}

	if iceEnabled {
		iceCfg := ice.DefaultConfig()
		advertiseHost := strings.TrimSpace(cfg.Node.PublicAddress)
		if opts.nodePublicAddress != nil && strings.TrimSpace(*opts.nodePublicAddress) != "" {
			advertiseHost = strings.TrimSpace(*opts.nodePublicAddress)
		}
		iceCfg.AdvertiseHost = advertiseHost
		if iceUDPAddrOverride != "" {
			iceCfg.UDPAddr = iceUDPAddrOverride
		} else if strings.TrimSpace(cfg.Proxy.ICE.UDPAddr) != "" {
			iceCfg.UDPAddr = strings.TrimSpace(cfg.Proxy.ICE.UDPAddr)
		} else if fallback := reuseUDPAddrFromTunnelListen(cfg.Tunnel.Listen); fallback != "" {
			iceCfg.UDPAddr = fallback
		}
		if strings.TrimSpace(cfg.Proxy.ICE.UDPAddrAlt) != "" {
			iceCfg.UDPAddrAlt = strings.TrimSpace(cfg.Proxy.ICE.UDPAddrAlt)
		}
		iceCfg.UDPAddr = normalizeICEUDPListenAddrForAdvertiseHost(iceCfg.UDPAddr, advertiseHost)
		iceCfg.UDPAddrAlt = normalizeICEUDPListenAddrForAdvertiseHost(iceCfg.UDPAddrAlt, advertiseHost)
		channelCfg.ICEConfig = &iceCfg
	}

	// Create channel manager (responsible for initializing Registry, Proxies, Coordinator, WireGuard Handler, etc.)
	channelMgr, err := channel.NewChannelManager(channelCfg, tunnelSender, sessionMgr)
	if err != nil {
		return nil, fmt.Errorf("create channel manager: %w", err)
	}

	var httpsCertSvc *HTTPSCertService
	if httpProxyEnabled && registryCfg.HTTPSPort != 0 {
		httpProxy := channelMgr.GetHTTPProxyConfigurator()
		if httpProxy == nil {
			return nil, fmt.Errorf("https enabled but http proxy is unavailable")
		}
		httpsCertSvc, err = NewHTTPSCertService(
			context.Background(),
			cfg,
			httpProxy,
			nil, nil,
		)
		if err != nil {
			return nil, fmt.Errorf("init https certificate service: %w", err)
		}
		httpProxy.SetTLSCertificateResolver(httpsCertSvc.GetTLSCertificate)
		httpProxy.SetHTTPSDomainRequestHandler(func(aliasDomain, channelAssignedDomain string) {
			requestCtx, cancel := context.WithTimeout(context.Background(), certChallengeOperationTimeout)
			defer cancel()

			if _, certErr := httpsCertSvc.EnsureAliasDomain(requestCtx, aliasDomain, channelAssignedDomain); certErr != nil {
				logger.Warnf(
					"alias domain certificate failed, alias_domain=%s, channel_assigned_domain=%s, err=%v, hint=%s",
					aliasDomain, channelAssignedDomain, certErr, httpsCertSvc.AliasDomainGuidance(),
				)
				return
			}
			logger.Infof("alias domain certificate ready, alias_domain=%s, channel_assigned_domain=%s", aliasDomain, channelAssignedDomain)
		})
	}

	server := &Server{
		config:           cfg,
		tlsConfig:        tlsConfig,
		certBundle:       certBundle, // Save certificate bundle
		tlsCertMgr:       tlsCertMgr,
		sessions:         sessionMgr,
		certIssuer:       NewClientCertIssuer(certBundle),
		channelMgr:       channelMgr,
		httpsCertSvc:     httpsCertSvc,
		opts:             opts,
		stopCh:           make(chan struct{}),
		channelSuspended: false,
		broadcaster:      NewPushBroadcaster(defaultBroadcastBufferSize),
	}

	// Share broadcaster with SessionManager so WireGuard AsyncPushToClients works.
	sessionMgr.broadcaster = server.broadcaster

	// Set status change callback
	channelMgr.SetStatusChangeCallback(server.broadcastStatusToSessions)

	return server, nil
}

func resolveWireGuardRelaySettings(
	cfg *config.Config,
	opts serverOptions,
) (relayEnabled bool, interfacePrefix string, listenPortBase int, keyDir string, publicEndpoint string, forwarderStrategy string, defaultPeerRate uint64, defaultPeerCeil uint64) {
	if cfg == nil || cfg.Proxy.WireGuard == nil {
		return false, "", 0, "", "", "", 0, 0
	}

	relayEnabled = cfg.Proxy.WireGuard.RelayEnabled
	interfacePrefix = strings.TrimSpace(cfg.Proxy.WireGuard.InterfacePrefix)
	listenPortBase = cfg.Proxy.WireGuard.ListenPortBase
	keyDir = strings.TrimSpace(cfg.Proxy.WireGuard.KeyDir)
	publicEndpoint = strings.TrimSpace(cfg.Proxy.WireGuard.PublicEndpoint)
	forwarderStrategy = strings.TrimSpace(cfg.Proxy.WireGuard.ForwarderStrategy)
	defaultPeerRate = cfg.Proxy.WireGuard.DefaultPeerRate
	defaultPeerCeil = cfg.Proxy.WireGuard.DefaultPeerCeil
	if publicEndpoint != "" {
		return relayEnabled, interfacePrefix, listenPortBase, keyDir, publicEndpoint, forwarderStrategy, defaultPeerRate, defaultPeerCeil
	}

	if opts.nodePublicAddress != nil && strings.TrimSpace(*opts.nodePublicAddress) != "" {
		publicEndpoint = strings.TrimSpace(*opts.nodePublicAddress)
	} else {
		publicEndpoint = strings.TrimSpace(cfg.Node.PublicAddress)
	}

	return relayEnabled, interfacePrefix, listenPortBase, keyDir, publicEndpoint, forwarderStrategy, defaultPeerRate, defaultPeerCeil
}

// SetPairTokenVerifier wires a pairing token verifier into the server.
// Must be called before Start().
func (s *Server) SetPairTokenVerifier(v PairTokenVerifier) {
	s.pairTokenVerifier = v
}

// =================================================================================
// Lifecycle Management
// =================================================================================

// Start Start server
func (s *Server) Start() error {
	// 1. Start channel service
	if err := s.channelMgr.Start(); err != nil {
		return fmt.Errorf("start channel services: %w", err)
	}

	// Wire invite verifier from channel manager (set during WireGuard setup).
	// Must happen after channelMgr.Start() because setupWireGuard runs inside Start.
	if iv := s.channelMgr.GetInviteVerifier(); iv != nil {
		s.inviteVerifier = iv
		logger.Info("invite token verifier wired from channel manager")
	}

	// Wire pair token verifier (set by EdgeServer before Start).
	if s.pairTokenVerifier != nil {
		logger.Info("pair token verifier wired")
	}

	// 3. Create TLS listener
	listener, err := tls.Listen("tcp", s.config.Tunnel.Listen, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listener = listener

	logger.Infof("tunnel server started, address: %s", s.config.Tunnel.Listen)

	// 4. 启动成功，默认标记为 online（接受客户端服务）
	// 必须在 acceptLoop 之前，否则启动窗口期连接会被拒绝
	s.MarkOnline()

	// 5. Start background tasks
	s.wg.Add(3)
	go s.cleanupLoop()
	go s.certReconcileLoop()
	go s.acceptLoop()
	s.triggerAssignedDomainWildcardCert("startup")
	s.triggerCustomDomainCert("startup")

	return nil
}

// Stop Stop server
func (s *Server) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.shuttingDown = true
	close(s.stopCh)
	s.mu.Unlock()
	if s.httpsCertSvc != nil {
		s.httpsCertSvc.certOperationMu.Lock()
		for _, operations := range s.httpsCertSvc.certOperations {
			for _, cancel := range operations {
				cancel()
			}
		}
		s.httpsCertSvc.certOperationMu.Unlock()
	}

	logger.Info("tunnel server shutting down, enforcing 5s timeout")

	if s.listener != nil {
		s.listener.Close()
	}

	s.closeActiveConnections()

	// Shut down async broadcaster (closes all subscriber channels).
	if s.broadcaster != nil {
		s.broadcaster.Close()
	}

	// Close all active session connections to unblock ReadMessage
	for _, session := range s.sessions.GetAll() {
		if session.Conn != nil {
			session.Conn.Close()
		}
	}

	// 1. Save final offline status locally (no retry, best-effort)
	if s.channelMgr != nil {
		s.channelMgr.SetOnline(false)
	}

	// 3. Stop channel services (suspends proxies, WG coordinator, ICE, etc.)
	needStopChannels := false
	s.mu.Lock()
	if !s.channelSuspended {
		s.channelSuspended = true
		needStopChannels = true
	}
	s.mu.Unlock()

	if s.channelMgr != nil && needStopChannels {
		s.channelMgr.Stop()
	}

	// 5. Wait for background goroutines (with 5s timeout)
	wgDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(wgDone)
	}()
	select {
	case <-wgDone:
		logger.Debug("all server goroutines exited cleanly")
	case <-time.After(5 * time.Second):
		logger.Warn("server shutdown wait timed out after 5s, some goroutines may still be running (process will exit)")
	}

	logger.Info("Tunnel server stopped")
	return nil
}

// GetChannelManager returns the channel manager, or nil if not initialized.
func (s *Server) GetChannelManager() *channel.ChannelManager {
	return s.channelMgr
}

// =================================================================================
// Connection Handling
// =================================================================================

// acceptLoop Accept connection loop
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				logger.Errorf("accept error: %v", err)
				continue
			}
		}

		s.activeConns.Store(conn, struct{}{})
		s.wg.Add(1)
		go s.handleConnection(conn)

		// Log connection count when it's getting high
		connCount := s.activeConnCount()
		if connCount > 50 {
			logger.Warnf(
				"[ConnMonitor] new connection accepted from %s, activeConns=%d (high!)",
				conn.RemoteAddr(), connCount,
			)
		}
	}
}

// handleConnection Handle client connection
//
// Security model:
// - TLS layer: RequestClientCert (optional client certificate)
// - Application layer:
//  1. No client certificate: only allow CERT_REQUEST (certificate request), reject other operations
//  2. Has client certificate: require mTLS authentication, allow all business operations
//
// This design ensures business security (mTLS) while supporting initial certificate request (TLS).
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer s.activeConns.Delete(conn)
	defer conn.Close()
	// Top-level panic recovery: handleSession has its own recover, but
	// TLS handshake, auth negotiation, and other pre-session operations
	// are not protected. This catches any escaped panic to prevent the
	// goroutine from crashing the process.
	defer func() {
		if r := recover(); r != nil {
			remoteAddr := "unknown"
			if addr := conn.RemoteAddr(); addr != nil {
				remoteAddr = addr.String()
			}
			logger.Errorf(
				"handleConnection panic recovered, remote: %s, panic: %v",
				remoteAddr, r,
			)
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		logger.Error("not a TLS connection")
		return
	}

	// Ensure TLS handshake is complete (with timeout to prevent bot scanning
	// from hanging goroutines indefinitely).
	_ = tlsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		logger.Errorf("[%s] TLS handshake failed: %v", conn.RemoteAddr().String(), err)
		return
	}
	_ = tlsConn.SetReadDeadline(time.Time{})

	// Distinguish connection semantics based on ALPN protocol
	state := tlsConn.ConnectionState()
	proto := state.NegotiatedProtocol

	// Debug: log complete TLS state
	logger.Debugf("TLS state: Version=%x, ALPN=%s, PeerCerts=%d, HandshakeComplete=%v",
		state.Version, proto, len(state.PeerCertificates), state.HandshakeComplete)

	// Debug
	if proto == "" {
		logger.Debug("TLS connection without ALPN protocol negotiation")
	} else {
		logger.Debugf("TLS connection with ALPN protocol: %s", proto)
	}

	if proto == "edge-health/1" {
		// Health check connection: only verify TLS handshake success, no certificate request or business processing
		logger.Debug("health-check connection established (ALPN=edge-health/1)")
		return
	}

	// Read the device identity from the verified client certificate.
	certDeviceID, certScopeClaims, err := extractDeviceIdentity(tlsConn)
	if err != nil {
		if err == ErrNoClientCertificate {
			logger.Debug("TLS connection without client certificate, entering certificate request mode")
			s.handleCertRequestOnly(tlsConn)
			return
		}

		logger.Errorf("extract device identity failed: %v", err)
		// Try to check TLS connection status for better issue diagnosis
		state := tlsConn.ConnectionState()
		logger.Errorf("TLS connection state: HandshakeComplete=%v, Version=%x, NegotiatedProtocol=%s, DidResume=%v",
			state.HandshakeComplete, state.Version, state.NegotiatedProtocol, state.DidResume)
		if len(state.PeerCertificates) > 0 {
			logger.Errorf("Peer certificate count: %d", len(state.PeerCertificates))
			for i, cert := range state.PeerCertificates {
				logger.Errorf("Peer certificate[%d]: Subject=%s, Issuer=%s, Validity=[%v to %v]",
					i, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter)
			}
		} else {
			logger.Info("No peer certificates presented")
		}
		return
	}

	certOwnerScope := buildDeviceOwnerUserID(certDeviceID)

	authorization, authorizationErr := certmgr.ReadEdgeAuthorization(state.PeerCertificates[0], s.config.Node.ID)
	if authorizationErr != nil {
		logger.Warnf("certificate authorization denied: %v", authorizationErr)
		return
	}

	logger.Infof("mTLS connection established, cert_user: %s, cert_device: %s, cert_scopes: %v", certOwnerScope, certDeviceID, certScopeClaims)

	protocol := NewProtocol()

	// Reject new business sessions when edge is offline.
	// Health-check and certificate-request connections are already handled above.
	if s.channelMgr != nil && !s.channelMgr.IsOnline() {
		logger.Warnf("rejecting new connection: edge is offline, cert_user: %s", certOwnerScope)
		_ = protocol.SendError(tlsConn, fbMsg.ErrorCodeEDGE_OFFLINE, "edge is offline", "")
		return
	}

	logger.Debug("[Auth] Waiting for AUTH_REQUEST message...")
	_ = tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msg, err := protocol.ReadMessage(tlsConn)
	if err != nil {
		logger.Errorf("read auth message failed: %v", err)
		return
	}
	_ = tlsConn.SetReadDeadline(time.Time{})
	logger.Debugf("[Auth] Received message type: %d", msg.Header(nil).Type())

	if msg.Header(nil).Type() != fbMsg.MessageTypeAUTH_REQUEST {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeINVALID_MESSAGE, "expected AUTH_REQUEST", "")
		return
	}

	authReq := new(fbMsg.AuthRequest)
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeINVALID_MESSAGE, "invalid message body", "")
		return
	}
	authReq.Init(table.Bytes, table.Pos)

	requestedUserID := strings.TrimSpace(string(authReq.UserId()))
	requestedDeviceID := strings.TrimSpace(string(authReq.DeviceId()))
	userID, deviceID, err := resolveAuthenticatedSessionIdentity(
		certDeviceID,
		requestedUserID,
		requestedDeviceID,
	)
	if err != nil {
		rejectReason := "certificate identity mismatch, please refresh local certificate and retry"
		if requestedDeviceID != "" && strings.TrimSpace(certDeviceID) != "" && requestedDeviceID != strings.TrimSpace(certDeviceID) {
			rejectReason = "certificate device mismatch, please refresh local certificate and retry"
		} else if requestedUserID != "" && strings.TrimSpace(certOwnerScope) != "" && requestedUserID != strings.TrimSpace(certOwnerScope) {
			rejectReason = "certificate user mismatch, please refresh local certificate and retry"
		}
		logger.Warnf(
			"[Auth] identity mismatch denied: cert_user=%s cert_device=%s req_user=%s req_device=%s hostname=%s err=%v",
			strings.TrimSpace(certOwnerScope),
			strings.TrimSpace(certDeviceID),
			requestedUserID,
			requestedDeviceID,
			strings.TrimSpace(string(authReq.Hostname())),
			err,
		)
		_ = protocol.SendAuthResponse(
			tlsConn,
			false,
			"",
			rejectReason,
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			&AuthNegotiationResult{
				CompatibilityLevel: fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE,
				ReasonCode:         fbMsg.CompatibilityReasonCodeINCOMPATIBLE_SECURITY_BASELINE,
			},
		)
		return
	}
	hostname := strings.TrimSpace(string(authReq.Hostname()))
	logger.Debugf(
		"[Auth] AUTH_REQUEST: certOwnerScope=%s certDeviceID=%s reqUserID=%s reqDeviceID=%s canonicalUserID=%s canonicalDeviceID=%s hostname=%s",
		certOwnerScope,
		certDeviceID,
		requestedUserID,
		requestedDeviceID,
		userID,
		deviceID,
		hostname,
	)
	negotiation, compatible := negotiateSessionProtocol(protocol, tlsConn, authReq, s.resolveSupportedAuthFeatures())
	if !compatible {
		return
	}

	if !s.isUserAuthorized(userID) {
		_ = protocol.SendAuthResponse(
			tlsConn,
			false,
			"",
			"access denied",
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			&AuthNegotiationResult{
				NegotiatedProtocolMajor: negotiation.NegotiatedProtocolMajor,
				NegotiatedProtocolMinor: negotiation.NegotiatedProtocolMinor,
				CompatibilityLevel:      fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE,
				ReasonCode:              fbMsg.CompatibilityReasonCodeINCOMPATIBLE_POLICY_BLOCKED,
			},
		)
		return
	}

	caps := make([]string, 0, authReq.CapabilitiesLength())
	for i := 0; i < authReq.CapabilitiesLength(); i++ {
		caps = append(caps, string(authReq.Capabilities(i)))
	}
	if s.opts.autoEnableFromCapabilities {
		// Use ChannelManager to check and start service
		if err := s.channelMgr.EnsureForCapabilities(caps); err != nil {
			logger.Warnf("auto enable services from capabilities failed: %v", err)
		}
	}

	sessionID := uuid.New().String()
	session := NewSession(sessionID, userID, deviceID, hostname, tlsConn)
	session.Role = authorization.Role
	session.SetCapabilities(caps)
	session.SetScopeClaims(certScopeClaims) // Certificate scope restrictions (nil = full access)

	if err := s.sessions.Add(session); err != nil {
		_ = protocol.SendAuthResponse(
			tlsConn,
			false,
			"",
			err.Error(),
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			&AuthNegotiationResult{
				NegotiatedProtocolMajor: negotiation.NegotiatedProtocolMajor,
				NegotiatedProtocolMinor: negotiation.NegotiatedProtocolMinor,
				CompatibilityLevel:      fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE,
				ReasonCode:              fbMsg.CompatibilityReasonCodeINCOMPATIBLE_SECURITY_BASELINE,
			},
		)
		return
	}

	if err := protocol.SendAuthResponse(tlsConn, true, sessionID, "", 0, &negotiation); err != nil {
		s.sessions.Remove(sessionID)
		return
	}

	logger.Infof("session built, session: %s, user: %s, device: %s, hostname: %s, totalSessions=%d", sessionID, userID, deviceID, hostname, s.sessions.Count())
	s.handleSession(session)
}

func buildAuthNegotiationResult(
	protocolMajor,
	protocolMinor uint16,
	requiredFeatures,
	requestedFeatures []string,
	supported map[string]struct{},
) AuthNegotiationResult {
	const currentProtocolMajor = uint16(fbMsg.ProtocolMajorCURRENT)
	const currentProtocolMinor = uint16(fbMsg.ProtocolMinorCURRENT)

	result := AuthNegotiationResult{
		NegotiatedProtocolMajor: currentProtocolMajor,
		NegotiatedProtocolMinor: currentProtocolMinor,
		CompatibilityLevel:      fbMsg.CompatibilityLevelCOMPAT_FULL,
		ReasonCode:              fbMsg.CompatibilityReasonCodeOK_FULL,
	}

	// Protocol major is a hard gate for auth negotiation.
	if protocolMajor != currentProtocolMajor {
		result.CompatibilityLevel = fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE
		result.ReasonCode = fbMsg.CompatibilityReasonCodeINCOMPATIBLE_PROTOCOL_MAJOR_MISMATCH
		return result
	}

	if protocolMinor < currentProtocolMinor {
		result.NegotiatedProtocolMinor = protocolMinor
	}

	acceptedSeen := make(map[string]struct{})
	rejectedSeen := make(map[string]struct{})
	missingRequired := false

	addAccepted := func(feature string) {
		if feature == "" {
			return
		}
		if _, ok := acceptedSeen[feature]; ok {
			return
		}
		acceptedSeen[feature] = struct{}{}
		result.AcceptedFeatures = append(result.AcceptedFeatures, feature)
	}
	addRejected := func(feature string) {
		if feature == "" {
			return
		}
		if _, ok := rejectedSeen[feature]; ok {
			return
		}
		rejectedSeen[feature] = struct{}{}
		result.RejectedFeatures = append(result.RejectedFeatures, feature)
	}

	for _, feature := range requiredFeatures {
		name := strings.ToLower(strings.TrimSpace(feature))
		if name == "" {
			continue
		}
		if _, ok := supported[name]; ok {
			addAccepted(name)
			continue
		}
		addRejected(name)
		missingRequired = true
	}

	for _, feature := range requestedFeatures {
		name := strings.ToLower(strings.TrimSpace(feature))
		if name == "" {
			continue
		}
		if _, ok := supported[name]; ok {
			addAccepted(name)
			continue
		}
		addRejected(name)
	}

	if missingRequired {
		result.CompatibilityLevel = fbMsg.CompatibilityLevelCOMPAT_INCOMPATIBLE
		result.ReasonCode = fbMsg.CompatibilityReasonCodeINCOMPATIBLE_REQUIRED_FEATURE_MISSING
		return result
	}

	if len(result.RejectedFeatures) > 0 {
		result.CompatibilityLevel = fbMsg.CompatibilityLevelCOMPAT_DEGRADED
		result.ReasonCode = fbMsg.CompatibilityReasonCodeOK_DEGRADED_REQUESTED_FEATURE_REJECTED
	}
	return result
}

func supportedAuthFeatures(
	httpEnabled,
	httpsEnabled,
	tcpEnabled,
	udpEnabled,
	wireGuardEnabled,
	p2pQUICSupported bool,
) map[string]struct{} {
	supported := map[string]struct{}{
		"relay.fallback": {},
	}
	if httpEnabled {
		supported["http"] = struct{}{}
	}
	if httpsEnabled {
		supported["https"] = struct{}{}
	}
	if tcpEnabled {
		supported["tcp"] = struct{}{}
	}
	if udpEnabled {
		supported["udp"] = struct{}{}
	}
	if wireGuardEnabled {
		supported["wireguard"] = struct{}{}
		supported["wg"] = struct{}{}
	}
	if p2pQUICSupported {
		supported["p2p.quic"] = struct{}{}
	}
	return supported
}

func (s *Server) resolveSupportedAuthFeatures() map[string]struct{} {
	httpEnabled := s != nil && s.channelMgr != nil && s.channelMgr.SupportsChannelType(fbMsg.ChannelTypeHTTP)
	httpsEnabled := s != nil && s.channelMgr != nil && s.channelMgr.SupportsChannelType(fbMsg.ChannelTypeHTTPS)
	tcpEnabled := s != nil && s.channelMgr != nil && s.channelMgr.SupportsChannelType(fbMsg.ChannelTypeTCP)
	udpEnabled := s != nil && s.channelMgr != nil && s.channelMgr.SupportsChannelType(fbMsg.ChannelTypeUDP)
	wireGuardEnabled := s != nil && s.channelMgr != nil && s.channelMgr.SupportsChannelType(fbMsg.ChannelTypeWIREGUARD)
	p2pQUICSupported := s.isP2PQUICNegotiationAvailable()
	features := supportedAuthFeatures(httpEnabled, httpsEnabled, tcpEnabled, udpEnabled, wireGuardEnabled, p2pQUICSupported)
	if wireGuardEnabled && s.broadcaster != nil {
		features["wg.runtime-push.v1"] = struct{}{}
	}
	return features
}

func (s *Server) isP2PQUICNegotiationAvailable() bool {
	return s != nil && s.channelMgr != nil && s.channelMgr.GetICEController() != nil
}

func (s *Server) closeActiveConnections() {
	closed := 0
	s.activeConns.Range(func(key, _ interface{}) bool {
		conn, ok := key.(net.Conn)
		if !ok || conn == nil {
			return true
		}
		_ = conn.Close()
		closed++
		return true
	})
	if closed > 0 {
		logger.Infof("closed active tunnel connections during shutdown, count: %d", closed)
	}
}

// handleSession Handle Session message
func (s *Server) handleSession(session *Session) {
	defer func() {
		// Recover from any unexpected panics in the session read loop.
		// ReadMessage has its own recover, but SetReadDeadline and other
		// operations on the connection are not protected.
		if r := recover(); r != nil {
			logger.Errorf(
				"handleSession panic recovered, session: %s, user: %s, device: %s, panic: %v",
				session.ID,
				session.UserID,
				session.DeviceID,
				r,
			)
		}
	}()
	defer func() {
		// 0. Unsubscribe from async broadcast hub (closes delivery channel).
		if s.broadcaster != nil {
			s.broadcaster.Unsubscribe(session.ID)
		}
		// 1. Close channels bound to this session.
		if s.channelMgr != nil {
			s.channelMgr.CloseBySession(session.ID)
		}
		// 2. Remove session from the registry FIRST.
		//    SessionManager.Remove only deletes clientSessions[deviceID]
		//    when the stored pointer matches THIS session, so a newer
		//    session that already overwrote the entry is left intact.
		s.sessions.Remove(session.ID)
		// 3. Only transition members to Active when no live session
		//    exists for the device.  This prevents a stale defer from
		//    transitioning members when a new session has already taken over.
		if s.channelMgr != nil && !s.sessions.HasClientSession(session.DeviceID) {
			logger.Infof("[SessionDisconnect] device=%s session=%s no active session, calling HandleSessionDisconnect", session.DeviceID, session.ID)
			s.channelMgr.HandleSessionDisconnect(session.DeviceID)
			s.channelMgr.NotifyStatusChange()
		} else if s.channelMgr != nil {
			logger.Infof("[SessionDisconnect] device=%s session=%s still has active session, skipping disconnect", session.DeviceID, session.ID)
		}
	}()

	// Subscribe to async broadcast hub and start per-session delivery goroutine.
	// The delivery goroutine reads push messages from the ring buffer and writes
	// them to the connection independently of the read loop above.
	if s.broadcaster != nil {
		ch, _ := s.broadcaster.Subscribe(session.ID, defaultSubscriberChanSize, session.acceptsBroadcast)
		go session.runBroadcastDelivery(ch, s.broadcaster.Invalidated(session.ID))
	}

	var msgCounter int64
	for {
		select {
		case <-s.stopCh:
			return
		case <-session.closeCh:
			return
		default:
		}

		if err := session.Conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			// Connection is likely closed; exit gracefully instead of panicking.
			logger.Infof(
				"set read deadline failed (connection likely closed), session: %s, err: %v",
				session.ID,
				err,
			)
			return
		}

		msg, err := session.Protocol.ReadMessage(session.Conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			remoteAddr := "unknown"
			if addr := session.Conn.RemoteAddr(); addr != nil {
				remoteAddr = addr.String()
			}
			logger.Infof(
				"connection closed, session: %s, user: %s, device: %s, remote: %s, err: %v, msgsRead: %d",
				session.ID,
				session.UserID,
				session.DeviceID,
				remoteAddr,
				err,
				msgCounter,
			)
			return
		}

		msgCounter++

		// Diagnostic: log every 10th message to track session activity
		if msgCounter%10 == 0 {
			logger.Infof(
				"[SessionStats] session=%s device=%s msgsRead=%d",
				session.ID,
				session.DeviceID,
				msgCounter,
			)
		}

		session.UpdateActivity()
		if s.channelMgr != nil {
			s.channelMgr.TouchSessionChannels(session.ID)
		}
		if header := msg.Header(nil); header != nil {
			msgType := header.Type()
			isTunnelMetaMessage := msgType == fbMsg.MessageTypeTUNNEL_SYNC_REQUEST ||
				msgType == fbMsg.MessageTypeTUNNEL_UPSERT_REQUEST ||
				msgType == fbMsg.MessageTypeTUNNEL_DELETE_REQUEST ||
				msgType == fbMsg.MessageTypeTUNNEL_SYNC_RESPONSE ||
				msgType == fbMsg.MessageTypeTUNNEL_UPSERT_RESPONSE ||
				msgType == fbMsg.MessageTypeTUNNEL_DELETE_RESPONSE
			if isTunnelMetaMessage {
				logger.Infof(
					"[TunnelMeta] recv message type=%s(%d) seq=%d session=%s user=%s device=%s",
					msgType.String(),
					msgType,
					header.Seq(),
					session.ID,
					session.UserID,
					session.DeviceID,
				)
			}
			// Diagnostic: log all WG P2P messages received from clients
			isWGP2PMessage := msgType == fbMsg.MessageTypeWG_GATHER_INFO ||
				msgType == fbMsg.MessageTypeWG_PUNCH_INFO
			if isWGP2PMessage {
				logger.Infof(
					"[WGP2P] recv message type=%s(%d) seq=%d session=%s user=%s device=%s",
					msgType.String(),
					msgType,
					header.Seq(),
					session.ID,
					session.UserID,
					session.DeviceID,
				)
			}
		}

		if err := s.handleMessage(session, msg); err != nil {
			logger.Errorf("handle message failed, session: %s, err: %v", session.ID, err)
			// 统一错误响应：handler 出错时回一个 ERROR 消息给客户端，
			// 否则等待特定 ACK 的请求方（如创建网络）会一直阻塞至超时。
			// 客户端会将 ERROR 关联到 pending 请求并 fail fast。
			// 关键：ERROR 消息必须携带原始请求的 seq，避免被错误地传递给不相关的等待请求。
			if session.Protocol != nil {
				requestSeq := uint32(0)
				if header := msg.Header(nil); header != nil {
					requestSeq = header.Seq()
				}
				if sendErr := session.Protocol.SendErrorWithSeq(
					session.Conn,
					fbMsg.ErrorCodeINTERNAL_ERROR,
					err.Error(),
					session.ID,
					requestSeq,
				); sendErr != nil {
					logger.Warnf("failed to send error response, session: %s, err: %v", session.ID, sendErr)
				}
			}
		}
	}
}

// =================================================================================
// Message Handling
// =================================================================================

// handleMessage Handle specific message
func (s *Server) handleMessage(session *Session, msg *fbMsg.Message) error {
	msgType := msg.Header(nil).Type()
	ctx := s.buildHandlerContext(session)

	switch msgType {
	case fbMsg.MessageTypeHEARTBEAT:
		return session.Protocol.SendHeartbeatAck(session.Conn, session.ID)

	case fbMsg.MessageTypeCERT_REQUEST:
		// Certificate request for authenticated user (for renewal), forward to CSRForwarder
		return s.handleClientCertRequestForSession(session, msg)

	case fbMsg.MessageTypeEDGE_ONLINE_REQUEST:
		return handler.HandleEdgeOnline(ctx, msg, ctx.OwnerVerifier)

	case fbMsg.MessageTypeEDGE_OFFLINE_REQUEST:
		return handler.HandleEdgeOffline(ctx, msg, ctx.OwnerVerifier)

	case fbMsg.MessageTypeEDGE_STATUS_REQUEST:
		return s.handleEdgeStatusRequest(ctx, msg)
	case fbMsg.MessageTypeEDGE_CONFIG_REQUEST:
		return s.handleEdgeConfigRequest(session, msg)
	case fbMsg.MessageTypeEDGE_DOMAIN_CERTIFICATE_REQUEST:
		return s.handleDomainCertificateRequest(session, msg)

	case fbMsg.MessageTypeTUNNEL_STATUS_REQUEST:
		return s.handleTunnelStatusRequest(ctx, msg)

	case fbMsg.MessageTypeEDGE_LOG_REQUEST:
		return handler.HandleEdgeLogRequest(ctx, msg)

	case fbMsg.MessageTypeTUNNEL_SYNC_REQUEST:
		logger.Infof(
			"[TunnelSync] dispatch request message, session=%s, user=%s, device=%s",
			session.ID,
			session.UserID,
			session.DeviceID,
		)
		return s.handleTunnelSyncRequest(session, msg)

	case fbMsg.MessageTypeTUNNEL_UPSERT_REQUEST:
		return s.handleTunnelUpsertRequest(session, msg)

	case fbMsg.MessageTypeTUNNEL_DELETE_REQUEST:
		return s.handleTunnelDeleteRequest(session, msg)

	default:
		// Try to let ChannelManager handle
		// Build ChannelHandlerContext
		chanCtx := &channel.HandlerContext{
			SessionIdentity: chtype.SessionIdentity{
				SessionID:    session.ID,
				UserID:       session.UserID,
				DeviceID:     session.DeviceID,
				Hostname:     session.Hostname,
				Capabilities: session.CapabilitiesSlice(),
				ScopeClaims:  session.ScopeClaims,
			},
			Conn:     session.Conn,
			Protocol: session.Protocol,
			Manager:  s.channelMgr,
		}

		if handled, err := s.channelMgr.HandleMessage(chanCtx, msg); handled {
			return err
		}

		logger.Warnf("unknown message type: %v", msgType)
		return session.Protocol.SendError(session.Conn, fbMsg.ErrorCodeINVALID_MESSAGE,
			fmt.Sprintf("unknown message type: %d", msgType), session.ID)
	}
}

// handleEdgeStatusRequest Handle status request
func (s *Server) handleEdgeStatusRequest(ctx *handler.Context, msg *fbMsg.Message) error {
	var req fbMsg.EdgeStatusRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid EdgeStatusRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	return handler.HandleEdgeStatusRequest(ctx, &req)
}

func (s *Server) handleTunnelStatusRequest(ctx *handler.Context, msg *fbMsg.Message) error {
	var req fbMsg.TunnelStatusRequest
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return fmt.Errorf("invalid TunnelStatusRequest body")
	}
	req.Init(table.Bytes, table.Pos)
	return handler.HandleTunnelStatusRequest(ctx, &req)
}

// =================================================================================
// Helper Methods (Auth & Context)
// =================================================================================

// isUserAuthorized Check if user is authorized
func (s *Server) isUserAuthorized(userID string) bool {
	// Called only after mTLS verification and certificate-bound identity checks.
	// public/private/shared describe usage scope, never anonymous access.
	return strings.TrimSpace(userID) != ""
}

// buildHandlerContext Build handler context
func (s *Server) buildHandlerContext(session *Session) *handler.Context {
	lifecycle := handler.Lifecycle(s)

	return &handler.Context{
		SessionIdentity: chtype.SessionIdentity{
			SessionID:    session.ID,
			UserID:       session.UserID,
			DeviceID:     session.DeviceID,
			Hostname:     session.Hostname,
			Capabilities: session.CapabilitiesSlice(),
			ScopeClaims:  session.ScopeClaims,
		},
		Conn:                   session.Conn,
		ChannelRegistry:        s.channelMgr,
		SessionManager:         s.sessions,
		Lifecycle:              lifecycle,
		StatusManager:          &statusManagerAdapter{source: s.channelMgr},
		OwnerVerifier:          sessionOwnerVerifier{session: session},
		Config:                 s.config,
		Protocol:               &protocolAdapter{session.Protocol},
		ServiceManager:         s.channelMgr,
		DNS01ChallengeProvider: &dns01ChallengeAdapter{s.httpsCertSvc},
		CnameChecker:           &cnameCheckerAdapter{&s.config.Channel.DomainConfig},
		DomainStatusProvider: &domainStatusAdapter{
			dp:      &s.config.Channel.DomainConfig,
			certSvc: s.httpsCertSvc,
		},
	}
}

func (s *Server) triggerAssignedDomainWildcardCert(reason string) {
	if s.config.Proxy.HTTP.CertificateSource == "upload" {
		return
	}
	if s.httpsCertSvc == nil {
		return
	}

	assignedDomain := s.httpsCertSvc.AssignedBaseDomain()
	if assignedDomain == "" {
		return
	}

	s.certTriggerMu.Lock()
	if s.assignedCertTriggering {
		s.certTriggerMu.Unlock()
		logger.Debugf("skip assigned-domain cert trigger: already running, reason=%s, assigned_domain=%s", reason, assignedDomain)
		return
	}
	s.assignedCertTriggering = true
	s.certTriggerMu.Unlock()

	go func() {
		defer func() {
			s.certTriggerMu.Lock()
			s.assignedCertTriggering = false
			s.certTriggerMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), certChallengeOperationTimeout)
		defer cancel()

		stored, err := s.httpsCertSvc.EnsureAssignedDomain(ctx)
		if err != nil {
			logger.Warnf("assigned domain wildcard certificate failed, assigned_domain=%s, reason=%s, err=%v, hint=%s",
				assignedDomain, reason, err, s.httpsCertSvc.WildcardGuidance(assignedDomain))
			return
		}
		if stored != nil {
			logger.Infof("assigned domain wildcard certificate ready, domain=%s, reason=%s, cert=%s", stored.Domain, reason, stored.CertificatePath)
		}
	}()
}

func (s *Server) triggerCustomDomainCert(reason string) {
	if s.httpsCertSvc == nil {
		return
	}

	customDomain := s.config.Channel.GetCustomDomain()
	assignedDomain := s.config.Channel.GetAssignedDomain()
	if customDomain == "" || assignedDomain == "" {
		return
	}

	s.certTriggerMu.Lock()
	if s.customDomainTriggering {
		s.certTriggerMu.Unlock()
		logger.Debugf("skip custom-domain cert trigger: already running, reason=%s, custom_domain=%s", reason, customDomain)
		return
	}
	s.customDomainTriggering = true
	s.certTriggerMu.Unlock()

	go func() {
		defer func() {
			s.certTriggerMu.Lock()
			s.customDomainTriggering = false
			s.certTriggerMu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), certChallengeOperationTimeout)
		defer cancel()

		stored, err := s.httpsCertSvc.EnsureCustomDomain(ctx, customDomain, assignedDomain)
		if err != nil {
			logger.Warnf("custom domain certificate failed, custom_domain=%s, assigned_domain=%s, reason=%s, err=%v, hint=%s",
				customDomain, assignedDomain, reason, err, s.httpsCertSvc.CustomDomainGuidance())
			return
		}
		if stored != nil {
			logger.Infof("custom domain certificate ready, custom_domain=%s, assigned_domain=%s, reason=%s, cert=%s",
				customDomain, assignedDomain, reason, stored.CertificatePath)
		}
	}()
}

func reuseUDPAddrFromTunnelListen(listen string) string {
	trimmed := strings.TrimSpace(listen)
	if trimmed == "" {
		return ""
	}

	if _, port, err := net.SplitHostPort(trimmed); err == nil {
		port = strings.TrimSpace(port)
		if port == "" {
			return ""
		}
		return net.JoinHostPort("0.0.0.0", port)
	}

	if strings.Count(trimmed, ":") == 0 {
		return net.JoinHostPort("0.0.0.0", trimmed)
	}
	return ""
}

func normalizeICEUDPListenAddrForAdvertiseHost(listenAddr, advertiseHost string) string {
	trimmedListen := strings.TrimSpace(listenAddr)
	if trimmedListen == "" {
		return ""
	}

	ip := net.ParseIP(strings.TrimSpace(advertiseHost))
	if ip == nil || ip.To4() == nil {
		return trimmedListen
	}

	if strings.HasPrefix(trimmedListen, ":") {
		return "0.0.0.0" + trimmedListen
	}

	host, port, err := net.SplitHostPort(trimmedListen)
	if err != nil {
		return trimmedListen
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "::" || host == "0.0.0.0" {
		return net.JoinHostPort("0.0.0.0", strings.TrimSpace(port))
	}
	return trimmedListen
}
