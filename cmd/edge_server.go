package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"time"

	"icool.io/yat/edge/internal/ipc"
	"icool.io/yat/edge/internal/server"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"icool.io/yat/edge/pkg/config"
	"icool.io/yat/edge/pkg/i18n"
	logger "icool.io/yat/edge/pkg/log"
)

// ServerState Edge server lifecycle state
type ServerState int

const (
	StateUninitialized ServerState = iota // Uninitialized
	StateBootstrapping                    // Certificate Bootstrap in progress
	StateCertReady                        // Certificate ready
	StateStarting                         // Service starting
	StateRunning                          // Service running
	StateStopping                         // Service stopping
	StateStopped                          // Stopped
	StateError                            // Error state
)

func (s ServerState) String() string {
	switch s {
	case StateUninitialized:
		return "uninitialized"
	case StateBootstrapping:
		return "bootstrapping"
	case StateCertReady:
		return "cert_ready"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// EdgeServer Edge server (wraps all components)
type EdgeServer struct {
	// Configuration
	config        *config.Config
	pidFile       string
	sockFile      string
	tunnelOptions []server.ServerOption
	// State management
	state   ServerState
	stateMu sync.RWMutex

	// Certificate management (singleton)
	certMgr    *certmgr.Manager
	certBundle *certmgr.CertificateBundle
	certReady  bool

	// Runtime components (created after cert ready)
	tunnelServer  *server.Server
	ipcServer     *ipc.Server
	signalHandler *SignalHandler
	pairMgr       *server.PairingManager // pairing token manager (mTLS-based pairing)
	pairToken     string                 // Current pairing token

	// Lifecycle management
	stopCh   chan struct{}
	stopOnce sync.Once
	mu       sync.Mutex
}

// NewEdgeServer Create edge server
func NewEdgeServer(cfg *config.Config, pidFile string, sockFile string, tunnelOptions ...server.ServerOption) (*EdgeServer, error) {
	// Certificate bootstrap also needs the saved public address and domain.
	managed, err := config.LoadManagementConfig(cfg.GetDataDir())
	if err != nil {
		return nil, fmt.Errorf("load management config: %w", err)
	}
	managed.ApplyAtStartup(cfg)
	return &EdgeServer{
		config:        cfg,
		pidFile:       pidFile,
		sockFile:      sockFile,
		tunnelOptions: tunnelOptions,
		state:         StateUninitialized,
		stopCh:        make(chan struct{}),
	}, nil
}

// Start Start all services (in phases)
func (e *EdgeServer) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	msg := i18n.Msg()
	logger.Infof(msg.EdgeServerStarting, e.GetState())

	// Phase 1: Initialize certificate manager (singleton)
	if err := e.initCertManager(); err != nil {
		e.setState(StateError)
		return fmt.Errorf("init cert manager: %w", err)
	}

	// Phase 2: Ensure certificates are ready (may trigger Bootstrap)
	if err := e.ensureCertificates(); err != nil {
		e.setState(StateError)
		return fmt.Errorf("ensure certificates: %w", err)
	}

	// Phase 3: Certificates ready, initialize services
	if err := e.initializeServices(); err != nil {
		e.setState(StateError)
		return fmt.Errorf("initialize services: %w", err)
	}

	// Phase 4: Start services
	if err := e.startServices(); err != nil {
		e.setState(StateError)
		return fmt.Errorf("start services: %w", err)
	}

	e.setState(StateRunning)
	logger.Infof(msg.EdgeServerStarted, e.GetState())
	return nil
}

// Stop Stop all services
func (e *EdgeServer) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	msg := i18n.Msg()
	logger.Info(msg.EdgeServerStopping)

	// 1. Stop pairing is handled by tunnel server shutdown (no separate server)

	// 2. Stop IPC server
	if e.ipcServer != nil {
		e.ipcServer.Stop()
	}

	// 3. Stop tunnel server
	if e.tunnelServer != nil {
		e.tunnelServer.Stop()
	}

	logger.Info(msg.EdgeServerStopped)
	return nil
}

// registerIPCHandlers Register IPC command handlers
func (e *EdgeServer) registerIPCHandlers() {
	msg := i18n.Msg()

	// Resume local Edge service
	e.ipcServer.RegisterHandler("online", func(req *ipc.Request) *ipc.Response {
		e.tunnelServer.MarkOnline()
		logger.Info(msg.IPCNodeMarkedOnline)
		return &ipc.Response{
			Success: true,
			Message: "node marked as online successfully",
		}
	})

	// Suspend local Edge service
	e.ipcServer.RegisterHandler("offline", func(req *ipc.Request) *ipc.Response {
		e.tunnelServer.MarkOffline()
		logger.Info(msg.IPCNodeMarkedOffline)
		return &ipc.Response{
			Success: true,
			Message: "node marked as offline successfully",
		}
	})

	// reload command - reload configuration
	e.ipcServer.RegisterHandler("reload", func(req *ipc.Request) *ipc.Response {
		// Config
		logger.Info(msg.IPCReloadConfigRequested)
		return &ipc.Response{
			Success: true,
			Message: "reload not yet implemented",
		}
	})

	// status command - get service status
	e.ipcServer.RegisterHandler("status", func(req *ipc.Request) *ipc.Response {
		data := make(map[string]interface{})

		// Server status
		data["state"] = e.GetState().String()
		data["cert_ready"] = e.certReady

		// Configuration info
		if e.config != nil {
			data["node_id"] = e.config.Node.ID
			data["zone"] = e.config.Node.Zone
			data["tunnel_listen"] = e.config.Tunnel.Listen
			data["max_sessions"] = e.config.Tunnel.MaxSessions
		}

		// Certificate info
		if e.certBundle != nil {
			data["cert_expires_at"] = e.certBundle.GetExpiresAt()
		}

		// Tunnel server info
		if e.tunnelServer != nil {
			data["tunnel_running"] = true
		} else {
			data["tunnel_running"] = false
		}

		return &ipc.Response{
			Success: true,
			Message: fmt.Sprintf("server is %s", e.GetState()),
			Data:    data,
		}
	})

	// network_info command - get runtime info for a WireGuard network
	e.ipcServer.RegisterHandler("network_info", func(req *ipc.Request) *ipc.Response {
		networkID, _ := req.Params["network_id"].(string)
		if networkID == "" {
			return &ipc.Response{Success: false, Message: "network_id required"}
		}
		if e.tunnelServer == nil {
			return &ipc.Response{Success: false, Message: "server not running"}
		}
		cm := e.tunnelServer.GetChannelManager()
		if cm == nil {
			return &ipc.Response{Success: false, Message: "channel manager not initialized"}
		}
		rm := cm.GetWGRelayManager()
		if rm == nil {
			return &ipc.Response{Success: false, Message: "WireGuard relay manager not available"}
		}
		info, err := rm.GetNetworkRuntimeInfo(networkID)
		if err != nil {
			return &ipc.Response{Success: false, Message: err.Error()}
		}
		return &ipc.Response{
			Success: true,
			Data: map[string]interface{}{
				"interface_name":     info.InterfaceName,
				"forwarder_strategy": info.ForwarderStrategy,
				"route_table_id":     info.RouteTableID,
				"forwarded":          info.ForwarderStats.Forwarded,
				"dropped":            info.ForwarderStats.Dropped,
				"errors":             info.ForwarderStats.Errors,
				"peer_stats":         info.PeerStats,
				"rate_limits":        info.RateLimits,
			},
		}
	})

	// network_members command - get real-time member list from in-memory state
	// Unlike SQLite, this includes current authenticated control presence,
	// independently of the relay's WG handshake observations.
	e.ipcServer.RegisterHandler("network_members", func(req *ipc.Request) *ipc.Response {
		networkID, _ := req.Params["network_id"].(string)
		if networkID == "" {
			return &ipc.Response{Success: false, Message: "network_id required"}
		}
		if e.tunnelServer == nil {
			return &ipc.Response{Success: false, Message: "server not running"}
		}
		cm := e.tunnelServer.GetChannelManager()
		if cm == nil {
			return &ipc.Response{Success: false, Message: "channel manager not initialized"}
		}
		members := cm.GetWGNetworkMembers(networkID)
		if members == nil {
			return &ipc.Response{Success: false, Message: "WireGuard coordinator not available"}
		}
		memberData := make([]map[string]interface{}, 0, len(members))
		for _, m := range members {
			if m == nil {
				continue
			}
			memberData = append(memberData, map[string]interface{}{
				"member_id":    m.ID,
				"status":       int(m.Status),
				"endpoint":     m.Endpoint,
				"lan_endpoint": m.LANEndpoint,
			})
		}
		return &ipc.Response{
			Success: true,
			Data:    map[string]interface{}{"members": memberData},
		}
	})

	// network_rate_limit command - set, remove, or query per-peer rate limits
	e.ipcServer.RegisterHandler("network_rate_limit", func(req *ipc.Request) *ipc.Response {
		networkID, _ := req.Params["network_id"].(string)
		action, _ := req.Params["action"].(string)
		peerIP, _ := req.Params["peer_ip"].(string)
		if networkID == "" || action == "" {
			return &ipc.Response{Success: false, Message: "network_id and action required"}
		}
		if e.tunnelServer == nil {
			return &ipc.Response{Success: false, Message: "server not running"}
		}
		cm := e.tunnelServer.GetChannelManager()
		if cm == nil {
			return &ipc.Response{Success: false, Message: "channel manager not initialized"}
		}
		rm := cm.GetWGRelayManager()
		if rm == nil {
			return &ipc.Response{Success: false, Message: "WireGuard relay manager not available"}
		}
		switch action {
		case "set":
			rate, _ := req.Params["rate"].(float64)
			ceil, _ := req.Params["ceil"].(float64)
			if rate <= 0 {
				return &ipc.Response{Success: false, Message: "rate must be positive (bytes/sec)"}
			}
			if ceil <= 0 {
				ceil = rate
			}
			if err := rm.SetPeerRateLimit(networkID, peerIP, uint64(rate), uint64(ceil)); err != nil {
				return &ipc.Response{Success: false, Message: err.Error()}
			}
			return &ipc.Response{Success: true, Message: fmt.Sprintf("rate limit set for %s: %.0f/%.0f bytes/s", peerIP, rate, ceil)}
		case "remove":
			if err := rm.RemovePeerRateLimit(networkID, peerIP); err != nil {
				return &ipc.Response{Success: false, Message: err.Error()}
			}
			return &ipc.Response{Success: true, Message: fmt.Sprintf("rate limit removed for %s", peerIP)}
		case "query":
			// Query mode: if peer_ip is provided, return that peer's limit;
			// otherwise return all rate limits for the network.
			if peerIP != "" {
				info, found := rm.GetPeerRateLimit(networkID, peerIP)
				if !found {
					return &ipc.Response{Success: true, Data: map[string]interface{}{
						"network_id": networkID,
						"peer_ip":    peerIP,
						"configured": false,
					}}
				}
				return &ipc.Response{Success: true, Data: map[string]interface{}{
					"network_id": networkID,
					"peer_ip":    peerIP,
					"configured": true,
					"rate":       info.Rate,
					"ceil":       info.Ceil,
				}}
			}
			// Network-wide query: return all rate limits for the network.
			runtimeInfo, err := rm.GetNetworkRuntimeInfo(networkID)
			if err != nil {
				return &ipc.Response{Success: false, Message: err.Error()}
			}
			return &ipc.Response{Success: true, Data: map[string]interface{}{
				"network_id":  networkID,
				"rate_limits": runtimeInfo.RateLimits,
			}}
		default:
			return &ipc.Response{Success: false, Message: "action must be 'set', 'remove', or 'query'"}
		}
	})

	// pair_info command - return current pairing token and tunnel address
	e.ipcServer.RegisterHandler("pair_info", func(req *ipc.Request) *ipc.Response {
		if e.pairMgr == nil {
			return &ipc.Response{Success: false, Message: "pairing manager not initialized"}
		}
		// Generate a fresh token for the CLI request
		role := certmgr.RoleDevice
		if owner, _ := req.Params["owner"].(bool); owner {
			role = certmgr.RoleOwner
		}
		token := e.pairMgr.GenerateTokenForRole(role)
		return &ipc.Response{
			Success: true,
			Data: map[string]interface{}{
				"role":           role,
				"token":          token,
				"tunnel_address": e.pairMgr.TunnelAddress(),
				"edge_id":        e.config.Node.ID,
			},
		}
	})
}

// GetTunnelServer Get tunnel server (for testing)
func (e *EdgeServer) GetTunnelServer() *server.Server {
	return e.tunnelServer
}

// initCertManager Initialize certificate manager (singleton)
func (e *EdgeServer) initCertManager() error {
	dataDir := e.config.GetDataDir()

	e.certMgr = certmgr.NewManager(&certmgr.ManagerConfig{
		CertDir:       dataDir,
		NodeID:        e.config.Node.ID,
		PublicAddress: e.config.Node.PublicAddress,
		CustomDomain:  e.config.Channel.GetCustomDomain(),
		Timeout:       60 * time.Second,
	})

	logger.Infof(i18n.Msg().CertManagerInitialized, dataDir)
	return nil
}

// ensureCertificates Ensure certificates are ready (check + load/request)
func (e *EdgeServer) ensureCertificates() error {
	msg := i18n.Msg()
	logger.Info(msg.CheckingCertificateStatus)

	dataDir := e.config.GetDataDir()
	// Distinguish between full bootstrap and local TLS leaf regeneration.
	needsLocalTLSCertificate := certmgr.NeedsTLSCertificate(dataDir)
	needsBootstrap := certmgr.NeedsCertificate(dataDir) && !needsLocalTLSCertificate

	if needsBootstrap {
		logger.Info(msg.CertMissingOrExpiredBootstrap)
	}
	if needsBootstrap || needsLocalTLSCertificate {
		if needsLocalTLSCertificate {
			logger.Warn("TLS certificate missing or invalid, attempting local regeneration")
		}
		if err := e.runBootstrap(); err != nil {
			// Bootstrap 失败，直接返回致命错误（调用方应退出程序）
			return &FatalBootstrapError{Err: err}
		}
	}

	// Load certificate bundle (once)
	bundle, err := e.certMgr.LoadCertificateBundle()
	if err != nil {
		return fmt.Errorf("load certificate bundle: %w", err)
	}
	if bundle == nil || bundle.TLSCert == nil {
		return fmt.Errorf("certificate bundle is incomplete after ensure: TLS certificate is missing")
	}
	e.certBundle = bundle

	// Check if about to expire (within 7 days)
	if bundle.WillExpireSoon(7 * 24 * time.Hour) {
		logger.Warnf(msg.CertExpiringSoon,
			bundle.GetExpiresAt(),
			bundle.GetExpiresIn())
	}

	e.certReady = true
	e.setState(StateCertReady)

	// Load persisted AssignedDomain (from previous bootstrap)
	if e.config.Channel.GetAssignedDomain() == "" {
		if bd, err := config.LoadAssignedDomain(e.config.GetDataDir()); err == nil && bd != "" {
			changed, persistErr := e.config.Channel.SetAssignedDomainWithError(bd)
			if persistErr != nil {
				logger.Warnf("persist assigned domain from local failed: data_dir=%s assigned_domain=%s err=%v", e.config.GetDataDir(), bd, persistErr)
			}
			logger.Infof("%s (changed=%t, data_dir=%s)", fmt.Sprintf(msg.LoadedAssignedDomainFromLocal, bd), changed, e.config.GetDataDir())
		}
	}

	logger.Info(msg.CertificateReady)
	return nil
}

// runBootstrap Execute Bootstrap (using certMgr)
func (e *EdgeServer) runBootstrap() error {
	e.setState(StateBootstrapping)
	msg := i18n.Msg()
	logger.Info(msg.StartingCertificateBootstrap)

	// Use initialized certMgr to execute Bootstrap
	bundle, err := e.certMgr.EnsureCertificate(context.Background())
	if err != nil {
		return fmt.Errorf("local certificate bootstrap failed: %w", err)
	}

	// Update certificate bundle
	e.certBundle = bundle

	// DEBUG: Print bootstrap bundle info
	logger.Infof("DEBUG bootstrap bundle: AssignedDomain=%q, ExpiresAt=%v",
		bundle.AssignedDomain, bundle.GetExpiresAt())

	// Try to extract NodeID from certificate (if not in config)
	if e.config.Node.ID == "" && bundle.TLSCert != nil {
		if cn := bundle.TLSCert.Subject.CommonName; len(cn) > 5 && cn[:5] == "edge_" {
			e.config.Node.ID = cn[5:]
			logger.Infof(msg.ExtractedNodeIDFromCert, e.config.Node.ID)
		}
	}

	// Apply AssignedDomain to config (SetAssignedDomain auto-persists)
	if bundle.AssignedDomain != "" {
		changed, persistErr := e.config.Channel.SetAssignedDomainWithError(bundle.AssignedDomain)
		if persistErr != nil {
			logger.Warnf("persist assigned domain failed: data_dir=%s assigned_domain=%s err=%v", e.config.GetDataDir(), bundle.AssignedDomain, persistErr)
		}
		logger.Infof("%s (changed=%t, data_dir=%s)", fmt.Sprintf(msg.AppliedAssignedDomain, bundle.AssignedDomain), changed, e.config.GetDataDir())
	}

	logger.Infof(msg.BootstrapCompleted, bundle.AssignedDomain, bundle.GetExpiresAt())
	return nil
}

// initializeServices Initialize service components
func (e *EdgeServer) initializeServices() error {
	if !e.certReady {
		return errors.New("certificates not ready")
	}

	msg := i18n.Msg()
	logger.Info(msg.InitializingServices)

	// 1. Create Tunnel Server (using singleton certBundle)
	tunnelSrv, err := server.NewServer(e.config, e.certBundle, e.tunnelOptions...)
	if err != nil {
		return fmt.Errorf("create tunnel server: %w", err)
	}
	e.tunnelServer = tunnelSrv

	// 2. Create IPC Server
	e.ipcServer = ipc.NewServer(e.sockFile)
	e.registerIPCHandlers()

	// 3. Create Pairing Manager and wire to tunnel server
	tunnelAddr := e.config.Tunnel.Listen
	if e.config.Node.PublicAddress != "" {
		if _, port, err := net.SplitHostPort(e.config.Tunnel.Listen); err == nil {
			tunnelAddr = net.JoinHostPort(e.config.Node.PublicAddress, port)
		}
	}
	e.pairMgr = server.NewPairingManager(tunnelAddr)
	if err := e.pairMgr.SetStateFile(filepath.Join(e.config.GetDataDir(), "consumed-pair-tokens.json")); err != nil {
		return fmt.Errorf("load pairing state: %w", err)
	}
	if e.config.Pair.Token != "" {
		e.pairMgr.RegisterTokenForRole(e.config.Pair.Token, e.config.Pair.Role)
		e.pairToken = e.config.Pair.Token
	} else {
		e.pairToken = e.pairMgr.GenerateTokenForRole(certmgr.RoleOwner)
	}
	tunnelSrv.SetPairTokenVerifier(e.pairMgr)
	logger.Infof("[pair] pairing manager wired to tunnel server, token: %s", e.pairToken)

	// 4. Create signal handler
	e.signalHandler = NewSignalHandler(e.pidFile)

	logger.Info(msg.ServicesInitialized)
	return nil
}

// startServices Start all services
func (e *EdgeServer) startServices() error {
	e.setState(StateStarting)

	msg := i18n.Msg()
	logger.Info(msg.StartingServices)

	// 1. Start Tunnel Server
	if err := e.tunnelServer.Start(); err != nil {
		return fmt.Errorf("start tunnel server: %w", err)
	}

	// 2. Start IPC Server
	if err := e.ipcServer.Start(); err != nil {
		logger.Warnf(msg.StartIPCServerFailed, err)
		// Don't block service startup
	}

	// 3. Set up signal handling
	e.signalHandler.Setup(e)

	return nil
}

// GetPairToken returns the current pairing token.
func (e *EdgeServer) GetPairToken() string {
	return e.pairToken
}

// GetPairingManager returns the PairingManager (for IPC handlers).
func (e *EdgeServer) GetPairingManager() *server.PairingManager {
	return e.pairMgr
}

// setState Set state
func (e *EdgeServer) setState(state ServerState) {
	e.stateMu.Lock()
	old := e.state
	e.state = state
	e.stateMu.Unlock()

	if old != state {
		logger.Infof(i18n.Msg().ServerStateChanged, old, state)
	}
}

// GetState Get current state
func (e *EdgeServer) GetState() ServerState {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.state
}

// FatalBootstrapError represents a fatal bootstrap error that should cause program exit
type FatalBootstrapError struct {
	Err error
}

func (e *FatalBootstrapError) Error() string {
	return e.Err.Error()
}

func (e *FatalBootstrapError) Unwrap() error {
	return e.Err
}

// IsFatalBootstrapError checks if the error is a fatal bootstrap error
func IsFatalBootstrapError(err error) bool {
	var fatalErr *FatalBootstrapError
	return errors.As(err, &fatalErr)
}
