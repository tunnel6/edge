//go:build linux

package relay

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	logger "icool.io/yat/edge/pkg/log"
)

type linuxRelayManager struct {
	cfg         *Config
	mu          sync.RWMutex
	lifecycleMu sync.Mutex
	// interfaceMu serializes create/delete/stop across both kernel work and
	// lifetime publication. Owner never takes this or the kernel-operation mu.
	interfaceMu  sync.Mutex
	observations observationLifetimes
	interfaces   map[string]*networkInterface // networkID -> interface state
	client       *wgctrl.Client
	stopCh       chan struct{}
	running      bool
	wg           sync.WaitGroup

	// routeTables assigns a unique Linux routing table ID to each network,
	// preventing route conflicts when multiple networks use overlapping CIDRs.
	routeTables *routeTableAllocator

	// rateLimitStore persists per-peer rate limits across restarts.
	// Nil means rate limits are not persisted.
	rateLimitStore PeerRateLimitStore

	// rateLimitCache caches persisted rate limits keyed by "networkID/peerIP".
	// Populated once by RestorePeerRateLimits; updated on Set/Remove.
	rateLimitCache map[string]PeerRateLimitInfo

	// OnEndpointChange is called when a peer's observed endpoint changes.
	OnEndpointChange func(networkID, publicKey, endpoint string)
	onObservation    func(Observation)

	// OnHeartbeatTimeout is called when a peer's WireGuard handshake age
	// exceeds the heartbeat timeout (no successful handshake within the window).
	OnHeartbeatTimeout func(networkID, publicKey string)
}

type networkInterface struct {
	Generation      string
	Name            string
	NetworkID       string
	PrivateKey      wgtypes.Key
	PublicKey       wgtypes.Key
	ListenPort      int
	AssignedIP      string
	CIDR            string
	ObservationOnly bool
	// routeTableID is the per-network Linux routing table ID used for policy
	// routing. Zero means no table has been allocated (e.g. cleanup already done).
	routeTableID uint32

	mu sync.Mutex
	// peerObserved maps publicKey → peer's current observed WG address.
	// Updated by the observe loop from the main WG interface.
	peerObserved map[string]*net.UDPAddr
	// peerInfos maps publicKey → assigned IP.
	peerInfos map[string]string
	// forwarder handles same-interface packet forwarding for relay mode.
	forwarder Forwarder
}

func NewLinuxRelayManager(cfg *Config) (RelayManager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	publicHost, err := NormalizePublicHost(cfg.PublicEndpoint)
	if err != nil {
		return nil, err
	}
	copyConfig := *cfg
	copyConfig.PublicEndpoint = publicHost
	cfg = &copyConfig

	if cfg.KeyDir != "" {
		if err := os.MkdirAll(cfg.KeyDir, 0700); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
	}

	// Let wgctrl/netlink probe the real kernel capability. The old /proc and /sys
	// precheck was overly strict on some hosts and could reject otherwise working
	// WireGuard runtimes before the actual client probe ran.
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client (is wireguard module loaded?): %w", err)
	}

	// Scan local physical subnets so that user-provided CIDRs can be validated
	// against the edge's actual network topology.
	localSubnets, scanErr := ScanLocalSubnets()
	if scanErr != nil {
		logger.Warnf("failed to scan local subnets for CIDR validation: %v", scanErr)
	} else if len(localSubnets) > 0 {
		for _, s := range localSubnets {
			logger.Infof("local subnet detected: %s", s.String())
		}
	}
	cfg.ForbiddenSubnets = localSubnets

	return &linuxRelayManager{
		cfg:            cfg,
		interfaces:     make(map[string]*networkInterface),
		client:         client,
		stopCh:         make(chan struct{}),
		routeTables:    newRouteTableAllocator(),
		rateLimitCache: make(map[string]PeerRateLimitInfo),
	}, nil
}

func (m *linuxRelayManager) SetOnEndpointChange(fn func(networkID, publicKey, endpoint string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OnEndpointChange = fn
}

func (m *linuxRelayManager) SetOnObservation(fn func(Observation)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onObservation = fn
}

func (m *linuxRelayManager) WithCurrentObservation(sample Observation, consume func() error) error {
	return m.observations.withCurrent(sample, consume)
}

var _ ObservationSource = (*linuxRelayManager)(nil)
var _ ObservationMutationSource = (*linuxRelayManager)(nil)

func (m *linuxRelayManager) BindObservationMutations(gate func(func() error) error) (func(), error) {
	return m.observations.bind(gate)
}

func (m *linuxRelayManager) SetOnHeartbeatTimeout(fn func(networkID, publicKey string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OnHeartbeatTimeout = fn
}

func (m *linuxRelayManager) SetObservationOnly(networkID string, observationOnly bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ni := m.interfaces[networkID]
	if ni == nil {
		return fmt.Errorf("no interface for network %s", networkID)
	}
	wasObservationOnly := ni.ObservationOnly
	ni.ObservationOnly = observationOnly
	if observationOnly {
		ni.mu.Lock()
		ni.peerInfos = make(map[string]string)
		ni.peerObserved = make(map[string]*net.UDPAddr)
		ni.mu.Unlock()
	} else if wasObservationOnly && ni.forwarder == nil {
		// Transitioning from observation-only to relay mode: the interface
		// was created without a forwarder. Create and start one now to
		// install nftables/iptables forwarding rules.
		fwd, err := NewForwarder(m.cfg.ForwarderStrategy, ni.Name, ni.CIDR, ni.AssignedIP)
		if err != nil {
			logger.Warnf("forwarder init failed for %s (observation→relay): %v", ni.Name, err)
		} else {
			ni.forwarder = fwd
			if err := ni.forwarder.Start(); err != nil {
				logger.Warnf("forwarder start failed for %s (observation→relay): %v", ni.Name, err)
			}
		}
	}
	return nil
}

func (m *linuxRelayManager) CreateNetworkInterface(req CreateInterfaceRequest) (*RelayNodeInfo, error) {
	m.interfaceMu.Lock()
	defer m.interfaceMu.Unlock()
	info, err := m.createNetworkInterface(req)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	generation := m.interfaces[req.NetworkID].Generation
	m.mu.RUnlock()
	// Publish only after setup releases the kernel-operation lock. No Owner
	// callback can wait for kernel I/O through the observation lifetime map.
	if err := m.observations.publish(req.NetworkID, generation); err != nil {
		return nil, err
	}
	return info, nil
}

func (m *linuxRelayManager) createNetworkInterface(req CreateInterfaceRequest) (*RelayNodeInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.interfaces[req.NetworkID]; exists {
		return nil, fmt.Errorf("interface already exists for network %s", req.NetworkID)
	}

	ifName := m.cfg.InterfaceName(req.NetworkID)
	listenPort := m.allocateInterfaceListenPortLocked()
	if listenPort == 0 {
		return nil, fmt.Errorf("no available WireGuard interface listen port")
	}

	privKey, err := m.loadOrGenerateKey(req.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("keypair: %w", err)
	}
	pubKey := privKey.PublicKey()

	// Calculate relay IP (.1 in the subnet)
	relayIP, err := firstUsableIP(req.CIDR)
	if err != nil {
		return nil, fmt.Errorf("calculate relay IP: %w", err)
	}

	// Create WG interface via netlink.
	// Remove stale interface first (may exist from a previous forced stop).
	la := netlink.NewLinkAttrs()
	la.Name = ifName
	wgLink := &netlink.Wireguard{LinkAttrs: la}
	if existing, err := netlink.LinkByName(ifName); err == nil {
		logger.Warnf("removing stale WireGuard interface %s from previous run", ifName)
		if delErr := netlink.LinkDel(existing); delErr != nil {
			return nil, fmt.Errorf("delete stale interface %s: %w", ifName, delErr)
		}
	}
	if err := netlink.LinkAdd(wgLink); err != nil {
		return nil, fmt.Errorf("create interface %s: %w", ifName, err)
	}

	// Configure WG device
	port := listenPort
	err = m.client.ConfigureDevice(ifName, wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
	})
	if err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("configure device %s: %w", ifName, err)
	}

	// Assign IP address with /32 mask to prevent the kernel from auto-adding
	// the full CIDR connected route (e.g. 10.24.0.0/24) to the main table.
	// The CIDR route belongs only in the per-network table (table 1000).
	// An explicit /24 route with a high metric is added below for edge-host
	// peer reachability (ping debugging) without overriding more specific routes.
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(relayIP),
			Mask: net.CIDRMask(32, 32),
		},
	}
	link, _ := netlink.LinkByName(ifName)
	if err := netlink.AddrAdd(link, addr); err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("assign addr to %s: %w", ifName, err)
	}

	// Bring interface up
	if err := netlink.LinkSetUp(link); err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("bring up %s: %w", ifName, err)
	}

	// Allocate a per-network routing table for policy routing.
	// This prevents route conflicts when multiple networks use overlapping CIDRs:
	// each network's CIDR route lives in its own table, selected by ip rule.
	_, cidrNet, _ := net.ParseCIDR(req.CIDR)
	tableID, err := m.routeTables.Allocate(req.NetworkID)
	if err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("allocate route table for %s: %w", req.NetworkID, err)
	}

	// Add CIDR route to the per-network table (used by forwarded traffic).
	cidrRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       cidrNet,
		Scope:     netlink.SCOPE_LINK,
		Table:     int(tableID),
	}
	if err := netlink.RouteReplace(cidrRoute); err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("add cidr route to table %d for %s: %w", tableID, req.CIDR, err)
	}

	// Add ip rule: from <CIDR> lookup <tableID>.
	// This directs forwarded packets (matching the CIDR source) to the
	// per-network routing table.
	// Delete any stale rule from a previous run first (RuleAdd uses NLM_F_EXCL
	// and would fail with EEXIST if the rule already exists).
	rule := netlink.NewRule()
	rule.Src = cidrNet
	rule.Table = int(tableID)
	_ = netlink.RuleDel(rule) // best-effort cleanup; ignore "not found"
	if err := netlink.RuleAdd(rule); err != nil {
		netlink.LinkDel(wgLink)
		return nil, fmt.Errorf("add ip rule for %s table %d: %w", req.CIDR, tableID, err)
	}

	// TODO: When the edge node itself is also a peer member (has an assigned IP
	// in the same CIDR, e.g. 10.24.0.5 in addition to the relay IP 10.24.0.1),
	// the relayManager needs to handle this dual-role scenario:
	// - The edge's own peer traffic must use the relay WG interface for
	//   reaching other peers, but the current setup only assigns the relay IP.
	// - Policy rule `from <CIDR>` would match the edge's own peer IP as source,
	//   potentially causing routing loops or incorrect table lookups if the
	//   edge's peer IP is not properly accounted for.
	// - Consider adding the edge's peer IP as an additional address on the
	//   relay WG interface, or ensuring the edge's peer traffic is routed
	//   through the same relay path.

	// Add the CIDR route to the main table with a high metric so the edge
	// host itself can reach peer IPs (e.g. ping for debugging).  The high
	// metric ensures this route is a low-priority fallback: any more
	// specific route (e.g. policy routing via table 1000 for forwarded
	// traffic) takes precedence.
	cidrMainRoute := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       cidrNet,
		Scope:     netlink.SCOPE_LINK,
		Priority:  1000,
	}
	if err := netlink.RouteReplace(cidrMainRoute); err != nil {
		logger.Warnf("failed to add CIDR main table route for %s: %v", req.CIDR, err)
	}

	ni := &networkInterface{
		Generation:      uuid.NewString(),
		Name:            ifName,
		NetworkID:       req.NetworkID,
		PrivateKey:      privKey,
		PublicKey:       pubKey,
		ListenPort:      listenPort,
		AssignedIP:      relayIP,
		CIDR:            req.CIDR,
		ObservationOnly: req.ObservationOnly,
		routeTableID:    tableID,
		peerObserved:    make(map[string]*net.UDPAddr),
		peerInfos:       make(map[string]string),
	}
	m.interfaces[req.NetworkID] = ni

	// Start the forwarder for non-observation interfaces.
	// This provides the configured forwarding path between WireGuard peers.
	if !req.ObservationOnly {
		fwd, err := NewForwarder(m.cfg.ForwarderStrategy, ifName, req.CIDR, relayIP)
		if err != nil {
			logger.Warnf("forwarder init failed for %s: %v", ifName, err)
		} else {
			ni.forwarder = fwd
			if err := ni.forwarder.Start(); err != nil {
				logger.Warnf("forwarder start failed for %s: %v", ifName, err)
			}
		}
	}

	endpoint := m.cfg.PublicEndpoint
	if endpoint != "" {
		endpoint = endpointWithPort(endpoint, listenPort)
	}

	return &RelayNodeInfo{
		MemberID:      relayMemberID(req.NetworkID),
		PublicKey:     pubKey.String(),
		Endpoint:      endpoint,
		AssignedIP:    relayIP,
		ListenPort:    listenPort,
		PeerEndpoints: nil,
	}, nil
}

// allocateInterfaceListenPortLocked returns the first unused interface port.
// The old len(interfaces)-based allocation reused a live network's port after
// another network was deleted or switched relay modes.
//
// The caller must hold m.mu.
func (m *linuxRelayManager) allocateInterfaceListenPortLocked() int {
	base := m.cfg.ListenPortBase
	if base <= 0 {
		base = 58021
	}
	for port := base; port <= 65535; port++ {
		used := false
		for _, ni := range m.interfaces {
			if ni != nil && ni.ListenPort == port {
				used = true
				break
			}
		}
		if !used {
			return port
		}
	}
	return 0
}

func (m *linuxRelayManager) DeleteNetworkInterface(networkID string) error {
	m.interfaceMu.Lock()
	defer m.interfaceMu.Unlock()
	// Withdraw before any cleanup I/O, including cleanup of stale interfaces.
	// A blocked cleanup must never keep old raw observations authoritative.
	if err := m.observations.retire(networkID); err != nil {
		return err
	}
	return m.deleteNetworkInterface(networkID)
}

func (m *linuxRelayManager) deleteNetworkInterface(networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ni, ok := m.interfaces[networkID]
	if !ok {
		// Network not tracked in memory (e.g. after restart with stale
		// kernel state).  Still attempt to clean up the kernel interface
		// by computing its name from the network ID.
		ifName := m.cfg.InterfaceName(networkID)
		if link, err := netlink.LinkByName(ifName); err == nil {
			logger.Infof("cleaning up stale WireGuard interface %s for deleted network %s", ifName, networkID)
			if delErr := netlink.LinkDel(link); delErr != nil {
				logger.Warnf("failed to delete stale interface %s: %v", ifName, delErr)
				return delErr
			}
		}
		return nil
	}

	// Clean up policy routing: remove ip rule and release route table.
	m.cleanupPolicyRouting(ni)

	link, err := netlink.LinkByName(ni.Name)
	if err == nil {
		if delErr := netlink.LinkDel(link); delErr != nil {
			logger.Warnf("failed to delete interface %s for network %s: %v", ni.Name, networkID, delErr)
		}
	} else {
		logger.Warnf("interface %s for network %s not found in kernel (already removed?): %v", ni.Name, networkID, err)
	}
	if ni.forwarder != nil {
		_ = ni.forwarder.Stop()
	}
	// Clean up persisted rate limits for this network.
	if m.rateLimitStore != nil {
		if err := m.rateLimitStore.DeleteNetworkPeerRateLimits(context.Background(), networkID); err != nil {
			logger.Warnf("failed to clean up rate limits for network %s: %v", networkID, err)
		}
	}
	delete(m.interfaces, networkID)
	return nil
}

// cleanupPolicyRouting removes the ip rule and releases the route table
// assigned to a network interface. Safe to call multiple times.
// The caller must hold m.mu.
func (m *linuxRelayManager) cleanupPolicyRouting(ni *networkInterface) {
	if ni.routeTableID == 0 {
		return
	}
	_, cidrNet, err := net.ParseCIDR(ni.CIDR)
	if err == nil {
		rule := netlink.NewRule()
		rule.Src = cidrNet
		rule.Table = int(ni.routeTableID)
		if err := netlink.RuleDel(rule); err != nil {
			logger.Warnf("failed to delete ip rule for %s table %d: %v", ni.CIDR, ni.routeTableID, err)
		}
	}
	m.routeTables.Release(ni.NetworkID)
	ni.routeTableID = 0
}

// reconcileStaleInterfaces removes kernel WireGuard interfaces that are not
// tracked in m.interfaces.  Called during Start() to clean up leftovers from
// previous runs where DeleteNetworkInterface failed or was not reached (e.g.
// crash, network deletion error).  At startup m.interfaces is empty so every
// matching interface is stale.
func (m *linuxRelayManager) reconcileStaleInterfaces() {
	prefix := m.cfg.InterfacePrefix
	if prefix == "" {
		prefix = DefaultConfig().InterfacePrefix
	}
	prefixWithDash := prefix + "-"

	links, err := netlink.LinkList()
	if err != nil {
		logger.Warnf("reconcileStaleInterfaces: failed to list links: %v", err)
		return
	}

	m.mu.RLock()
	activeNames := make(map[string]bool, len(m.interfaces))
	for _, ni := range m.interfaces {
		activeNames[ni.Name] = true
	}
	m.mu.RUnlock()

	for _, link := range links {
		name := link.Attrs().Name
		if !strings.HasPrefix(name, prefixWithDash) {
			continue
		}
		if activeNames[name] {
			continue
		}
		logger.Infof("reconcileStaleInterfaces: deleting stale WireGuard interface %s", name)
		if err := netlink.LinkDel(link); err != nil {
			logger.Warnf("reconcileStaleInterfaces: failed to delete %s: %v", name, err)
		}
	}
}

func (m *linuxRelayManager) AddPeer(networkID string, peer PeerConfig) error {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	defaultRate := m.cfg.DefaultPeerRate
	defaultCeil := m.cfg.DefaultPeerCeil
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no interface for network %s", networkID)
	}

	pubKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("parse peer public key: %w", err)
	}

	_, allowedNet, err := net.ParseCIDR(peer.AssignedIP + "/32")
	if err != nil {
		return fmt.Errorf("parse peer allowed IP: %w", err)
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*allowedNet},
	}

	// If a last-known endpoint is available, configure it so the WG kernel
	// module can proactively initiate a handshake.  This is critical for
	// recovery after Edge restart: without it, the Edge must wait for the
	// peer's PersistentKeepalive to arrive, which may never happen if the
	// peer's NAT mapping has expired during the downtime.
	if peer.Endpoint != "" {
		if addr, err := net.ResolveUDPAddr("udp", peer.Endpoint); err == nil {
			peerCfg.Endpoint = addr
		}
	}

	if err := m.client.ConfigureDevice(ni.Name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return err
	}
	ni.mu.Lock()
	ni.peerInfos[peer.PublicKey] = peer.AssignedIP
	ni.mu.Unlock()

	// Apply rate limit for the newly added peer.
	// Strategy: start with the config default (if any), then override with
	// a persisted specific limit if one exists in the cache. This ensures
	// that peers with individually configured limits keep them across
	// edge restarts, while peers without specific limits fall back to
	// the edge-wide default.
	if ni.forwarder != nil {
		// 1. Apply default from config (if configured).
		if defaultRate > 0 {
			ceil := defaultCeil
			if ceil == 0 {
				ceil = defaultRate
			}
			if err := ni.forwarder.SetPeerRateLimit(peer.AssignedIP, defaultRate, ceil); err != nil {
				logger.Warnf("failed to apply default rate limit for %s/%s: %v", networkID, peer.AssignedIP, err)
			}
		}
		// 2. Override with persisted specific limit (if any).
		cacheKey := networkID + "/" + peer.AssignedIP
		m.mu.RLock()
		specific, hasSpecific := m.rateLimitCache[cacheKey]
		m.mu.RUnlock()
		if hasSpecific {
			if err := ni.forwarder.SetPeerRateLimit(peer.AssignedIP, specific.Rate, specific.Ceil); err != nil {
				logger.Warnf("failed to apply persisted rate limit for %s/%s: %v", networkID, peer.AssignedIP, err)
			}
		}
	}
	return nil
}

func (m *linuxRelayManager) RemovePeer(networkID string, publicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ni, ok := m.interfaces[networkID]
	if !ok {
		return nil
	}
	pubKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	ni.mu.Lock()
	delete(ni.peerInfos, publicKey)
	delete(ni.peerObserved, publicKey)
	ni.mu.Unlock()

	// Clean up is handled by peerObserved/peerInfos deletion above.

	remove := true
	return m.client.ConfigureDevice(ni.Name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pubKey,
			Remove:    remove,
		}},
	})
}

func (m *linuxRelayManager) GetObservedEndpoints(networkID string) ([]ObservedEndpoint, error) {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no interface for network %s", networkID)
	}

	startedAt := time.Now()
	dev, err := m.client.Device(ni.Name)
	if err != nil {
		return nil, fmt.Errorf("get device %s: %w", ni.Name, err)
	}
	sampledAt := time.Now()

	var endpoints []ObservedEndpoint
	for _, peer := range dev.Peers {
		// Only log observations for peers that have actually handshaked;
		// zero-value last_handshake peers produce no diagnostic signal.
		if !peer.LastHandshakeTime.IsZero() {
			logger.Debugf("WireGuard UDP observation: network=%s interface=%s public_key=%s observed_endpoint=%s observer_listen_port=%d last_handshake=%s source=wgctrl", networkID, ni.Name, peer.PublicKey.String(), peerEndpointString(peer.Endpoint), dev.ListenPort, peer.LastHandshakeTime.Format(time.RFC3339))
		}
		m.mu.RLock()
		if current := m.interfaces[networkID]; current == ni && peer.Endpoint != nil {
			ni.mu.Lock()
			// Always update peerObserved for all WG peers, including
			// observation-only interfaces where peerInfos is not populated.
			// This is required for same-NAT detection (DetectSameNATPeers).
			ni.peerObserved[peer.PublicKey.String()] = cloneUDPAddr(peer.Endpoint)
			ni.mu.Unlock()
		}
		m.mu.RUnlock()
		endpoints = append(endpoints, ObservedEndpoint{
			InterfaceGeneration: ni.Generation, StartedAt: startedAt, SampledAt: sampledAt,
			PublicKey:         peer.PublicKey.String(),
			Endpoint:          peer.Endpoint,
			LastHandshakeTime: peer.LastHandshakeTime,
			RxBytes:           peer.ReceiveBytes,
		})
	}
	return endpoints, nil
}

func peerEndpointString(addr *net.UDPAddr) string {
	if addr == nil {
		return "<none>"
	}
	return addr.String()
}

// shortKey returns the first 8 chars of a public key for log readability.
func shortKey(publicKey string) string {
	if len(publicKey) > 8 {
		return publicKey[:8] + "…"
	}
	return publicKey
}

func (m *linuxRelayManager) GetRelayNodeInfo(networkID string) (*RelayNodeInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ni, ok := m.interfaces[networkID]
	if !ok {
		return nil, fmt.Errorf("no interface for network %s", networkID)
	}

	endpoint := m.cfg.PublicEndpoint
	if endpoint != "" {
		endpoint = endpointWithPort(endpoint, ni.ListenPort)
	}

	return &RelayNodeInfo{
		MemberID:      relayMemberID(networkID),
		PublicKey:     ni.PublicKey.String(),
		Endpoint:      endpoint,
		AssignedIP:    ni.AssignedIP,
		ListenPort:    ni.ListenPort,
		PeerEndpoints: nil,
	}, nil
}

func (m *linuxRelayManager) Start() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.running {
		return nil
	}

	// Non-blocking sysctl check — warn but don't fail.
	if warnings := CheckRequiredSysctl(); len(warnings) > 0 {
		for _, w := range warnings {
			logger.Warnf("sysctl: %s", w.Message)
		}
	}

	if m.client == nil {
		client, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("create wgctrl client: %w", err)
		}
		m.client = client
	}

	// Clean up stale nftables rules from previous runs.
	// At startup m.interfaces is empty, so all existing yat_relay rules are stale.
	// This MUST run before reconcileStaleInterfaces to ensure a clean slate:
	// reconcileStaleInterfaces deletes kernel WG interfaces but cannot clean up
	// nftables rules (it doesn't know which rules belong to which interface).
	// Without this cleanup, stale rules for deleted interfaces persist and
	// new forwarders may fail to install correct rules.
	if err := cleanupNFTTable(); err != nil {
		logger.Warnf("startup: failed to cleanup stale nftables table: %v", err)
	}

	// Reconcile stale kernel interfaces from previous runs.
	// At startup m.interfaces is empty, so any existing WG interface
	// with the configured prefix is stale and should be removed.
	m.reconcileStaleInterfaces()

	m.stopCh = make(chan struct{})
	m.running = true
	m.wg.Add(1)
	go m.observeLoop(m.stopCh)
	return nil
}

func (m *linuxRelayManager) Stop() error {
	var stopCh chan struct{}

	// Phase 1: signal goroutines to stop (release lifecycleMu before waiting).
	m.lifecycleMu.Lock()
	if !m.running {
		m.lifecycleMu.Unlock()
		return nil
	}
	stopCh = m.stopCh
	m.running = false
	m.stopCh = nil
	m.lifecycleMu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	m.wg.Wait()

	// Phase 2: clean up interfaces, forwarders, and policy routing.
	m.interfaceMu.Lock()
	defer m.interfaceMu.Unlock()
	if err := m.observations.retireAll(); err != nil {
		return err
	}
	m.mu.Lock()
	for netID, ni := range m.interfaces {
		if ni.forwarder != nil {
			_ = ni.forwarder.Stop()
		}
		m.cleanupPolicyRouting(ni)
		link, err := netlink.LinkByName(ni.Name)
		if err == nil {
			netlink.LinkDel(link)
		}
		delete(m.interfaces, netID)
	}
	m.mu.Unlock()

	// Phase 3: remove the yat_relay nftables table (all forwarders stopped).
	if err := cleanupNFTTable(); err != nil {
		logger.Warnf("relay manager: failed to cleanup nftables table: %v", err)
	}

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	return nil
}

func endpointWithPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return ""
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

func cloneUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), value.IP...), Port: value.Port, Zone: value.Zone}
}

func (m *linuxRelayManager) observeLoop(stopCh chan struct{}) {
	defer m.wg.Done()

	interval := time.Duration(m.cfg.ObserveInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	heartbeatTimeout := time.Duration(m.cfg.HeartbeatTimeout) * time.Second
	if heartbeatTimeout <= 0 {
		heartbeatTimeout = 300 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.mu.RLock()
			networks := make([]string, 0, len(m.interfaces))
			for netID := range m.interfaces {
				networks = append(networks, netID)
			}
			endpointCallback := m.OnEndpointChange
			timeoutCallback := m.OnHeartbeatTimeout
			observationCallback := m.onObservation
			m.mu.RUnlock()

			// Log forwarder stats periodically.
			m.mu.RLock()
			for _, netID := range networks {
				ni := m.interfaces[netID]
				if ni != nil && ni.forwarder != nil {
					s := ni.forwarder.Stats()
					logger.Infof("forwarder stats: network=%s strategy=%s forwarded=%d dropped=%d errors=%d",
						netID, ni.forwarder.Name(),
						s.Forwarded, s.Dropped, s.Errors)
				}
			}
			m.mu.RUnlock()

			now := time.Now()
			for _, netID := range networks {
				endpoints, err := m.GetObservedEndpoints(netID)
				if err != nil {
					continue
				}

				for _, ep := range endpoints {
					// Raw samples include never-handshaked/reset peers; independent of legacy liveness.
					if observationCallback != nil {
						observationCallback(observationFromEndpoint(netID, ep))
					}
					// Liveness detection via handshake age (stateless).
					//
					// boringtun rekey cycle: REJECT_AFTER_TIME(180s) + next PK(25s)
					// + 1 RTT ≈ 210s peak. HeartbeatTimeout=300s tolerates this.
					//
					// Handshake age is the direct liveness signal:
					//   - Handshake fresh (≤ timeout) → peer alive
					//   - Handshake stale   (> timeout) → peer offline
					if ep.LastHandshakeTime.IsZero() {
						// Never handshaked — skip liveness check.
						continue
					}

					handshakeAge := now.Sub(ep.LastHandshakeTime)

					if handshakeAge <= heartbeatTimeout {
						logger.Debugf("WireGuard liveness: network=%s peer=%s handshake_age=%s rx_bytes=%d endpoint=%s",
							netID, shortKey(ep.PublicKey),
							handshakeAge.Round(time.Second),
							ep.RxBytes,
							peerEndpointString(ep.Endpoint))

						if endpointCallback != nil && ep.Endpoint != nil {
							endpointCallback(netID, ep.PublicKey, ep.Endpoint.String())
						}
					} else {
						logger.Infof("WireGuard liveness timeout: network=%s peer=%s handshake_age=%s (> %s) rx_bytes=%d",
							netID, shortKey(ep.PublicKey),
							handshakeAge.Round(time.Second),
							heartbeatTimeout.Round(time.Second),
							ep.RxBytes)
						if timeoutCallback != nil {
							timeoutCallback(netID, ep.PublicKey)
						}
					}
				}
				// Reconcile against member storage on every poll. Deduplicating
				// here loses unchanged endpoints after rejoin or a failed DB write.
				// Empty polls never clear the last persisted observation.
			}
		}
	}
}

// loadOrGenerateKey loads a private key from disk or generates a new one.
func (m *linuxRelayManager) loadOrGenerateKey(networkID string) (wgtypes.Key, error) {
	if m.cfg.KeyDir == "" {
		return wgtypes.GeneratePrivateKey()
	}

	keyPath := filepath.Join(m.cfg.KeyDir, networkID+".key")

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) > 0 {
		return wgtypes.ParseKey(string(data))
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}

	if err := os.WriteFile(keyPath, []byte(key.String()), 0600); err != nil {
		return wgtypes.Key{}, fmt.Errorf("persist key: %w", err)
	}
	return key, nil
}

// firstUsableIP returns the first usable host IP in the CIDR (network + 1).
func firstUsableIP(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 supported")
	}
	// Increment to get first host address
	ip[3]++
	return ip.String(), nil
}

func (m *linuxRelayManager) LocalSubnets() []net.IPNet {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	out := make([]net.IPNet, len(m.cfg.ForbiddenSubnets))
	copy(out, m.cfg.ForbiddenSubnets)
	return out
}

func (m *linuxRelayManager) SuggestCIDRs(existingCIDRs []string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	return GenerateSuggestedCIDRs(m.cfg.ForbiddenSubnets, existingCIDRs)
}

// DetectSameNATPeers groups peers by their observed public IP and returns
// all pairs that share the same IP.  Two peers behind the same public IP
// are very likely behind the same NAT and can potentially communicate
// directly over the LAN.
//
// When a peer's observed IP is a private/reserved address it means the
// peer is on the same LAN as the Edge itself.  All such peers are
// grouped under a synthetic key so they are detected as same-NAT pairs
// regardless of which specific private IP each one happens to use.
func (m *linuxRelayManager) DetectSameNATPeers(networkID string) []SameNATPair {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok {
		return nil
	}

	// Group peer public keys by observed IP.
	// Private IPs are collapsed into a single group because those peers
	// are all on the Edge's local network and can reach each other
	// directly without traversing a NAT.
	const lanGroupKey = "lan"
	ni.mu.Lock()
	byIP := make(map[string][]string)
	for pubKey, addr := range ni.peerObserved {
		if addr == nil {
			continue
		}
		groupKey := addr.IP.String()
		if addr.IP.IsPrivate() || addr.IP.IsLoopback() {
			groupKey = lanGroupKey
		}
		byIP[groupKey] = append(byIP[groupKey], pubKey)
	}
	ni.mu.Unlock()

	// Collect pairs from groups with 2+ peers.
	var pairs []SameNATPair
	for ip, keys := range byIP {
		if len(keys) < 2 {
			continue
		}
		sort.Strings(keys)
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				pairs = append(pairs, SameNATPair{
					PeerA:    keys[i],
					PeerB:    keys[j],
					PublicIP: ip,
				})
			}
		}
	}
	return pairs
}

func (m *linuxRelayManager) GetNetworkRuntimeInfo(networkID string) (*NetworkRuntimeInfo, error) {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("network interface not found: %s", networkID)
	}

	info := &NetworkRuntimeInfo{
		InterfaceName: ni.Name,
		RouteTableID:  ni.routeTableID,
	}
	if ni.forwarder != nil {
		info.ForwarderStrategy = ni.forwarder.Name()
		info.ForwarderStats = ni.forwarder.Stats()
		info.PeerStats = ni.forwarder.PeerStats()
		info.RateLimits = ni.forwarder.PeerRateLimits()
	}
	return info, nil
}

func (m *linuxRelayManager) SetPeerRateLimit(networkID, peerIP string, rate, ceil uint64) error {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("network interface not found: %s", networkID)
	}
	if ni.forwarder == nil {
		return fmt.Errorf("forwarder not initialized for network: %s", networkID)
	}
	if err := ni.forwarder.SetPeerRateLimit(peerIP, rate, ceil); err != nil {
		return err
	}
	// Update cache.
	cacheKey := networkID + "/" + peerIP
	m.mu.Lock()
	m.rateLimitCache[cacheKey] = PeerRateLimitInfo{Rate: rate, Ceil: ceil}
	m.mu.Unlock()
	// Persist to store (best-effort; log but don't fail the operation).
	if m.rateLimitStore != nil {
		if err := m.rateLimitStore.SavePeerRateLimit(context.Background(), networkID, peerIP, rate, ceil); err != nil {
			logger.Warnf("failed to persist rate limit for %s/%s: %v", networkID, peerIP, err)
		}
	}
	return nil
}

func (m *linuxRelayManager) RemovePeerRateLimit(networkID, peerIP string) error {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("network interface not found: %s", networkID)
	}
	if ni.forwarder == nil {
		return fmt.Errorf("forwarder not initialized for network: %s", networkID)
	}
	if err := ni.forwarder.RemovePeerRateLimit(peerIP); err != nil {
		return err
	}
	// Update cache.
	cacheKey := networkID + "/" + peerIP
	m.mu.Lock()
	delete(m.rateLimitCache, cacheKey)
	m.mu.Unlock()
	// Remove from store.
	if m.rateLimitStore != nil {
		if err := m.rateLimitStore.DeletePeerRateLimit(context.Background(), networkID, peerIP); err != nil {
			logger.Warnf("failed to remove persisted rate limit for %s/%s: %v", networkID, peerIP, err)
		}
	}
	return nil
}

// GetPeerRateLimit returns the configured rate limit for a specific peer.
func (m *linuxRelayManager) GetPeerRateLimit(networkID, peerIP string) (PeerRateLimitInfo, bool) {
	m.mu.RLock()
	ni, ok := m.interfaces[networkID]
	m.mu.RUnlock()
	if !ok || ni.forwarder == nil {
		return PeerRateLimitInfo{}, false
	}
	limits := ni.forwarder.PeerRateLimits()
	info, found := limits[peerIP]
	return info, found
}

// SetPeerRateLimitStore injects the persistence layer for rate limits.
func (m *linuxRelayManager) SetPeerRateLimitStore(store PeerRateLimitStore) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimitStore = store
}

// RestorePeerRateLimits re-applies persisted rate limits to all active
// network interfaces. Call once after all networks have been created.
// Also populates the in-memory cache so that AddPeer can look up
// specific limits when peers reconnect.
func (m *linuxRelayManager) RestorePeerRateLimits() error {
	if m.rateLimitStore == nil {
		return nil
	}
	records, err := m.rateLimitStore.LoadPeerRateLimits(context.Background())
	if err != nil {
		return fmt.Errorf("load peer rate limits: %w", err)
	}
	// Populate cache.
	m.mu.Lock()
	for _, r := range records {
		cacheKey := r.NetworkID + "/" + r.PeerIP
		m.rateLimitCache[cacheKey] = PeerRateLimitInfo{Rate: r.Rate, Ceil: r.Ceil}
	}
	m.mu.Unlock()
	// Apply to active interfaces.
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range records {
		ni, ok := m.interfaces[r.NetworkID]
		if !ok || ni.forwarder == nil {
			continue
		}
		if err := ni.forwarder.SetPeerRateLimit(r.PeerIP, r.Rate, r.Ceil); err != nil {
			logger.Warnf("failed to restore rate limit for %s/%s: %v", r.NetworkID, r.PeerIP, err)
		}
	}
	if len(records) > 0 {
		logger.Infof("restored %d peer rate limit(s) from storage", len(records))
	}
	return nil
}
