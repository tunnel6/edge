package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
	logger "icool.io/yat/edge/pkg/log"
)

type MeshCoordinator struct {
	NetworkManager *NetworkManager
	MemberManager  *MemberManager
	RelayManager   relay.RelayManager
	// relayForwardingEnabled gates business relay creation. The observation
	// interface may still be active when this is false (disabled networks).
	relayForwardingEnabled bool

	mu              sync.Mutex
	lifecycleMu     sync.Mutex
	stopCh          chan struct{}
	running         bool
	wg              sync.WaitGroup
	memberRuntimeMu sync.Mutex
	retiredPeerKeys map[string]map[string]bool

	// lanEndpoints stores per-network, per-publicKey LAN endpoints reported
	// by clients.  Used to inject same-LAN peer endpoints into snapshots so
	// that clients can establish direct LAN paths.
	lanEndpointsMu sync.Mutex
	lanEndpoints   map[string]map[string][]string // networkID → publicKey → []"LAN_IP:WG_PORT" (candidates)

	// lanGatherPusher is a callback that sends gather requests to clients.
	// When set, detectAndStoreSameNAT uses it to request LAN endpoint
	// reports from same-NAT peer pairs.
	lanGatherPusher func(networkID, clientID string) error

	// onSessionCreated removed (S5-B2): was only used by EnsureDirectSessions.

	// sameNATPairLastPush throttles same-NAT gather pushes per peer pair
	// so that detectAndStoreSameNAT does not re-push every maintenance tick
	// before the client has had time to respond.  Key = "networkID:pkA:pkB"
	// (public keys sorted lexicographically), value = last push time.
	sameNATPairLastPushMu sync.Mutex
	sameNATPairLastPush   map[string]time.Time
}

// Create
func NewMeshCoordinator() *MeshCoordinator {
	networkManager := NewNetworkManager()
	memberManager := NewMemberManager(networkManager)

	return &MeshCoordinator{
		NetworkManager:         networkManager,
		MemberManager:          memberManager,
		relayForwardingEnabled: true,
	}
}

// SetRelayForwardingEnabled controls business relay listeners independently of
// the Edge WG observation runtime. Observation remains available when false.
func (c *MeshCoordinator) SetRelayForwardingEnabled(enabled bool) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	c.relayForwardingEnabled = enabled
	c.mu.Unlock()
	return c.reconcileNetworks()
}

func (c *MeshCoordinator) RelayForwardingReady() bool {
	return c != nil && c.RelayManager != nil && c.isRelayForwardingEnabled()
}

func (c *MeshCoordinator) isRelayForwardingEnabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	enabled := c.relayForwardingEnabled
	c.mu.Unlock()
	return enabled
}

// Start
func (c *MeshCoordinator) Start() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	if c.RelayManager != nil {
		if err := c.RelayManager.Start(); err != nil {
			return fmt.Errorf("start relay manager: %w", err)
		}
	}

	c.stopCh = make(chan struct{})
	c.running = true
	c.wg.Add(1)
	go c.maintenanceLoop(c.stopCh)
	return nil
}

// Stop
func (c *MeshCoordinator) Stop() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.NetworkManager.stopPathOwner()
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}

	close(c.stopCh)
	c.running = false
	c.stopCh = nil
	relayManager := c.RelayManager
	c.mu.Unlock()
	c.wg.Wait()

	if relayManager != nil {
		if err := relayManager.Stop(); err != nil {
			logger.Warnf("failed to stop relay manager: %v", err)
		}
	}

	return nil
}

// Check
func (c *MeshCoordinator) maintenanceLoop(stopCh <-chan struct{}) {
	defer c.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			// Session timeout/cleanup removed (S5-B2): session state machine inert.

			// Same-NAT detection: only push LAN gather to peer pairs
			// that share the same observed public IP (same NAT/LAN).
			c.detectAndStoreSameNAT()
		}
	}
}

func (c *MeshCoordinator) SetStorage(s Storage) {
	if s == nil {
		return
	}
	c.NetworkManager.SetStorage(s)
	c.MemberManager.SetStorage(s)
	// PeerSessionManager does not persist to storage — sessions are ephemeral.
}

// SetPeerSessionStateChangeCallback removed (S5-B2): session state machine inert.

// Status
func RecoverFromStorage(ctx context.Context, c *MeshCoordinator, s Storage) error {
	if c == nil || s == nil {
		return nil
	}

	snap, err := s.LoadSnapshot(ctx)
	if err != nil {
		return err
	}

	return pathSourceChange(c.NetworkManager, func() error {
		nm := c.NetworkManager
		nm.mu.Lock()
		for _, n := range snap.Networks {
			if n == nil {
				continue
			}
			nm.networks[n.ID] = n
			n.pathPolicyRevision = 1
		}
		nm.mu.Unlock()

		mm := c.MemberManager
		mm.mu.Lock()
		for _, m := range snap.Members {
			if m == nil {
				continue
			}
			rotatePathMembership(m)
			// Revocation is durable and independent of the legacy presence reset below.
			m.pathRevoked = m.pathRevoked || m.Status == MemberStatusLeaved || m.Status == MemberStatusRemoved
			// Backward-compat migration: older Edge versions stored member.ClientID
			// as userID-deviceID (e.g. "3-device-xxx").  The canonical format is
			// now bare deviceID.  Strip the userID prefix on load so that all
			// in-memory maps use the new format consistently.
			if idx := strings.Index(m.ClientID, "-"); idx > 0 && !strings.HasPrefix(m.ClientID, "device-") {
				m.ClientID = m.ClientID[idx+1:]
			}

			mm.members[m.ID] = m
			mm.networkMembers[m.NetworkID] = append(mm.networkMembers[m.NetworkID], m.ID)
			if mm.clientMembers[m.ClientID] == nil {
				mm.clientMembers[m.ClientID] = make(map[string]string)
			}
			mm.clientMembers[m.ClientID][m.NetworkID] = m.ID

			if mm.allocatedIPs[m.NetworkID] == nil {
				mm.allocatedIPs[m.NetworkID] = make(map[string]bool)
			}
			mm.allocatedIPs[m.NetworkID][m.IP] = true

			// Endpoint is loaded from SQLite and used by addExistingPeersToRelay
			// to configure the WG relay peer endpoint, enabling the kernel to
			// proactively initiate handshakes after Edge restart.
			// LANEndpoint and ObservedAt are loaded but not actively used for
			// recovery — they are repopulated by gather flow and observation.

			// Status is ephemeral: after an Edge restart no client is
			// connected, so always reset to Active (member exists but offline).
			// The stored value may be stale (e.g. Online from before the restart)
			// because online/offline transitions are not always persisted.
			// This observation ledger is restored via WG handshake evidence.
			// Product control presence is projected separately at read time.
			if m.Status != MemberStatusActive {
				m.Status = MemberStatusActive
				m.UpdatedAt = time.Now()
				// Persist the reset so SQLite doesn't retain stale "online".
				if s != nil {
					if err := s.UpdateMember(ctx, m); err != nil {
						logger.Warnf("failed to persist status reset for member %s: %v", m.ID, err)
					}
				}
			}
		}
		mm.mu.Unlock()

		return nil
	})
}

// Create
func (c *MeshCoordinator) CreateNetwork(req *CreateNetworkRequest) (*Network, error) {
	return c.NetworkManager.CreateNetwork(req)
}

// Get
func (c *MeshCoordinator) GetNetwork(networkID string) (*Network, error) {
	return c.NetworkManager.GetNetwork(networkID)
}

func (c *MeshCoordinator) ListNetworks() []*Network {
	return c.NetworkManager.ListNetworks()
}

// Delete
func (c *MeshCoordinator) DeleteNetwork(networkID string) error {
	_, err := c.NetworkManager.GetNetwork(networkID)
	relayRuntime := err == nil && c.RelayManager != nil

	if err := c.NetworkManager.DeleteNetwork(networkID); err != nil {
		return err
	}
	if relayRuntime {
		if err := c.RelayManager.DeleteNetworkInterface(networkID); err != nil {
			logger.Warnf("failed to delete relay interface for network %s: %v", networkID, err)
		}
	}

	// Clean up in-memory LAN endpoint map for this network.
	c.lanEndpointsMu.Lock()
	delete(c.lanEndpoints, networkID)
	c.lanEndpointsMu.Unlock()

	// Clear persisted LAN endpoints in SQLite.  LAN endpoints are ephemeral
	// (not restored on restart), but clearing them prevents stale values from
	// lingering in the database after network deletion.
	if c.MemberManager != nil {
		if err := c.MemberManager.ClearNetworkLANEndpoints(networkID); err != nil {
			logger.Warnf("failed to clear LAN endpoints for deleted network %s: %v", networkID, err)
		}
	}

	return nil
}

func (c *MeshCoordinator) JoinNetwork(req *JoinNetworkRequest) (*NetworkMember, error) {
	t0 := time.Now()
	c.memberRuntimeMu.Lock()
	defer c.memberRuntimeMu.Unlock()
	logger.Infof("[JoinPerf] network_id=%s memberRuntimeMu acquired in %v", req.NetworkID, time.Since(t0))

	t1 := time.Now()
	previousKey := c.MemberManager.clientPublicKey(req.ClientID, req.NetworkID)
	member, err := c.MemberManager.JoinNetwork(req)
	logger.Infof("[JoinPerf] network_id=%s MemberManager.JoinNetwork elapsed=%v", req.NetworkID, time.Since(t1))
	if err != nil {
		return nil, err
	}
	if c.RelayManager == nil || member.PublicKey == "" || member.PublicKey == req.ClientID {
		return member, nil
	}
	if c.retiredPeerKeys == nil {
		c.retiredPeerKeys = make(map[string]map[string]bool)
	}
	if previousKey != "" && previousKey != req.ClientID && previousKey != member.PublicKey {
		if c.retiredPeerKeys[member.ID] == nil {
			c.retiredPeerKeys[member.ID] = make(map[string]bool)
		}
		c.retiredPeerKeys[member.ID][previousKey] = true
	}
	// Persisted joins remain idempotent when runtime setup fails. Retain old
	// keys until registration succeeds so the next join can retry cleanup.
	t2 := time.Now()
	if err := c.reconcileNetwork(req.NetworkID); err != nil {
		return nil, fmt.Errorf("reconcile joined peer: %w", err)
	}
	logger.Infof("[JoinPerf] network_id=%s reconcileNetwork elapsed=%v", req.NetworkID, time.Since(t2))
	for key := range c.retiredPeerKeys[member.ID] {
		if key != member.PublicKey {
			// Skip placeholder keys (e.g. clientId used as publicKey in proxy-add).
			// These were never added to the relay interface.
			if _, err := wgtypes.ParseKey(key); err != nil {
				logger.Debugf("skipping retired placeholder key %s for member %s: %v", key, member.ID, err)
				delete(c.retiredPeerKeys[member.ID], key)
				continue
			}
			if err := c.RelayManager.RemovePeer(req.NetworkID, key); err != nil {
				return nil, fmt.Errorf("remove retired peer: %w", err)
			}
		}
		delete(c.retiredPeerKeys[member.ID], key)
	}
	delete(c.retiredPeerKeys, member.ID)
	logger.Infof("[JoinPerf] network_id=%s total elapsed=%v", req.NetworkID, time.Since(t0))
	return member, nil
}

// Set
func (c *MeshCoordinator) SetMemberOnline(memberID string) error {
	return c.MemberManager.SetMemberOnline(memberID)
}

// SetMemberOffline marks a member as leaved (requires explicit rejoin).
func (c *MeshCoordinator) SetMemberOffline(memberID string) error {
	return c.MemberManager.SetMemberOffline(memberID)
}

// SetMemberDisconnected marks only the current network membership temporarily
// offline, preserving its membership and path-coordination eligibility.
func (c *MeshCoordinator) SetMemberDisconnected(memberID string) error {
	return c.MemberManager.SetMemberDisconnected(memberID)
}

// Remove
func (c *MeshCoordinator) RemoveMember(memberID string) error {
	return c.MemberManager.RemoveMember(memberID)
}

// HandleDeviceDisconnect resets the device's legacy WG observation state to
// Active without revoking membership. Product presence is projected separately
// from the current control session. Leaved is reserved for explicit leave.
func (c *MeshCoordinator) HandleDeviceDisconnect(deviceID string) error {
	return c.MemberManager.SetClientMembersDisconnected(deviceID)
}

// HandleDeviceConnect does not change WG observation state. Product control
// presence follows the current session independently of this compatibility API.
func (c *MeshCoordinator) HandleDeviceConnect(deviceID string) int {
	return c.MemberManager.SetClientMembersConnected(deviceID)
}

// SuggestCIDRs delegates to the relay manager's suggestion engine.
func (c *MeshCoordinator) SuggestCIDRs(existingCIDRs []string) []string {
	if c.RelayManager == nil {
		return nil
	}
	return c.RelayManager.SuggestCIDRs(existingCIDRs)
}

func (c *MeshCoordinator) ListNetworkMembers(networkID string) []*NetworkMember {
	return c.MemberManager.ListNetworkMembers(networkID)
}

func (c *MeshCoordinator) ListOnlineMembers(networkID string) []*NetworkMember {
	return c.MemberManager.ListOnlineMembers(networkID)
}

func (c *MeshCoordinator) GetClientMember(clientID, networkID string) (*NetworkMember, error) {
	return c.MemberManager.GetClientMember(clientID, networkID)
}

// CreatePeerSession, GetPeerSession, StartGatheringPeerSession,
// StartPunchingPeerSession, StartEstablishingPeerSession,
// MarkSessionConnected, UpdatePeerSessionEndpoint, MarkSessionFailed,
// MarkSessionClosed removed (S5-B2): session state machine inert.

// Get
func (c *MeshCoordinator) GetNetworkOverview(networkID string) (*NetworkOverview, error) {
	network, members, err := c.MemberManager.pathOverviewSnapshot(networkID)
	if err != nil {
		return nil, err
	}

	overview := &NetworkOverview{
		Network:   network,
		Members:   members,
		RelayNode: c.GetRelayNodeInfo(networkID),
	}
	// 从 relay node 或 relay manager 获取 Edge 公网端点，供客户端 NAT 推断。
	if overview.RelayNode != nil && overview.RelayNode.Endpoint != "" {
		overview.EdgePublicEndpoint = overview.RelayNode.Endpoint
	}
	// Inject stored LAN endpoint candidates for same-NAT direct path optimization.
	overview.LANPeerEndpoints = c.GetLANPeerEndpointCandidates(networkID)
	return overview, nil
}

type NetworkOverview struct {
	Network            *Network
	Members            []*NetworkMember
	RelayNode          *relay.RelayNodeInfo
	EdgePublicEndpoint string              // Edge WG observation interface 的公网地址 (ip:port)
	LANPeerEndpoints   map[string][]string // publicKey → []"LAN_IP:WG_PORT" candidates for same-NAT peers
	PathAuthorityEpoch string              // populated only by the gated coordination owner
	PathPairs          []*fbMsg.WGPathPairRuntimeInfoT
	// Revision and RevisionEpoch are assigned by the handler's Edge-owned
	// runtime sequencer immediately before serializing a snapshot.
	Revision      uint64
	RevisionEpoch string
}

// MarkSessionFailed, MarkSessionClosed removed (S5-B2): session state machine inert.

// EnsureDirectSessions, RecoverFailedSessionsForObserver and directSessionID
// removed (S5-B2): old session mechanism was dead code — clients only accept
// "lan:" prefixed gather, "auto-" sessions were always dropped.

// GetRelayManager returns the underlying relay manager, or nil if not set.
func (c *MeshCoordinator) GetRelayManager() relay.RelayManager {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.RelayManager
}

func (c *MeshCoordinator) SetRelayManager(rm relay.RelayManager) {
	if c == nil {
		return
	}
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	// A managed authority binds the relay source chosen at construction.
	// Dependency reassembly ends that lifetime before publishing a new source.
	c.NetworkManager.stopPathOwner()
	c.RelayManager = rm

	// Propagate the edge's local physical subnets to the NetworkManager so
	// that CreateNetwork can reject CIDRs that would conflict with the host.
	if rm != nil {
		c.NetworkManager.SetForbiddenSubnets(rm.LocalSubnets())
	}

	if err := c.reconcileNetworks(); err != nil {
		logger.Warnf("failed to reconcile WireGuard topology: %v", err)
	}

	// Restore persisted per-peer rate limits after all network interfaces
	// have been created.
	if rm != nil {
		if err := rm.RestorePeerRateLimits(); err != nil {
			logger.Warnf("failed to restore peer rate limits: %v", err)
		}
	}
}

func (c *MeshCoordinator) reconcileNetworks() error {
	if c.RelayManager == nil {
		logger.Debug("reconcileNetworks: RelayManager is nil, skipping")
		return nil
	}
	networks := c.NetworkManager.ListNetworks()
	logger.Debugf("reconcileNetworks: reconciling %d networks", len(networks))
	var errs []error
	for _, network := range networks {
		logger.Debugf("reconcileNetworks: processing network %s", network.ID)
		if err := c.reconcileNetwork(network.ID); err != nil {
			logger.Warnf("reconcileNetworks: network %s failed: %v", network.ID, err)
			errs = append(errs, fmt.Errorf("network %s: %w", network.ID, err))
		}
		logger.Debugf("reconcileNetworks: network %s done", network.ID)
	}
	return errors.Join(errs...)
}

func (c *MeshCoordinator) reconcileNetwork(networkID string) error {
	network, err := c.NetworkManager.GetNetwork(networkID)
	if err != nil {
		return err
	}
	if networkUsesRelay(network) && c.RelayForwardingReady() {
		return c.ensureRelayForNetwork(networkID)
	}
	if err := c.removeRelayMembers(networkID); err != nil {
		return err
	}
	if c.RelayManager != nil {
		return c.ensureObservationForNetwork(networkID)
	}
	return nil
}

// CreateNetworkWithRelay creates a network and registers the edge relay peer.
func (c *MeshCoordinator) CreateNetworkWithRelay(req *CreateNetworkRequest) (*Network, *relay.RelayNodeInfo, error) {
	network, err := c.NetworkManager.CreateNetwork(req)
	if err != nil {
		return nil, nil, err
	}

	if c.RelayManager == nil {
		if !networkUsesRelay(network) {
			return network, nil, nil
		}
		if network.RelayMode == RelayModeForce {
			if rollbackErr := c.rollbackCreatedNetwork(network.ID); rollbackErr != nil {
				return nil, nil, fmt.Errorf("force relay mode requires an available edge relay runtime: %w (rollback failed: %v)", errForceRelayRuntimeUnavailable, rollbackErr)
			}
			return nil, nil, errForceRelayRuntimeUnavailable
		}
		return network, nil, nil
	}
	if !c.isRelayForwardingEnabled() && networkUsesRelay(network) {
		if network.RelayMode == RelayModeForce {
			if rollbackErr := c.rollbackCreatedNetwork(network.ID); rollbackErr != nil {
				return nil, nil, fmt.Errorf("force relay mode requires an enabled edge relay runtime: %w (rollback failed: %v)", errForceRelayRuntimeUnavailable, rollbackErr)
			}
			return nil, nil, errForceRelayRuntimeUnavailable
		}
		if err := c.ensureObservationForNetwork(network.ID); err != nil {
			logger.Warnf("failed to create WireGuard observation interface for network %s: %v", network.ID, err)
		}
		return network, nil, nil
	}
	if !networkUsesRelay(network) {
		if err := c.ensureObservationForNetwork(network.ID); err != nil {
			logger.Warnf("failed to create WireGuard observation interface for network %s: %v", network.ID, err)
		}
		return network, nil, nil
	}
	if err := c.ensureRelayForNetwork(network.ID); err != nil {
		if network.RelayMode == RelayModeForce {
			if rollbackErr := c.rollbackCreatedNetwork(network.ID); rollbackErr != nil {
				return nil, nil, fmt.Errorf("force relay mode requires a healthy edge relay: %w (rollback failed: %v)", err, rollbackErr)
			}
			return nil, nil, fmt.Errorf("force relay mode requires a healthy edge relay: %w", err)
		}
		logger.Warnf("failed to create relay topology for network %s: %v", network.ID, err)
		return network, nil, nil
	}
	return network, c.GetRelayNodeInfo(network.ID), nil
}

var errForceRelayRuntimeUnavailable = fmt.Errorf("force relay mode requires an available edge relay runtime")

func (c *MeshCoordinator) rollbackCreatedNetwork(networkID string) error {
	if c == nil {
		return nil
	}

	var rollbackErrs []string
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member == nil {
			continue
		}
		if err := c.MemberManager.RemoveMember(member.ID); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Sprintf("remove member %s: %v", member.ID, err))
		}
	}
	if err := c.DeleteNetwork(networkID); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Sprintf("delete network %s: %v", networkID, err))
	}
	if len(rollbackErrs) == 0 {
		return nil
	}
	return errors.New(strings.Join(rollbackErrs, "; "))
}

func (c *MeshCoordinator) addExistingPeersToRelay(networkID string) error {
	if c == nil || c.RelayManager == nil {
		return nil
	}
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member == nil || member.IsRelay || !hasRealPublicKey(member) {
			continue
		}
		if err := c.RelayManager.AddPeer(networkID, relay.PeerConfig{
			PublicKey:  member.PublicKey,
			AssignedIP: member.IP,
			Endpoint:   member.Endpoint, // last known endpoint from SQLite
		}); err != nil {
			return fmt.Errorf("add existing peer %s to relay network %s: %w", member.ID, networkID, err)
		}
	}
	return nil
}

func (c *MeshCoordinator) removeRelayMembers(networkID string) error {
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member != nil && member.IsRelay {
			if err := c.MemberManager.RemoveMember(member.ID); err != nil {
				return fmt.Errorf("remove relay member %s: %w", member.ID, err)
			}
		}
	}
	return c.NetworkManager.SetRelayMemberID(networkID, "")
}

// NotifyRelayPeerLeft notifies the relay manager about a peer leaving.
func (c *MeshCoordinator) NotifyRelayPeerLeft(networkID, publicKey string) {
	if c.RelayManager == nil || publicKey == "" {
		return
	}
	// Skip placeholder keys (e.g. clientId used as publicKey in proxy-add).
	if _, err := wgtypes.ParseKey(publicKey); err != nil {
		return
	}
	if _, err := c.NetworkManager.GetNetwork(networkID); err != nil {
		return
	}
	if err := c.RelayManager.RemovePeer(networkID, publicKey); err != nil {
		logger.Warnf("relay remove peer failed (network=%s): %v", networkID, err)
	}
}

// GetRelayNodeInfo returns the Edge WG node info for a network. For disabled
// networks this is observation-only metadata; it is not registered as a
// relay member and must not be used for business-traffic fallback.
func (c *MeshCoordinator) GetRelayNodeInfo(networkID string) *relay.RelayNodeInfo {
	// Observation-only interfaces are intentionally present for disabled
	// networks as well.  Their node info is not a published relay member and is
	// only consumed by clients to maintain the hidden Edge WG heartbeat peer.
	if c == nil || c.RelayManager == nil {
		return nil
	}
	info, err := c.RelayManager.GetRelayNodeInfo(networkID)
	if err != nil {
		return nil
	}
	info.HostName = "edge-reply"
	return info
}

func (c *MeshCoordinator) UpdateNetworkCIDR(networkID, newCIDR string) error {
	// 原子地迁移网段并把所有成员 IP 重新映射进新网段（保留主机位，冲突则回退分配）。
	if err := c.MemberManager.RemapNetworkCIDR(networkID, newCIDR); err != nil {
		return err
	}

	network, err := c.NetworkManager.GetNetwork(networkID)
	if err == nil && network != nil && c.RelayManager != nil {
		if err := c.RelayManager.DeleteNetworkInterface(networkID); err != nil {
			return err
		}
		return c.reconcileNetwork(networkID)
	}
	return nil
}

func (c *MeshCoordinator) UpdateRelayMode(networkID string, mode RelayMode) error {
	network, err := c.NetworkManager.GetNetwork(networkID)
	if err != nil {
		return err
	}

	previousMode := network.RelayMode
	if mode == RelayModeForce && !c.RelayForwardingReady() {
		return errForceRelayRuntimeUnavailable
	}
	if previousMode == mode {
		return c.reconcileNetwork(networkID)
	}

	if err := c.NetworkManager.UpdateRelayMode(networkID, mode); err != nil {
		return err
	}

	if err := c.reconcileNetwork(networkID); err != nil {
		rollbackErr := c.NetworkManager.UpdateRelayMode(networkID, previousMode)
		if rollbackErr == nil {
			rollbackErr = c.reconcileNetwork(networkID)
		}
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func (c *MeshCoordinator) ensureRelayForNetwork(networkID string) error {
	if c == nil {
		return nil
	}
	if c.RelayManager == nil {
		return fmt.Errorf("wireguard relay runtime unavailable for network %s", networkID)
	}
	if !c.isRelayForwardingEnabled() {
		return fmt.Errorf("wireguard business relay disabled for network %s", networkID)
	}

	network, err := c.NetworkManager.GetNetwork(networkID)
	if err != nil {
		return err
	}
	if !networkUsesRelay(network) {
		return nil
	}

	relayInfo, err := c.RelayManager.GetRelayNodeInfo(network.ID)
	if err != nil || relayInfo == nil {
		relayInfo, err = c.RelayManager.CreateNetworkInterface(relay.CreateInterfaceRequest{
			NetworkID: network.ID,
			CIDR:      network.CIDR,
		})
		if err != nil {
			return fmt.Errorf("create relay interface: %w", err)
		}
	}
	if err := c.RelayManager.SetObservationOnly(networkID, false); err != nil {
		return err
	}

	relayIP := strings.TrimSpace(relayInfo.AssignedIP)
	if relayIP == "" {
		relayIP, err = firstUsableIPv4(network.CIDR)
		if err != nil {
			return fmt.Errorf("resolve relay reserved IP: %w", err)
		}
	}

	members := c.MemberManager.ListNetworkMembers(network.ID)
	if err := c.moveMemberOffRelayReservedIP(network, relayIP, members); err != nil {
		return err
	}

	members = c.MemberManager.ListNetworkMembers(network.ID)
	relayMember := findRelayMember(members, network.RelayMemberID)
	if relayMember == nil {
		relayMember, err = c.MemberManager.JoinNetwork(&JoinNetworkRequest{
			MemberID:   relayInfo.MemberID,
			NetworkID:  network.ID,
			HostName:   "edge-relay",
			ClientID:   relayInfo.MemberID,
			PublicKey:  relayInfo.PublicKey,
			IsRelay:    true,
			AssignedIP: relayIP,
		})
		if err != nil {
			return fmt.Errorf("register relay member: %w", err)
		}
	} else {
		if strings.TrimSpace(relayMember.IP) != relayIP {
			if err := c.MemberManager.UpdateMemberIP(relayMember.ID, relayIP); err != nil {
				return fmt.Errorf("assign relay member %s to reserved IP %s: %w", relayMember.ID, relayIP, err)
			}
		}
		if strings.TrimSpace(relayInfo.PublicKey) != "" && relayMember.PublicKey != relayInfo.PublicKey {
			updatedRelayMember, joinErr := c.MemberManager.JoinNetwork(&JoinNetworkRequest{
				MemberID:   relayMember.ID,
				NetworkID:  network.ID,
				ClientID:   relayMember.ClientID,
				PublicKey:  relayInfo.PublicKey,
				IsRelay:    true,
				AssignedIP: relayIP,
			})
			if joinErr != nil {
				return fmt.Errorf("refresh relay member public key: %w", joinErr)
			}
			relayMember = updatedRelayMember
		}
	}

	if err := c.MemberManager.SetMemberOnline(relayMember.ID); err != nil {
		return fmt.Errorf("mark relay member online: %w", err)
	}
	if relayInfo.Endpoint != "" {
		if err := c.MemberManager.UpdateMemberEndpoint(relayMember.ID, relayInfo.Endpoint); err != nil {
			return fmt.Errorf("update relay member endpoint: %w", err)
		}
	}
	if strings.TrimSpace(network.RelayMemberID) != relayMember.ID {
		if err := c.NetworkManager.SetRelayMemberID(network.ID, relayMember.ID); err != nil {
			return fmt.Errorf("persist relay member id: %w", err)
		}
	}

	return c.addExistingPeersToRelay(network.ID)
}

// ensureObservationForNetwork creates the Edge WG interface used to observe
// canonical peer UDP endpoints, without registering/publishing an Edge relay
// member. It is also used for RelayMode=disabled networks: disabled means no
// relay fallback, not "use the mTLS control connection as a WG endpoint".
func (c *MeshCoordinator) ensureObservationForNetwork(networkID string) error {
	if c == nil || c.RelayManager == nil {
		return fmt.Errorf("wireguard observation runtime unavailable for network %s", networkID)
	}
	network, err := c.NetworkManager.GetNetwork(networkID)
	if err != nil {
		return err
	}
	if network == nil {
		return fmt.Errorf("network %s not found", networkID)
	}
	observationInfo, infoErr := c.RelayManager.GetRelayNodeInfo(networkID)
	if infoErr != nil {
		var createErr error
		observationInfo, createErr = c.RelayManager.CreateNetworkInterface(relay.CreateInterfaceRequest{
			NetworkID:       network.ID,
			CIDR:            network.CIDR,
			ObservationOnly: true,
		})
		if createErr != nil {
			// A relay manager may report an existing interface while its node info
			// is temporarily unavailable during recovery. Verify the observation
			// interface directly before treating the create error as fatal.
			if _, observeErr := c.RelayManager.GetObservedEndpoints(networkID); observeErr != nil {
				return fmt.Errorf("create observation interface: %w", createErr)
			}
			observationInfo, _ = c.RelayManager.GetRelayNodeInfo(networkID)
		}
	}
	if err := c.RelayManager.SetObservationOnly(networkID, true); err != nil {
		return err
	}
	// The observation interface owns the first usable address in the network,
	// just like a relay interface. Move a pre-existing member away from that
	// reserved address before programming the peer list, otherwise the hidden
	// observer peer would collide with the first client (/32 overlap).
	if observationInfo != nil {
		members := c.MemberManager.ListNetworkMembers(network.ID)
		if err := c.moveMemberOffRelayReservedIP(network, observationInfo.AssignedIP, members); err != nil {
			return err
		}
	}
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member == nil || member.IsRelay || !hasRealPublicKey(member) {
			continue
		}
		if err := c.RelayManager.AddPeer(networkID, relay.PeerConfig{
			PublicKey:  member.PublicKey,
			AssignedIP: member.IP,
		}); err != nil {
			return fmt.Errorf("add observation peer %s: %w", member.ID, err)
		}
	}
	return nil
}

func (c *MeshCoordinator) moveMemberOffRelayReservedIP(network *Network, relayIP string, members []*NetworkMember) error {
	if c == nil || network == nil {
		return nil
	}
	relayIP = strings.TrimSpace(relayIP)
	if relayIP == "" {
		return nil
	}

	for _, member := range members {
		if member == nil || member.IsRelay || member.Status == MemberStatusRemoved || strings.TrimSpace(member.IP) != relayIP {
			continue
		}
		nextIP, err := nextAvailableMemberIP(network.CIDR, members, relayIP)
		if err != nil {
			return fmt.Errorf("relay reserved IP %s is occupied by member %s and no spare IP is available: %w", relayIP, member.ID, err)
		}
		if err := c.MemberManager.UpdateMemberIP(member.ID, nextIP); err != nil {
			return fmt.Errorf("move member %s from reserved relay IP %s to %s: %w", member.ID, relayIP, nextIP, err)
		}
		logger.Warnf("moved member %s in network %s from reserved relay IP %s to %s to restore relay topology", member.ID, network.ID, relayIP, nextIP)
		return nil
	}
	return nil
}

func findRelayMember(members []*NetworkMember, relayMemberID string) *NetworkMember {
	relayMemberID = strings.TrimSpace(relayMemberID)
	if relayMemberID != "" {
		for _, member := range members {
			if member != nil && member.IsRelay && member.ID == relayMemberID {
				return member
			}
		}
	}
	for _, member := range members {
		if member != nil && member.IsRelay {
			return member
		}
	}
	return nil
}

func firstUsableIPv4(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("only IPv4 supported")
	}
	next := dupIP(ip4)
	next[3]++
	return next.String(), nil
}

func nextAvailableMemberIP(cidr string, members []*NetworkMember, reservedIPs ...string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %w", err)
	}

	allocated := make(map[string]bool, len(members))
	for _, member := range members {
		if member == nil || member.Status == MemberStatusRemoved {
			continue
		}
		allocated[strings.TrimSpace(member.IP)] = true
	}

	reserved := make(map[string]struct{}, len(reservedIPs))
	for _, reservedIP := range reservedIPs {
		trimmed := strings.TrimSpace(reservedIP)
		if trimmed != "" {
			reserved[trimmed] = struct{}{}
		}
	}

	candidate := dupIP(ip.Mask(ipNet.Mask))

	var (
		networkIP    net.IP
		broadcastIP  net.IP
		skipReserved bool
	)

	if candidate4 := candidate.To4(); candidate4 != nil {
		candidate = dupIP(candidate4)
		networkIP = dupIP(candidate)
		ones, bits := ipNet.Mask.Size()
		skipReserved = ones < bits
		if skipReserved {
			broadcastIP = make(net.IP, len(networkIP))
			for i := range networkIP {
				broadcastIP[i] = networkIP[i] | ^ipNet.Mask[i]
			}
			incIP(candidate)
		}
	}

	for ; ipNet.Contains(candidate); incIP(candidate) {
		if skipReserved && (candidate.Equal(networkIP) || candidate.Equal(broadcastIP)) {
			continue
		}
		ipStr := candidate.String()
		if allocated[ipStr] {
			continue
		}
		if _, blocked := reserved[ipStr]; blocked {
			continue
		}
		return ipStr, nil
	}

	return "", fmt.Errorf("no available IP in CIDR: %s", cidr)
}

func (c *MeshCoordinator) UpdateMemberIP(memberID, newIP string) error {
	member, err := c.MemberManager.GetMember(memberID)
	if err != nil {
		return err
	}
	previousIP := member.IP
	if err := c.MemberManager.UpdateMemberIP(memberID, newIP); err != nil {
		return err
	}
	if c.RelayManager == nil || member.IsRelay || !hasRealPublicKey(member) {
		return nil
	}
	if err := c.RelayManager.AddPeer(member.NetworkID, relay.PeerConfig{
		PublicKey: member.PublicKey, AssignedIP: member.IP,
	}); err != nil {
		rollbackErr := c.MemberManager.UpdateMemberIP(memberID, previousIP)
		restoreErr := c.RelayManager.AddPeer(member.NetworkID, relay.PeerConfig{
			PublicKey: member.PublicKey, AssignedIP: previousIP,
		})
		return fmt.Errorf("update observer allowed IP: %w (member rollback: %v; observer rollback: %v)", err, rollbackErr, restoreErr)
	}
	return nil
}

// UpdateMember 支持多字段更新：newIP 非空时更新 IP，newHostname 非空时更新 hostname。
func (c *MeshCoordinator) UpdateMember(memberID, newIP, newHostname string) error {
	if strings.TrimSpace(newIP) != "" {
		if err := c.UpdateMemberIP(memberID, newIP); err != nil {
			return err
		}
	}
	if strings.TrimSpace(newHostname) != "" {
		if err := c.MemberManager.UpdateMemberHostname(memberID, newHostname); err != nil {
			return err
		}
	}
	if strings.TrimSpace(newIP) == "" && strings.TrimSpace(newHostname) == "" {
		return fmt.Errorf("no fields to update for member %s", memberID)
	}
	return nil
}

func (c *MeshCoordinator) UpdateMemberEndpoint(memberID, endpoint string) error {
	return c.MemberManager.UpdateMemberEndpoint(memberID, endpoint)
}

func (c *MeshCoordinator) ApplyObservedEndpoint(networkID, publicKey, endpoint string) (bool, error) {
	return c.MemberManager.ApplyObservedEndpoint(networkID, publicKey, endpoint)
}

// HandleHeartbeatTimeout marks a member offline when its WireGuard handshake
// goes stale. This is the UDP-only liveness signal: peer status is driven
// solely by the observation loop, independent of the mTLS control connection.
func (c *MeshCoordinator) HandleHeartbeatTimeout(networkID, publicKey string) error {
	return c.MemberManager.HandleHeartbeatTimeout(networkID, publicKey)
}

// SetMemberOnlineByPublicKey marks a member online by matching its public key
// within a network. Used by the UDP observation callback to restore online
// status when a fresh WireGuard handshake is detected.
// Returns (nil, true) on a non-Online → Online transition.
func (c *MeshCoordinator) SetMemberOnlineByPublicKey(networkID, publicKey string) (error, bool) {
	return c.MemberManager.SetMemberOnlineByPublicKey(networkID, publicKey)
}

func (c *MeshCoordinator) SetRelayEndpointChangeCallback(fn func(networkID, publicKey, endpoint string)) {
	if c == nil || c.RelayManager == nil {
		return
	}
	c.RelayManager.SetOnEndpointChange(fn)
	if fn == nil {
		return
	}

	// Replay endpoints already learned before the callback was installed. This
	// matters during config reload/recovery: the WG observation loop may have
	// seen a handshake before the handler was rebuilt, and waiting for another
	// endpoint transition would leave snapshots stale or empty indefinitely.
	for _, network := range c.NetworkManager.ListNetworks() {
		if network == nil {
			continue
		}
		observed, err := c.RelayManager.GetObservedEndpoints(network.ID)
		if err != nil {
			continue
		}
		for _, endpoint := range observed {
			if endpoint.Endpoint == nil {
				continue
			}
			fn(network.ID, endpoint.PublicKey, endpoint.Endpoint.String())
		}
	}
}

// SetHeartbeatTimeoutCallback registers the callback invoked by the observation
// loop when a peer's WG handshake exceeds the heartbeat timeout window.
func (c *MeshCoordinator) SetHeartbeatTimeoutCallback(fn func(networkID, publicKey string)) {
	if c == nil || c.RelayManager == nil {
		return
	}
	c.RelayManager.SetOnHeartbeatTimeout(fn)
}

// ---------------------------------------------------------------------------
// LAN endpoint management (same-NAT direct path optimization)
// ---------------------------------------------------------------------------

// StoreLANEndpoint records a client's reported LAN WireGuard endpoint.
// The endpoint is in the form "LAN_IP:WG_LISTEN_PORT".
// Rejects endpoints whose IP matches any member's assigned network IP —
// that indicates the client reported its WG TUN address (or a host IP
// from a virtualised environment) rather than a real physical LAN address.
func (c *MeshCoordinator) StoreLANEndpoint(networkID, publicKey string, candidates []string) bool {
	if c == nil || networkID == "" || publicKey == "" || len(candidates) == 0 {
		return false
	}
	// Validate: filter out candidates whose IP collides with a member's assigned IP.
	var valid []string
	if c.MemberManager != nil {
		assignedIPs := make(map[string]string) // ip → memberID
		for _, m := range c.MemberManager.ListNetworkMembers(networkID) {
			if m != nil && m.IP != "" {
				assignedIPs[m.IP] = m.ID
			}
		}
		for _, ep := range candidates {
			lanIP, _, splitErr := net.SplitHostPort(ep)
			if splitErr == nil && lanIP != "" {
				if memberID, collision := assignedIPs[lanIP]; collision {
					logger.Warnf("rejected LAN candidate: network=%s peer=%s endpoint=%s matches member assigned IP %s (member=%s)",
						networkID, shortKey(publicKey), ep, lanIP, memberID)
					continue
				}
			}
			valid = append(valid, ep)
		}
	} else {
		valid = candidates
	}
	if len(valid) == 0 {
		return false
	}
	c.lanEndpointsMu.Lock()
	if c.lanEndpoints == nil {
		c.lanEndpoints = make(map[string]map[string][]string)
	}
	if c.lanEndpoints[networkID] == nil {
		c.lanEndpoints[networkID] = make(map[string][]string)
	}
	changed := !slices.Equal(c.lanEndpoints[networkID][publicKey], valid)
	c.lanEndpoints[networkID][publicKey] = slices.Clone(valid)
	c.lanEndpointsMu.Unlock()
	// Persist first candidate to SQLite for durability (backup / inspection).
	if c.MemberManager != nil {
		if err := c.MemberManager.UpdateMemberLANEndpoint(networkID, publicKey, valid[0]); err != nil {
			logger.Warnf("failed to persist LAN endpoint: network=%s peer=%s err=%v", networkID, publicKey, err)
		}
	}
	logger.Infof("stored LAN endpoint candidates: network=%s peer=%s candidates=%v", networkID, publicKey, valid)
	return changed
}

// GetLANPeerEndpoints returns all stored LAN endpoints for a network.
// Returns publicKey → first endpoint (backward compat).
func (c *MeshCoordinator) GetLANPeerEndpoints(networkID string) map[string]string {
	if c == nil {
		return nil
	}
	c.lanEndpointsMu.Lock()
	defer c.lanEndpointsMu.Unlock()
	src := c.lanEndpoints[networkID]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// GetLANPeerEndpointCandidates returns all stored LAN endpoint candidates for a network.
// Returns publicKey → []endpoint candidates.
func (c *MeshCoordinator) GetLANPeerEndpointCandidates(networkID string) map[string][]string {
	if c == nil {
		return nil
	}
	c.lanEndpointsMu.Lock()
	defer c.lanEndpointsMu.Unlock()
	src := c.lanEndpoints[networkID]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string][]string, len(src))
	for k, v := range src {
		if len(v) > 0 {
			cp := make([]string, len(v))
			copy(cp, v)
			out[k] = cp
		}
	}
	return out
}

// GetLANPeerEndpointsForClient returns only the LAN endpoints whose target
// member shares the same observed public IP as the requesting client (same-NAT).
// This prevents non-same-NAT clients from receiving LAN endpoints they cannot
// reach. The requester is identified by their public key within the network.
//
// This is a defense-in-depth complement to the frontend same-NAT check; the
// push broadcast path still sends the full map (frontend filters locally).
func (c *MeshCoordinator) GetLANPeerEndpointsForClient(networkID, requesterPublicKey string) map[string]string {
	candidates := c.GetLANPeerEndpointCandidatesForClient(networkID, requesterPublicKey)
	if candidates == nil {
		return nil
	}
	out := make(map[string]string, len(candidates))
	for k, v := range candidates {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// GetLANPeerEndpointCandidatesForClient returns candidate LAN endpoints whose target
// member shares the same observed public IP as the requesting client (same-NAT).
func (c *MeshCoordinator) GetLANPeerEndpointCandidatesForClient(networkID, requesterPublicKey string) map[string][]string {
	if c == nil || networkID == "" || requesterPublicKey == "" {
		return nil
	}
	var requesterIP string
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member != nil && member.PublicKey == requesterPublicKey {
			requesterIP = extractIPFromEndpoint(member.Endpoint)
			break
		}
	}
	if requesterIP == "" {
		return c.GetLANPeerEndpointCandidates(networkID)
	}
	// Deep copy under lock to avoid concurrent map access when iterating.
	// StoreLANEndpoint may write to c.lanEndpoints[networkID] concurrently.
	c.lanEndpointsMu.Lock()
	src := c.lanEndpoints[networkID]
	if len(src) == 0 {
		c.lanEndpointsMu.Unlock()
		return nil
	}
	// Make a deep copy: outer map + inner slices
	copied := make(map[string][]string, len(src))
	for pk, candidates := range src {
		if len(candidates) > 0 {
			cp := make([]string, len(candidates))
			copy(cp, candidates)
			copied[pk] = cp
		}
	}
	c.lanEndpointsMu.Unlock()

	memberByPK := make(map[string]*NetworkMember)
	for _, m := range c.MemberManager.ListNetworkMembers(networkID) {
		if m != nil && m.PublicKey != "" {
			memberByPK[m.PublicKey] = m
		}
	}

	out := make(map[string][]string)
	for pk, candidates := range copied {
		target := memberByPK[pk]
		if target == nil {
			continue
		}
		targetIP := extractIPFromEndpoint(target.Endpoint)
		if targetIP != "" && targetIP == requesterIP {
			out[pk] = candidates
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extractIPFromEndpoint extracts the IP address from an "ip:port" endpoint string.
func extractIPFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		// Might be a bare IP or malformed; try trimming.
		return strings.Split(endpoint, ":")[0]
	}
	return host
}

// RemoveLANEndpoint clears a stored LAN endpoint for a peer.
func (c *MeshCoordinator) RemoveLANEndpoint(networkID, publicKey string) {
	if c == nil {
		return
	}
	c.lanEndpointsMu.Lock()
	if m := c.lanEndpoints[networkID]; m != nil {
		delete(m, publicKey)
		if len(m) == 0 {
			delete(c.lanEndpoints, networkID)
		}
	}
	c.lanEndpointsMu.Unlock()
}

// pairHasLANEndpoints returns true when both peers in a same-NAT pair already
// have stored LAN endpoints.  Used to select a longer refresh interval so
// that stale endpoints are periodically re-gathered without flooding clients
// with unnecessary requests on every maintenance tick.
func (c *MeshCoordinator) pairHasLANEndpoints(networkID, pkA, pkB string) bool {
	c.lanEndpointsMu.Lock()
	defer c.lanEndpointsMu.Unlock()
	m := c.lanEndpoints[networkID]
	if m == nil {
		return false
	}
	return len(m[pkA]) > 0 && len(m[pkB]) > 0
}

// SetSessionCreatedCallback removed (S5-B2): was only used by EnsureDirectSessions.

// SetLANGatherPusher installs a callback that pushes gather requests to
// clients. Called from the setup code to connect the coordinator with the
// WireGuard handler's PushGatherInfo method.
func (c *MeshCoordinator) SetLANGatherPusher(pusher func(networkID, clientID string) error) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.lanGatherPusher = pusher
	c.mu.Unlock()
}

// detectAndStoreSameNAT checks the relay manager for peer pairs that share
// the same observed public IP, logs them, and pushes gather requests so
// that clients report their LAN endpoints.
func (c *MeshCoordinator) detectAndStoreSameNAT() {
	if c == nil {
		return
	}
	if c.RelayManager == nil {
		logger.Debugf("same-NAT check skipped: relay manager not set")
		return
	}
	c.mu.Lock()
	pusher := c.lanGatherPusher
	c.mu.Unlock()

	networks := c.NetworkManager.ListNetworks()
	logger.Debugf("same-NAT check: networks=%d pusher=%v", len(networks), pusher != nil)
	for _, network := range networks {
		if network == nil {
			continue
		}
		// Force-relay networks never establish P2P direct paths, so
		// same-NAT LAN gather is pointless — skip entirely.
		if network.RelayMode == RelayModeForce {
			continue
		}
		pairs := c.RelayManager.DetectSameNATPeers(network.ID)
		logger.Debugf("same-NAT check: network=%s pairs=%d", network.ID, len(pairs))
		for _, pair := range pairs {
			shortA := shortKey(pair.PeerA)
			shortB := shortKey(pair.PeerB)
			logger.Debugf("same-NAT detected: network=%s peerA=%s peerB=%s publicIP=%s",
				network.ID, shortA, shortB, pair.PublicIP)

			if pusher == nil {
				continue
			}

			// Throttle per peer pair.  When both peers already have LAN
			// endpoints, use a longer refresh interval to detect stale
			// values (e.g. after a client port migration).  When either
			// peer is still missing an endpoint, use the shorter interval
			// so the initial gather completes quickly.
			pairKey := sameNATPairKey(network.ID, pair.PeerA, pair.PeerB)
			bothHaveEndpoints := c.pairHasLANEndpoints(network.ID, pair.PeerA, pair.PeerB)
			throttleInterval := lanGatherInterval
			if bothHaveEndpoints {
				throttleInterval = lanGatherRefreshInterval
			}
			c.sameNATPairLastPushMu.Lock()
			if c.sameNATPairLastPush == nil {
				c.sameNATPairLastPush = make(map[string]time.Time)
			}
			lastPush := c.sameNATPairLastPush[pairKey]
			if time.Since(lastPush) < throttleInterval {
				c.sameNATPairLastPushMu.Unlock()
				continue
			}
			c.sameNATPairLastPush[pairKey] = time.Now()
			c.sameNATPairLastPushMu.Unlock()

			// Push gather requests to both peers so they report their
			// LAN endpoints (localWGEndpoint).
			clientA := c.findMemberClientIDByPublicKey(network.ID, pair.PeerA)
			clientB := c.findMemberClientIDByPublicKey(network.ID, pair.PeerB)
			logger.Debugf("same-NAT gather push: network=%s peerA=%s clientA=%q peerB=%s clientB=%q",
				network.ID, shortKey(pair.PeerA), clientA, shortKey(pair.PeerB), clientB)
			if clientA != "" {
				if err := pusher(network.ID, clientA); err != nil {
					logger.Warnf("same-NAT gather push failed: network=%s client=%s err=%v", network.ID, shortKey(pair.PeerA), err)
				} else {
					logger.Debugf("same-NAT gather pushed to clientA=%s", clientA)
				}
			}
			if clientB != "" {
				if err := pusher(network.ID, clientB); err != nil {
					logger.Warnf("same-NAT gather push failed: network=%s client=%s err=%v", network.ID, shortKey(pair.PeerB), err)
				} else {
					logger.Debugf("same-NAT gather pushed to clientB=%s", clientB)
				}
			}
		}
	}
}

// shortKey returns the first 8 characters of a public key for logging.
func shortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}

// sameNATPairKey returns a deterministic map key for a same-NAT peer pair.
// Public keys are sorted lexicographically so that (A,B) and (B,A) produce
// the same key.
func sameNATPairKey(networkID, pkA, pkB string) string {
	if pkA > pkB {
		pkA, pkB = pkB, pkA
	}
	return networkID + ":" + pkA + ":" + pkB
}

// lanGatherInterval is the minimum time between same-NAT LAN gather
// pushes to the same peer pair when either peer is still missing a LAN
// endpoint.  Prevents flooding clients with gather requests on every
// maintenance tick.
const lanGatherInterval = 15 * time.Second

// lanGatherRefreshInterval is the throttle interval for same-NAT pairs
// where both peers already have stored LAN endpoints.  Longer than
// lanGatherInterval to avoid unnecessary traffic, but short enough to
// detect stale endpoints (e.g. after a client port migration or DHCP
// renewal) within a few minutes.
const lanGatherRefreshInterval = 5 * time.Minute

// findMemberClientIDByPublicKey looks up a member's clientID by matching
// the public key within a network.  member.ClientID is the bare deviceID
// set at JoinNetwork time, which is what SessionManager.PushToClient expects.
func (c *MeshCoordinator) findMemberClientIDByPublicKey(networkID, publicKey string) string {
	for _, member := range c.MemberManager.ListNetworkMembers(networkID) {
		if member != nil && member.PublicKey == publicKey {
			return member.ClientID
		}
	}
	return ""
}
