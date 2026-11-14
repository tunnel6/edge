package wireguard

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

// Status

// Status
type MemberManager struct {
	members        map[string]*NetworkMember    // memberID -> Member
	networkMembers map[string][]string          // networkID -> []memberID
	clientMembers  map[string]map[string]string // clientID -> map[networkID]memberID
	allocatedIPs   map[string]map[string]bool   // networkID -> map[ip]bool
	mu             sync.RWMutex
	networkManager *NetworkManager // Status
	storage        Storage
}

// Create
func NewMemberManager(networkManager *NetworkManager) *MemberManager {
	return &MemberManager{
		members:        make(map[string]*NetworkMember),
		networkMembers: make(map[string][]string),
		clientMembers:  make(map[string]map[string]string),
		allocatedIPs:   make(map[string]map[string]bool),
		networkManager: networkManager,
	}
}

func (m *MemberManager) SetStorage(s Storage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage = s
}

func (m *MemberManager) clientPublicKey(clientID, networkID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if member := m.members[m.clientMembers[clientID][networkID]]; member != nil {
		return member.PublicKey
	}
	return ""
}

type JoinNetworkRequest struct {
	MemberID   string
	NetworkID  string
	HostName   string
	ClientID   string
	UserID     string
	PublicKey  string
	IsRelay    bool
	AssignedIP string
}

// Status

func (m *MemberManager) JoinNetwork(req *JoinNetworkRequest) (*NetworkMember, error) {
	return pathSourceValue(m.networkManager, func() (*NetworkMember, error) {
		return m.joinNetwork(req)
	})
}

func (m *MemberManager) joinNetwork(req *JoinNetworkRequest) (*NetworkMember, error) {
	mt0 := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	logger.Infof("[JoinPerf] network_id=%s MemberManager.m.mu acquired in %v", req.NetworkID, time.Since(mt0))

	network, err := m.networkManager.GetNetwork(req.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("network not found: %w", err)
	}
	if network.Status != NetworkStatusActive {
		return nil, fmt.Errorf("network not active: %s", req.NetworkID)
	}

	// Check
	if clientNets, ok := m.clientMembers[req.ClientID]; ok {
		if existingMemberID, exists := clientNets[req.NetworkID]; exists {
			// 幂等重入 / 公钥升级：同一 client 重新加入不再报错。
			// 代加成员先以 clientId 占位公钥加入，待其真正启动 WG 用真实公钥重入时就地升级，
			// 否则会一直停留在「占位公钥 + 永远离线」且无法转为真实可连接 peer。
			existing, found := m.members[existingMemberID]
			if !found || existing == nil {
				return nil, fmt.Errorf("client %s already joined network %s as member %s",
					req.ClientID, req.NetworkID, existingMemberID)
			}
			isRealKey := req.PublicKey != "" && req.PublicKey != req.ClientID
			keyChanged := isRealKey && req.PublicKey != existing.PublicKey
			if keyChanged || existing.pathRevoked {
				updated := *existing
				if keyChanged {
					updated.PublicKey = req.PublicKey
					updated.Endpoint = ""
					updated.ObservedAt = time.Time{}
					updated.HostName = req.HostName
				}
				updated.UpdatedAt = time.Now()
				// Only a persisted explicit rejoin may restore coordination eligibility.
				// Owner proxy-add is an explicit re-add too. Restore a soft-left
				// member to Active so it is eligible for pushes and can complete
				// its local real-key rejoin; clearing pathRevoked alone leaves it
				// permanently excluded from network events.
				if updated.Status == MemberStatusLeaved {
					updated.Status = MemberStatusActive
				}
				updated.pathRevoked = false
				rotatePathMembership(&updated)
				if m.storage != nil {
					if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
						return nil, fmt.Errorf("persist member rejoin: %w", err)
					}
				}
				*existing = updated
			}
			return existing, nil
		}
	}

	// Backward-compat migration: older Edge versions stored member.ClientID as
	// userID-deviceID (e.g. "3-device-xxx").  The canonical format is now
	// bare deviceID (e.g. "device-xxx").  When the bare-deviceID lookup
	// above misses, check whether the same device already has a member under
	// the old userID-deviceID key and migrate it in place.
	if req.UserID != "" {
		oldFormatClientID := req.UserID + "-" + req.ClientID
		if oldClientNets, ok := m.clientMembers[oldFormatClientID]; ok {
			if oldMemberID, exists := oldClientNets[req.NetworkID]; exists {
				if oldMember, found := m.members[oldMemberID]; found && oldMember != nil {
					// Migrate: update the member's ClientID to bare deviceID
					// and move the clientMembers entry.
					updated := *oldMember
					updated.ClientID = req.ClientID
					if req.PublicKey != "" && req.PublicKey != req.ClientID && req.PublicKey != updated.PublicKey {
						updated.PublicKey = req.PublicKey
						updated.Endpoint = ""
						updated.ObservedAt = time.Time{}
					}
					rotatePathMembership(&updated)
					updated.pathRevoked = false
					updated.HostName = req.HostName
					updated.UpdatedAt = time.Now()
					if m.storage != nil {
						if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
							return nil, fmt.Errorf("persist legacy member rejoin: %w", err)
						}
					}
					*oldMember = updated
					// Move clientMembers entry: old format → bare deviceID.
					if m.clientMembers[req.ClientID] == nil {
						m.clientMembers[req.ClientID] = make(map[string]string)
					}
					m.clientMembers[req.ClientID][req.NetworkID] = oldMemberID
					delete(oldClientNets, req.NetworkID)
					if len(oldClientNets) == 0 {
						delete(m.clientMembers, oldFormatClientID)
					}
					return oldMember, nil
				}
			}
		}
	}

	requestedIP := strings.TrimSpace(req.AssignedIP)
	ip := requestedIP
	if requestedIP != "" {
		if err := m.reserveIP(req.NetworkID, network.CIDR, requestedIP); err != nil {
			return nil, fmt.Errorf("reserve requested IP failed: %w", err)
		}
	} else {
		var allocErr error
		ip, allocErr = m.allocateIP(req.NetworkID, network.CIDR)
		if allocErr != nil {
			return nil, fmt.Errorf("allocate IP failed: %w", allocErr)
		}
	}

	now := time.Now()
	member := &NetworkMember{
		ID:        req.MemberID,
		NetworkID: req.NetworkID,
		ClientID:  req.ClientID,
		IP:        ip,
		HostName:  req.HostName,
		PublicKey: req.PublicKey,
		IsRelay:   req.IsRelay,
		Status:    MemberStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}

	member.Status = MemberStatusActive
	rotatePathMembership(member)
	member.UpdatedAt = time.Now()

	if m.storage != nil {
		if err := m.storage.SaveMember(context.Background(), member); err != nil {
			m.releaseIP(req.NetworkID, ip)
			return nil, fmt.Errorf("persist member: %w", err)
		}
	}

	m.members[req.MemberID] = member
	m.networkMembers[req.NetworkID] = append(m.networkMembers[req.NetworkID], req.MemberID)

	if m.clientMembers[req.ClientID] == nil {
		m.clientMembers[req.ClientID] = make(map[string]string)
	}
	m.clientMembers[req.ClientID][req.NetworkID] = req.MemberID

	return member, nil
}

// Set
// Status
func (m *MemberManager) SetMemberOnline(memberID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.setMemberOnline(memberID)
	})
}

func (m *MemberManager) setMemberOnline(memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}

	if member.Status != MemberStatusActive && member.Status != MemberStatusOnline && member.Status != MemberStatusLeaved {
		return fmt.Errorf("cannot set online from status: %d", member.Status)
	}

	member.Status = MemberStatusOnline
	member.LastOnline = time.Now()
	member.UpdatedAt = time.Now()

	// Online status is ephemeral — not persisted.
	return nil
}

// SetMemberOffline marks a member as permanently leaved. The member remains
// in the network but will not receive pushes and requires explicit rejoin.
func (m *MemberManager) SetMemberOffline(memberID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.setMemberOffline(memberID)
	})
}

// SetMemberDisconnected marks a member temporarily offline without persisting
// the observation or revoking path coordination. Explicit leave uses
// SetMemberOffline instead.
func (m *MemberManager) SetMemberDisconnected(memberID string) error {
	return pathSourceChange(m.networkManager, func() error {
		m.mu.Lock()
		defer m.mu.Unlock()

		member, ok := m.members[memberID]
		if !ok || member == nil {
			return fmt.Errorf("member not found: %s", memberID)
		}
		if member.Status == MemberStatusOnline {
			member.Status = MemberStatusActive
			member.UpdatedAt = time.Now()
		}
		// Active, Leaved, and Removed states are already offline or ineligible.
		// In particular, don't revive an explicit leave or removal here.
		return nil
	})
}

func (m *MemberManager) setMemberOffline(memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}

	member.Status = MemberStatusLeaved
	revokePathMembership(member)
	member.LastOnline = time.Now()
	member.UpdatedAt = time.Now()

	if m.storage != nil {
		if err := m.storage.UpdateMember(context.Background(), member); err != nil {
			return fmt.Errorf("persist member offline: %w", err)
		}
	}
	return nil
}

// SetClientMembersOffline explicitly leaves all memberships for a device and
// revokes coordination eligibility. Temporary session disconnects/timeouts must
// use SetClientMembersDisconnected instead.
func (m *MemberManager) SetClientMembersOffline(clientID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.setClientMembersOffline(clientID)
	})
}

func (m *MemberManager) setClientMembersOffline(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	networkMap, ok := m.clientMembers[clientID]
	if !ok {
		return nil // client has no memberships; nothing to do
	}

	var errs []error
	for _, memberID := range networkMap {
		member, found := m.members[memberID]
		if !found || member == nil {
			continue
		}
		if member.Status == MemberStatusRemoved {
			continue
		}
		member.Status = MemberStatusLeaved
		revokePathMembership(member)
		member.LastOnline = time.Now()
		member.UpdatedAt = time.Now()
		if m.storage != nil {
			if err := m.storage.UpdateMember(context.Background(), member); err != nil {
				errs = append(errs, fmt.Errorf("persist offline for member %s: %w", memberID, err))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("set client members offline: %v", errs)
	}
	return nil
}

// SetClientMembersDisconnected transitions all members belonging to the given
// client (device) to Active status when the mTLS session disconnects. This is
// a *temporary* offline: the member remains a network member and recovers to
// Online when WG handshake observation detects a live tunnel.
//
// Recovery path (independent of mTLS reconnect):
//   - Helper daemon sends PersistentKeepalive → Edge relay receives handshake
//   - Edge observeLoop detects handshake → SetMemberOnlineByPublicKey
//   - Member transitions Active → Online
func (m *MemberManager) SetClientMembersDisconnected(clientID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.setClientMembersDisconnected(clientID)
	})
}

func (m *MemberManager) setClientMembersDisconnected(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	networkMap, ok := m.clientMembers[clientID]
	if !ok {
		logger.Debugf("[SetClientMembersDisconnected] clientID=%s not found in clientMembers", clientID)
		return nil
	}

	transitionedCount := 0
	for _, memberID := range networkMap {
		member, found := m.members[memberID]
		if !found || member == nil {
			continue
		}
		// Only transition Online members to Active (temporary offline).
		// Members already Active/Leaved/Removed are left as-is.
		if member.Status != MemberStatusOnline {
			logger.Debugf("[SetClientMembersDisconnected] member=%s status=%d (not Online), skipping", memberID, member.Status)
			continue
		}
		logger.Infof("[SetClientMembersDisconnected] member=%s network=%s transitioning Online->Active", memberID, member.NetworkID)
		member.Status = MemberStatusActive
		member.UpdatedAt = time.Now()
		transitionedCount++
		// Status change is ephemeral — not persisted.
	}
	if transitionedCount > 0 {
		logger.Infof("[SetClientMembersDisconnected] clientID=%s transitioned %d members from Online to Active", clientID, transitionedCount)
	}
	return nil
}

// SetClientMembersConnected leaves the relay observation ledger unchanged:
// reconnect is not evidence of an established WG tunnel. Product control
// presence is projected separately by MembersWithControlPresence.
func (m *MemberManager) SetClientMembersConnected(clientID string) int {
	return 0
}

// Remove
// Status
func (m *MemberManager) RemoveMember(memberID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.removeMember(memberID)
	})
}

func (m *MemberManager) removeMember(memberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}

	// Mark
	member.Status = MemberStatusRemoved
	member.UpdatedAt = time.Now()

	m.releaseIP(member.NetworkID, member.IP)

	// Remove
	m.removeFromNetwork(member.NetworkID, memberID)
	m.removeFromClient(member.ClientID, member.NetworkID)

	// Delete
	delete(m.members, memberID)

	if m.storage != nil {
		if err := m.storage.DeleteMember(context.Background(), memberID); err != nil {
			return fmt.Errorf("persist delete member: %w", err)
		}
	}
	return nil
}

// Get
func (m *MemberManager) GetMember(memberID string) (*NetworkMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	member, ok := m.members[memberID]
	if !ok {
		return nil, fmt.Errorf("member not found: %s", memberID)
	}
	return member, nil
}

func (m *MemberManager) ListNetworkMembers(networkID string) []*NetworkMember {
	m.mu.RLock()
	defer m.mu.RUnlock()

	memberIDs := m.networkMembers[networkID]
	result := make([]*NetworkMember, 0, len(memberIDs))
	for _, id := range memberIDs {
		if member, ok := m.members[id]; ok {
			result = append(result, member)
		}
	}
	return result
}

func (m *MemberManager) ListOnlineMembers(networkID string) []*NetworkMember {
	m.mu.RLock()
	defer m.mu.RUnlock()

	memberIDs := m.networkMembers[networkID]
	result := make([]*NetworkMember, 0)
	for _, id := range memberIDs {
		if member, ok := m.members[id]; ok && member.Status == MemberStatusOnline {
			result = append(result, member)
		}
	}
	return result
}

// Get
func (m *MemberManager) GetClientMember(clientID, networkID string) (*NetworkMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if clientNets, ok := m.clientMembers[clientID]; ok {
		if memberID, exists := clientNets[networkID]; exists {
			if member, ok := m.members[memberID]; ok {
				return member, nil
			}
		}
	}
	return nil, fmt.Errorf("client %s not in network %s", clientID, networkID)
}

// Method

func (m *MemberManager) allocateIP(networkID, cidr string) (string, error) {
	// Parse
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %w", err)
	}

	if m.allocatedIPs[networkID] == nil {
		m.allocatedIPs[networkID] = make(map[string]bool)
	}

	candidate := dupIP(ip.Mask(ipNet.Mask))

	var (
		networkIP    net.IP
		broadcastIP  net.IP
		skipReserved bool
	)

	// IPv4 子网需要跳过网络地址和广播地址，避免把 .0 / .255 分给成员。
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
		if !m.allocatedIPs[networkID][ipStr] {
			m.allocatedIPs[networkID][ipStr] = true
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("no available IP in CIDR: %s", cidr)
}

func (m *MemberManager) reserveIP(networkID, cidr, requestedIP string) error {
	ip := net.ParseIP(requestedIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", requestedIP)
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	if !ipNet.Contains(ip) {
		return fmt.Errorf("IP %s is not within network CIDR %s", requestedIP, cidr)
	}

	ones, bits := ipNet.Mask.Size()
	if ones < bits {
		networkIP := ipNet.IP.Mask(ipNet.Mask)
		if ip.Equal(networkIP) {
			return fmt.Errorf("IP %s is the network address", requestedIP)
		}
		broadcastIP := make(net.IP, len(networkIP))
		for i := range networkIP {
			broadcastIP[i] = networkIP[i] | ^ipNet.Mask[i]
		}
		if ip.Equal(broadcastIP) {
			return fmt.Errorf("IP %s is the broadcast address", requestedIP)
		}
	}

	if m.allocatedIPs[networkID] == nil {
		m.allocatedIPs[networkID] = make(map[string]bool)
	}
	if m.allocatedIPs[networkID][requestedIP] {
		return fmt.Errorf("IP %s is already assigned to another member", requestedIP)
	}
	m.allocatedIPs[networkID][requestedIP] = true
	return nil
}

func (m *MemberManager) releaseIP(networkID, ip string) {
	if m.allocatedIPs[networkID] != nil {
		delete(m.allocatedIPs[networkID], ip)
	}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Remove
func (m *MemberManager) removeFromNetwork(networkID, memberID string) {
	ids := m.networkMembers[networkID]
	for i, id := range ids {
		if id == memberID {
			m.networkMembers[networkID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	if len(m.networkMembers[networkID]) == 0 {
		delete(m.networkMembers, networkID)
	}
}

// Remove
func (m *MemberManager) removeFromClient(clientID, networkID string) {
	if clientNets, ok := m.clientMembers[clientID]; ok {
		delete(clientNets, networkID)
		if len(clientNets) == 0 {
			delete(m.clientMembers, clientID)
		}
	}
}

func (m *MemberManager) UpdateMemberEndpoint(memberID, endpoint string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.updateMemberEndpoint(memberID, endpoint)
	})
}

func (m *MemberManager) updateMemberEndpoint(memberID, endpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}
	_, err := m.updateMemberEndpointLocked(member, endpoint)
	return err
}

// ApplyObservedEndpoint matches identity and persists under one lock. An
// observation in flight for a replaced key must not update the new identity.
func (m *MemberManager) ApplyObservedEndpoint(networkID, publicKey, endpoint string) (bool, error) {
	return pathSourceValue(m.networkManager, func() (bool, error) {
		return m.applyObservedEndpoint(networkID, publicKey, endpoint)
	})
}

func (m *MemberManager) applyObservedEndpoint(networkID, publicKey, endpoint string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.networkMembers[networkID] {
		if member := m.members[id]; member != nil && member.PublicKey == publicKey {
			return m.updateMemberEndpointLocked(member, endpoint)
		}
	}
	return false, nil
}

// UpdateMemberLANEndpoint updates the LAN endpoint for a member identified by
// network ID and public key.  The new value is written to both the in-memory
// member (for CLI/snapshot reads) and SQLite (for durability).  LAN endpoints
// are NOT restored on Edge restart — they are repopulated by client reports.
func (m *MemberManager) UpdateMemberLANEndpoint(networkID, publicKey, lanEndpoint string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.updateMemberLANEndpoint(networkID, publicKey, lanEndpoint)
	})
}

func (m *MemberManager) updateMemberLANEndpoint(networkID, publicKey, lanEndpoint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.networkMembers[networkID] {
		if member := m.members[id]; member != nil && member.PublicKey == publicKey {
			if member.LANEndpoint == lanEndpoint {
				return nil // no change
			}
			updated := *member
			updated.LANEndpoint = lanEndpoint
			updated.UpdatedAt = time.Now()
			m.members[id] = &updated
			// Persist to SQLite for durability.  Not used for recovery
			// (RecoverFromStorage clears LANEndpoint), but ensures the
			// value survives process-level inspection / backup.
			if m.storage != nil {
				if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
					logger.Warnf("failed to persist LAN endpoint to SQLite: member=%s err=%v", id, err)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("member not found in network %s with public key %s", networkID, publicKey)
}

// ClearNetworkLANEndpoints resets the LAN endpoint for all members of a
// network.  Called when a network is deleted so stale LAN endpoints do not
// persist in memory or SQLite.
func (m *MemberManager) ClearNetworkLANEndpoints(networkID string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.clearNetworkLANEndpoints(networkID)
	})
}

func (m *MemberManager) clearNetworkLANEndpoints(networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.networkMembers[networkID] {
		if member := m.members[id]; member != nil && member.LANEndpoint != "" {
			updated := *member
			updated.LANEndpoint = ""
			updated.UpdatedAt = time.Now()
			m.members[id] = &updated
			if m.storage != nil {
				if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
					logger.Warnf("failed to clear LAN endpoint in SQLite: member=%s err=%v", id, err)
				}
			}
		}
	}
	return nil
}

// HandleHeartbeatTimeout marks a member offline when its WireGuard handshake
// goes stale. Only members with a real public key (not relay placeholders) are
// affected. The status transition is Online → Active (temporary offline),
// mirroring the mTLS disconnect path. Leaved is reserved for explicit leave
// or permanent removal; using Active here prevents status flicker where a
// brief handshake gap would flip the member to Leaved and back to Online.
func (m *MemberManager) HandleHeartbeatTimeout(networkID, publicKey string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.handleHeartbeatTimeout(networkID, publicKey)
	})
}

func (m *MemberManager) handleHeartbeatTimeout(networkID, publicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.networkMembers[networkID] {
		member := m.members[id]
		if member == nil || member.PublicKey != publicKey {
			continue
		}
		if !hasRealPublicKey(member) {
			return nil
		}
		if member.Status != MemberStatusOnline {
			return nil // already offline/active; nothing to do
		}
		member.Status = MemberStatusActive
		member.LastOnline = time.Now()
		member.UpdatedAt = time.Now()
		if m.storage != nil {
			if err := m.storage.UpdateMember(context.Background(), member); err != nil {
				return fmt.Errorf("persist heartbeat timeout for member %s: %w", id, err)
			}
		}
		return nil
	}
	return nil
}

// SetMemberOnlineByPublicKey marks a member online by matching its public key
// within a network. This is used by the UDP observation callback to restore
// online status when a fresh WireGuard handshake is detected, enabling recovery
// after mTLS reconnects or system sleep/wake cycles.
// Returns (nil, true) when the member transitioned from non-Online to Online.
// Returns (nil, false) when the member was already Online.
func (m *MemberManager) SetMemberOnlineByPublicKey(networkID, publicKey string) (error, bool) {
	var changed bool
	err := pathSourceChange(m.networkManager, func() error {
		var err error
		err, changed = m.setMemberOnlineByPublicKey(networkID, publicKey)
		return err
	})
	return err, changed
}

func (m *MemberManager) setMemberOnlineByPublicKey(networkID, publicKey string) (error, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range m.networkMembers[networkID] {
		member := m.members[id]
		if member == nil || member.PublicKey != publicKey {
			continue
		}
		if !hasRealPublicKey(member) {
			return fmt.Errorf("member %s has no real public key", id), false
		}
		if member.Status == MemberStatusOnline {
			return nil, false // already online, no transition
		}
		if member.Status != MemberStatusActive && member.Status != MemberStatusOnline && member.Status != MemberStatusLeaved {
			return fmt.Errorf("cannot set online from status: %d", member.Status), false
		}
		member.Status = MemberStatusOnline
		member.LastOnline = time.Now()
		member.UpdatedAt = time.Now()
		// Online status is ephemeral — not persisted.
		return nil, true
	}
	return fmt.Errorf("member not found in network %s with public key %s", networkID, publicKey), false
}

func (m *MemberManager) updateMemberEndpointLocked(member *NetworkMember, endpoint string) (bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || (member.Endpoint == endpoint && !member.ObservedAt.IsZero()) {
		return false, nil
	}

	updated := *member
	updated.Endpoint = endpoint
	updated.UpdatedAt = time.Now()
	updated.ObservedAt = updated.UpdatedAt

	// Observed endpoint is ephemeral — not persisted.
	*member = updated
	return true, nil
}

func (m *MemberManager) UpdateMemberIP(memberID, newIP string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.updateMemberIP(memberID, newIP)
	})
}

func (m *MemberManager) updateMemberIP(memberID, newIP string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}

	network, err := m.networkManager.GetNetwork(member.NetworkID)
	if err != nil {
		return fmt.Errorf("network not found: %w", err)
	}

	ip := net.ParseIP(newIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", newIP)
	}

	_, ipNet, err := net.ParseCIDR(network.CIDR)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}

	if !ipNet.Contains(ip) {
		return fmt.Errorf("IP %s is not within network CIDR %s", newIP, network.CIDR)
	}

	// Check network/broadcast
	ones, bits := ipNet.Mask.Size()
	if ones < bits {
		networkIP := ipNet.IP.Mask(ipNet.Mask)
		if ip.Equal(networkIP) {
			return fmt.Errorf("IP %s is the network address", newIP)
		}
		broadcastIP := make(net.IP, len(networkIP))
		for i := range networkIP {
			broadcastIP[i] = networkIP[i] | ^ipNet.Mask[i]
		}
		if ip.Equal(broadcastIP) {
			return fmt.Errorf("IP %s is the broadcast address", newIP)
		}
	}

	// Check not already allocated to another member
	if allocated, exists := m.allocatedIPs[member.NetworkID]; exists {
		if allocated[newIP] && member.IP != newIP {
			return fmt.Errorf("IP %s is already assigned to another member", newIP)
		}
	}

	updated := *member
	updated.IP = newIP
	if member.IP != newIP {
		rotatePathMembership(&updated)
	}
	updated.UpdatedAt = time.Now()
	if m.storage != nil {
		if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
			return fmt.Errorf("persist member IP update: %w", err)
		}
	}
	if allocated, exists := m.allocatedIPs[member.NetworkID]; exists {
		delete(allocated, member.IP)
		allocated[newIP] = true
	}
	*member = updated
	return nil
}

func (m *MemberManager) UpdateMemberHostname(memberID, newHostname string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.updateMemberHostname(memberID, newHostname)
	})
}

func (m *MemberManager) updateMemberHostname(memberID, newHostname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	member, ok := m.members[memberID]
	if !ok {
		return fmt.Errorf("member not found: %s", memberID)
	}

	newHostname = strings.TrimSpace(newHostname)
	if newHostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if len(newHostname) > 64 {
		return fmt.Errorf("hostname too long (max 64): %s", newHostname)
	}

	updated := *member
	updated.HostName = newHostname
	updated.UpdatedAt = time.Now()
	if m.storage != nil {
		if err := m.storage.UpdateMember(context.Background(), &updated); err != nil {
			return fmt.Errorf("persist member hostname update: %w", err)
		}
	}
	*member = updated
	return nil
}

// RemapNetworkCIDR 把网络迁移到 newCIDR，并把全部活跃成员的 IP 重新映射进新网段。
// 映射规则：尽量保留旧 IP 的主机位（10.0.0.5/24 -> 192.168.1.5/24）；若主机位在新网段
// 内冲突 / 落在网络地址或广播地址上，则回退到新网段里下一个可用地址。整个过程在一次锁内
// 先计算出完整方案、确认无冲突，再写入网络子网与各成员 IP，保证「要么全部成功、要么全部不动」。
func (m *MemberManager) RemapNetworkCIDR(networkID, newCIDR string) error {
	return pathSourceChange(m.networkManager, func() error {
		return m.remapNetworkCIDR(networkID, newCIDR)
	})
}

func (m *MemberManager) remapNetworkCIDR(networkID, newCIDR string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, newNet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	base := newNet.IP.Mask(newNet.Mask)
	ones, bits := newNet.Mask.Size()
	hasNetBroadcast := ones < bits
	var broadcast net.IP
	if hasNetBroadcast {
		broadcast = make(net.IP, len(base))
		for i := range base {
			broadcast[i] = base[i] | ^newNet.Mask[i]
		}
	}

	isReserved := func(ip net.IP) bool {
		if !hasNetBroadcast {
			return false
		}
		return ip.Equal(base) || ip.Equal(broadcast)
	}

	// 计算阶段：构造 memberID -> newIP 方案，确保全部成员都能落入新网段且互不冲突。
	planned := make(map[string]string)
	used := make(map[string]bool)

	allocNext := func() string {
		for ip := dupIP(base); newNet.Contains(ip); incIP(ip) {
			s := ip.String()
			if used[s] || isReserved(ip) {
				continue
			}
			return s
		}
		return ""
	}

	for _, memberID := range m.networkMembers[networkID] {
		member := m.members[memberID]
		if member == nil || member.Status == MemberStatusRemoved {
			continue
		}

		var newIPStr string
		if mapped := remapHostBits(member.IP, newNet); mapped != nil && !used[mapped.String()] && !isReserved(mapped) {
			newIPStr = mapped.String()
		} else {
			newIPStr = allocNext()
		}
		if newIPStr == "" {
			return fmt.Errorf("new CIDR %s is too small to hold all members of network %s", newCIDR, networkID)
		}
		used[newIPStr] = true
		planned[memberID] = newIPStr
	}

	// 写入阶段：先改网络子网，再改成员 IP，并重建 allocatedIPs。此处仅可能因存储失败而出错。
	if err := m.networkManager.setNetworkCIDR(networkID, newCIDR); err != nil {
		return err
	}

	m.allocatedIPs[networkID] = make(map[string]bool)
	now := time.Now()
	for memberID, newIPStr := range planned {
		m.allocatedIPs[networkID][newIPStr] = true
		member := m.members[memberID]
		if member.IP != newIPStr {
			rotatePathMembership(member)
		}
		member.IP = newIPStr
		member.UpdatedAt = now
		if m.storage != nil {
			if err := m.storage.UpdateMember(context.Background(), member); err != nil {
				return fmt.Errorf("persist remapped member IP: %w", err)
			}
		}
	}
	return nil
}

// remapHostBits 把 oldIP 的主机位（相对 newNet 掩码）拼接到新网段的网络地址上，
// 用于在迁移网段时尽量保留主机号。仅支持 IPv4；无法解析时返回 nil。
func remapHostBits(oldIP string, newNet *net.IPNet) net.IP {
	parsed := net.ParseIP(oldIP)
	if parsed == nil {
		return nil
	}
	ip4 := parsed.To4()
	base := newNet.IP.Mask(newNet.Mask).To4()
	mask := net.IP(newNet.Mask).To4()
	if ip4 == nil || base == nil || mask == nil {
		return nil
	}
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = base[i] | (ip4[i] &^ mask[i])
	}
	return out
}

func dupIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
