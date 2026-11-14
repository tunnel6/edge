package wireguard

import (
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
)

func rotatePathMembership(member *NetworkMember) {
	member.pathGeneration = uuid.NewString()
	member.pathGenerationStartedAt = time.Now()
}

func revokePathMembership(member *NetworkMember) {
	if !member.pathRevoked {
		rotatePathMembership(member)
		member.pathRevoked = true
	}
}

func bumpPathPolicy(network *Network) {
	if network.pathPolicyRevision == math.MaxUint64 {
		// Zero is invalid and disables coordination until a new authority epoch.
		network.pathPolicyRevision = 0
		return
	}
	if network.pathPolicyRevision != 0 {
		network.pathPolicyRevision++
	}
}

func pathMembership(member *NetworkMember) (pathcoord.Membership, error) {
	if member == nil || member.IsRelay || member.pathRevoked || member.Status == MemberStatusPending ||
		member.Status == MemberStatusRemoved {
		return pathcoord.Membership{}, pathcoord.ErrMembershipRevoked
	}
	if member.pathGeneration == "" {
		return pathcoord.Membership{}, fmt.Errorf("WG membership generation not initialized")
	}
	observedAt := uint64(0)
	endpoint := ""
	if !member.ObservedAt.IsZero() && member.ObservedAt.UnixMilli() > 0 {
		observedAt = uint64(member.ObservedAt.UnixMilli())
		endpoint = member.Endpoint // persisted historical EP without a fresh observation is not a candidate
	}
	return pathcoord.Membership{MemberID: member.ID, DeviceID: member.ClientID, PublicKey: member.PublicKey,
		AssignedIP: member.IP, Generation: member.pathGeneration, GenerationStartedAt: member.pathGenerationStartedAt, ObservedEndpoint: endpoint, ObservedAt: observedAt,
		EndpointAcceptedAt: member.ObservedAt}, nil
}

// pathNetworkLocked requires both managers locked, in member -> network order.
func (m *MemberManager) pathNetworkLocked(networkID string) (pathcoord.NetworkBinding, error) {
	network := m.networkManager.networks[networkID]
	if network == nil || network.Status != NetworkStatusActive {
		return pathcoord.NetworkBinding{}, pathcoord.ErrMembershipRevoked
	}
	n := pathcoord.NetworkBinding{NetworkID: network.ID, CoordinatorID: network.CoordinatorEdgeID,
		PolicyRevision: network.pathPolicyRevision, RelayMode: fb.WGRelayMode(network.RelayMode)}
	if network.RelayMode != RelayModeDisabled && network.RelayMemberID != "" {
		relay := m.members[network.RelayMemberID]
		if relay == nil || !relay.IsRelay || relay.NetworkID != networkID || relay.Status == MemberStatusRemoved ||
			relay.Status == MemberStatusLeaved {
			return pathcoord.NetworkBinding{}, fmt.Errorf("WG relay registry identity unavailable")
		}
		n.RelayPublicKey = relay.PublicKey
	}
	return n, nil
}

// PathMember/PathPair are narrow immutable snapshots. Legacy getters keep their
// existing API; runtime coordination never retains their unlocked pointers.
func (m *MemberManager) PathMember(networkID, authenticatedDeviceID string) (pathcoord.MemberBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.networkManager.mu.RLock()
	defer m.networkManager.mu.RUnlock()
	n, err := m.pathNetworkLocked(networkID)
	if err != nil {
		return pathcoord.MemberBinding{}, err
	}
	live := m.members[m.clientMembers[authenticatedDeviceID][networkID]]
	if live == nil || live.NetworkID != networkID || live.ClientID != authenticatedDeviceID {
		return pathcoord.MemberBinding{}, pathcoord.ErrMembershipRevoked
	}
	member, err := pathMembership(live)
	if err != nil {
		return pathcoord.MemberBinding{}, err
	}
	return pathcoord.MemberBinding{Network: n, Member: member}, nil
}

func (m *MemberManager) PathPair(pair pathcoord.PairKey) (pathcoord.PairBinding, error) {
	canonical, err := pathcoord.NewPairKey(pair.NetworkID, pair.MemberAID, pair.MemberBID)
	if err != nil || canonical != pair {
		return pathcoord.PairBinding{}, fmt.Errorf("invalid WG membership pair")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.networkManager.mu.RLock()
	defer m.networkManager.mu.RUnlock()
	n, err := m.pathNetworkLocked(pair.NetworkID)
	if err != nil {
		return pathcoord.PairBinding{}, err
	}
	b := pathcoord.PairBinding{Network: n}
	for i, id := range [2]string{pair.MemberAID, pair.MemberBID} {
		member := m.members[id]
		if member == nil || member.NetworkID != pair.NetworkID {
			return pathcoord.PairBinding{}, pathcoord.ErrMembershipRevoked
		}
		b.Members[i], err = pathMembership(member)
		if err != nil {
			return pathcoord.PairBinding{}, err
		}
	}
	return b, nil
}

// pathOverviewSnapshot copies network policy and membership identity under the
// same member -> network lock order as PathMember. Never serialize live manager
// pointers: a concurrent leave/key/IP update must not race a generation read.
func (m *MemberManager) pathOverviewSnapshot(networkID string) (*Network, []*NetworkMember, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.networkManager.mu.RLock()
	defer m.networkManager.mu.RUnlock()
	network := m.networkManager.networks[networkID]
	if network == nil {
		return nil, nil, fmt.Errorf("network not found: %s", networkID)
	}
	n := *network
	members := make([]*NetworkMember, 0, len(m.networkMembers[networkID]))
	for _, id := range m.networkMembers[networkID] {
		if member := m.members[id]; member != nil {
			copy := *member
			copy.LANEndpointCandidates = append([]string(nil), member.LANEndpointCandidates...)
			members = append(members, &copy)
		}
	}
	return &n, members, nil
}

var _ pathcoord.MembershipReader = (*MemberManager)(nil)

// PathObservedMember resolves only an active, unambiguous authoritative identity.
// The generation's local start time rejects reads begun before a same-key rejoin.
func (m *MemberManager) PathObservedMember(networkID, publicKey string) (pathcoord.MemberBinding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.networkManager.mu.RLock()
	defer m.networkManager.mu.RUnlock()
	n, err := m.pathNetworkLocked(networkID)
	if err != nil {
		return pathcoord.MemberBinding{}, err
	}
	var found *NetworkMember
	for _, id := range m.networkMembers[networkID] {
		member := m.members[id]
		if member == nil || member.PublicKey != publicKey {
			continue
		}
		if _, err := pathMembership(member); err != nil {
			continue
		}
		if found != nil {
			return pathcoord.MemberBinding{}, fmt.Errorf("ambiguous WG observation key")
		}
		found = member
	}
	member, err := pathMembership(found)
	return pathcoord.MemberBinding{Network: n, Member: member}, err
}

