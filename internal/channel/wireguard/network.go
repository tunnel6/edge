package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"icool.io/yat/edge/internal/channel/wireguard/relay"
)

// Create

// Create
// Status

type NetworkManager struct {
	pathSources      pathSourceGate
	networks         map[string]*Network // networkID -> Network
	mu               sync.RWMutex
	storage          Storage
	forbiddenSubnets []net.IPNet
}

// Create
func NewNetworkManager() *NetworkManager {
	return &NetworkManager{
		networks: make(map[string]*Network),
	}
}

func (m *NetworkManager) SetStorage(s Storage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage = s
}

// SetForbiddenSubnets injects the edge's local physical subnets so that
// CreateNetwork can reject CIDRs that would conflict with the host's own
// network interfaces.
func (m *NetworkManager) SetForbiddenSubnets(subnets []net.IPNet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forbiddenSubnets = subnets
}

// CIDRConflictError is returned when a user-provided CIDR overlaps with the
// edge's local physical subnets. It carries suggested alternatives.
type CIDRConflictError struct {
	CIDR            string
	ConflictingWith string
	SuggestedCIDRs  []string
}

func (e *CIDRConflictError) Error() string {
	return fmt.Sprintf("CIDR %s conflicts with %s", e.CIDR, e.ConflictingWith)
}

// IsCIDRConflict reports whether err is a *CIDRConflictError.
func IsCIDRConflict(err error) bool {
	var target *CIDRConflictError
	return errors.As(err, &target)
}

// AsCIDRConflict returns the *CIDRConflictError if err is one, or nil.
func AsCIDRConflict(err error) *CIDRConflictError {
	var target *CIDRConflictError
	if errors.As(err, &target) {
		return target
	}
	return nil
}

// Create
type CreateNetworkRequest struct {
	ID                string
	Name              string
	CIDR              string
	CoordinatorEdgeID string
	OwnerUserID       string
	RelayMode         RelayMode
}

func relayModeEnabled(mode RelayMode) bool {
	return mode != RelayModeDisabled
}

func networkUsesRelay(network *Network) bool {
	return network != nil && relayModeEnabled(network.RelayMode)
}

// Create
// Status
func (m *NetworkManager) CreateNetwork(req *CreateNetworkRequest) (*Network, error) {
	return pathSourceValue(m, func() (*Network, error) {
		return m.createNetwork(req)
	})
}

func (m *NetworkManager) createNetwork(req *CreateNetworkRequest) (*Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check
	if _, exists := m.networks[req.ID]; exists {
		return nil, fmt.Errorf("network already exists: %s", req.ID)
	}

	// Check
	if req.CIDR == "" {
		return nil, fmt.Errorf("CIDR cannot be empty")
	}

	// Check CIDR uniqueness against existing networks (overlap, not just exact match).
	for _, n := range m.networks {
		if relay.CIDROverlaps(n.CIDR, req.CIDR) {
			return nil, &CIDRConflictError{
				CIDR:            req.CIDR,
				ConflictingWith: fmt.Sprintf("existing network %s (CIDR %s)", n.ID, n.CIDR),
			}
		}
	}

	// Check CIDR against edge local physical subnets.
	if conflict := m.checkCIDRAgainstLocalSubnetsLocked(req.CIDR); conflict != nil {
		return nil, conflict
	}

	now := time.Now()
	network := &Network{
		ID:                 req.ID,
		Name:               req.Name,
		CIDR:               req.CIDR,
		CoordinatorEdgeID:  req.CoordinatorEdgeID,
		OwnerUserID:        req.OwnerUserID,
		RelayMode:          req.RelayMode,
		Status:             NetworkStatusActive,
		CreatedAt:          now,
		UpdatedAt:          now,
		pathPolicyRevision: 1,
	}

	m.networks[req.ID] = network

	// Config
	if m.storage != nil {
		if err := m.storage.SaveNetwork(context.Background(), network); err != nil {
			return nil, fmt.Errorf("persist network: %w", err)
		}
	}
	return network, nil
}

// checkCIDRAgainstLocalSubnetsLocked returns a *CIDRConflictError if the given
// CIDR overlaps with any of the edge's local physical subnets.
// The caller must hold m.mu (read or write).
func (m *NetworkManager) checkCIDRAgainstLocalSubnetsLocked(cidr string) *CIDRConflictError {
	_, candidateNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil // invalid CIDR is caught elsewhere
	}

	for _, subnet := range m.forbiddenSubnets {
		if subnet.Contains(candidateNet.IP) || candidateNet.Contains(subnet.IP) {
			// Build existing CIDR list for suggestions.
			existing := make([]string, 0, len(m.networks))
			for _, n := range m.networks {
				existing = append(existing, n.CIDR)
			}
			return &CIDRConflictError{
				CIDR:            cidr,
				ConflictingWith: subnet.String(),
				SuggestedCIDRs:  relay.GenerateSuggestedCIDRs(m.forbiddenSubnets, existing),
			}
		}
	}
	return nil
}

// Get
func (m *NetworkManager) GetNetwork(networkID string) (*Network, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	network, ok := m.networks[networkID]
	if !ok {
		return nil, fmt.Errorf("network not found: %s", networkID)
	}
	return network, nil
}

func (m *NetworkManager) ListNetworks() []*Network {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Network, 0, len(m.networks))
	for _, n := range m.networks {
		list = append(list, n)
	}
	return list
}

// Delete
// Status
// Mark
func (m *NetworkManager) DeleteNetwork(networkID string) error {
	return pathSourceChange(m, func() error {
		return m.deleteNetwork(networkID)
	})
}

func (m *NetworkManager) deleteNetwork(networkID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	network, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network not found: %s", networkID)
	}

	if network.Status == NetworkStatusDeleted {
		return fmt.Errorf("network already deleted: %s", networkID)
	}

	// Clean
	network.Status = NetworkStatusDeleting
	network.UpdatedAt = time.Now()

	// Mark
	// Clean
	network.Status = NetworkStatusDeleted
	network.UpdatedAt = time.Now()

	// Delete
	delete(m.networks, networkID)

	// Delete
	if m.storage != nil {
		if err := m.storage.DeleteNetwork(context.Background(), networkID); err != nil {
			return fmt.Errorf("persist delete network: %w", err)
		}
	}
	return nil
}

// Update
func (m *NetworkManager) UpdateRelayMode(networkID string, mode RelayMode) error {
	return pathSourceChange(m, func() error {
		return m.updateRelayMode(networkID, mode)
	})
}

func (m *NetworkManager) updateRelayMode(networkID string, mode RelayMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	network, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network not found: %s", networkID)
	}

	if network.Status != NetworkStatusActive {
		return fmt.Errorf("cannot update network in status: %d", network.Status)
	}

	if network.RelayMode != mode {
		bumpPathPolicy(network)
	}
	network.RelayMode = mode
	network.UpdatedAt = time.Now()
	if m.storage != nil {
		if err := m.storage.SaveNetwork(context.Background(), network); err != nil {
			return fmt.Errorf("persist network relay mode update: %w", err)
		}
	}
	return nil
}

func (m *NetworkManager) SetRelayMemberID(networkID, relayMemberID string) error {
	return pathSourceChange(m, func() error {
		return m.setRelayMemberID(networkID, relayMemberID)
	})
}

func (m *NetworkManager) setRelayMemberID(networkID, relayMemberID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	network, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network not found: %s", networkID)
	}
	if network.Status != NetworkStatusActive {
		return fmt.Errorf("cannot update network in status: %d", network.Status)
	}

	if network.RelayMemberID == relayMemberID {
		return nil
	}
	network.RelayMemberID = relayMemberID
	bumpPathPolicy(network)
	network.UpdatedAt = time.Now()
	if m.storage != nil {
		if err := m.storage.SaveNetwork(context.Background(), network); err != nil {
			return fmt.Errorf("persist network relay member update: %w", err)
		}
	}
	return nil
}

// SetNetworkCIDR 只校验 CIDR 格式并写入网络子网，不校验成员 IP 是否落在新网段内。
// 成员 IP 的迁移由 MemberManager.RemapNetworkCIDR 负责（见 coordinator.UpdateNetworkCIDR），
// 二者在同一逻辑操作里完成，避免「改网段」与「改成员 IP」互相阻塞的死锁。
func (m *NetworkManager) SetNetworkCIDR(networkID, newCIDR string) error {
	return pathSourceChange(m, func() error {
		return m.setNetworkCIDR(networkID, newCIDR)
	})
}

func (m *NetworkManager) setNetworkCIDR(networkID, newCIDR string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	network, ok := m.networks[networkID]
	if !ok {
		return fmt.Errorf("network not found: %s", networkID)
	}
	if network.Status != NetworkStatusActive {
		return fmt.Errorf("cannot update network in status: %d", network.Status)
	}

	if _, _, err := net.ParseCIDR(newCIDR); err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check CIDR overlap against other existing networks.
	for _, n := range m.networks {
		if n.ID == networkID {
			continue // skip self
		}
		if relay.CIDROverlaps(n.CIDR, newCIDR) {
			return &CIDRConflictError{
				CIDR:            newCIDR,
				ConflictingWith: fmt.Sprintf("existing network %s (CIDR %s)", n.ID, n.CIDR),
			}
		}
	}

	if network.CIDR != newCIDR {
		bumpPathPolicy(network)
	}
	network.CIDR = newCIDR
	network.UpdatedAt = time.Now()

	if m.storage != nil {
		if err := m.storage.SaveNetwork(context.Background(), network); err != nil {
			return fmt.Errorf("persist network CIDR update: %w", err)
		}
	}
	return nil
}
