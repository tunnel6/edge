package wireguard

import (
	"time"
)

// Config
type RelayMode int

const (
	RelayModeDisabled RelayMode = iota
	RelayModeOptional
	RelayModeForce
)

// Status
// Create
type NetworkStatus int

const (
	NetworkStatusNew NetworkStatus = iota
	NetworkStatusActive
	NetworkStatusDeleting
	NetworkStatusDeleted
)

// Status
type Network struct {
	ID                string
	Name              string
	CIDR              string
	CoordinatorEdgeID string
	OwnerUserID       string
	RelayMode         RelayMode
	RelayMemberID     string
	Status            NetworkStatus
	CreatedAt         time.Time
	UpdatedAt         time.Time
	// pathPolicyRevision is Edge-local authority state, not a timestamp or DB revision.
	pathPolicyRevision uint64
}

// Status

type MemberStatus int

const (
	MemberStatusPending MemberStatus = iota
	MemberStatusActive
	MemberStatusOnline
	MemberStatusLeaved
	MemberStatusRemoved
)

// Status
type NetworkMember struct {
	ID                    string
	NetworkID             string
	ClientID              string
	IP                    string
	PublicKey             string
	HostName              string
	Endpoint              string
	LANEndpoint           string   // LAN WireGuard endpoint for same-NAT direct path (e.g. "192.168.1.100:51820") — first candidate, backward compat
	LANEndpointCandidates []string // All candidate LAN endpoints (IP:PORT) for multi-NIC hosts
	// ObservedAt is the time Edge accepted the latest UDP endpoint observation,
	// independent of membership/presence updates. It is not a liveness signal.
	ObservedAt time.Time
	IsRelay    bool
	Status     MemberStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastOnline time.Time
	// Coordination-only identity. Presence/observer updates cannot restore a
	// revoked membership; an explicit successful rejoin is required.
	pathGeneration          string
	pathGenerationStartedAt time.Time
	pathRevoked             bool // persisted separately from ephemeral presence; cleared only by explicit rejoin
}
