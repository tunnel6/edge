package relay

import (
	"context"
	"net"
	"time"
)

// PeerRateLimitRecord is the storage-layer representation of a persisted
// per-peer rate limit. The relay package defines it so that the concrete
// storage implementation (e.g. wireguard.sqliteStorage) can be injected
// without the relay package depending on the wireguard package.
type PeerRateLimitRecord struct {
	NetworkID string
	PeerIP    string
	Rate      uint64
	Ceil      uint64
	UpdatedAt time.Time
}

// PeerRateLimitStore persists per-peer rate limits so they survive edge
// restarts. Implementations must be safe for concurrent use.
type PeerRateLimitStore interface {
	SavePeerRateLimit(ctx context.Context, networkID, peerIP string, rate, ceil uint64) error
	DeletePeerRateLimit(ctx context.Context, networkID, peerIP string) error
	DeleteNetworkPeerRateLimits(ctx context.Context, networkID string) error
	LoadPeerRateLimits(ctx context.Context) ([]PeerRateLimitRecord, error)
}

// RelayManager manages per-network WireGuard observation interfaces and
// per-peer UDP relay listeners on the edge server. Edge acts as a WG peer for
// every network (heartbeat/endpoint observation), while encrypted datagrams
// that use a peer relay port are forwarded through an isolated UDP flow.
type RelayManager interface {
	// CreateNetworkInterface creates a WG interface for the given network,
	// generates/loads a keypair, and returns the relay node info.
	CreateNetworkInterface(req CreateInterfaceRequest) (*RelayNodeInfo, error)

	// SetObservationOnly changes forwarding without replacing the WG interface,
	// preserving its public key, listen port and authenticated peer endpoints.
	SetObservationOnly(networkID string, observationOnly bool) error

	// DeleteNetworkInterface tears down the WG interface for a network.
	DeleteNetworkInterface(networkID string) error

	// AddPeer adds a client peer to the network's WG interface.
	AddPeer(networkID string, peer PeerConfig) error

	// RemovePeer removes a client peer from the network's WG interface.
	RemovePeer(networkID string, publicKey string) error

	// GetObservedEndpoints returns the latest observed endpoints for all peers
	// on the given network's interface.
	GetObservedEndpoints(networkID string) ([]ObservedEndpoint, error)

	// GetRelayNodeInfo returns the relay node info for a network.
	GetRelayNodeInfo(networkID string) (*RelayNodeInfo, error)

	// Start begins the endpoint observation loop.
	Start() error

	// Stop shuts down all interfaces and the observation loop.
	Stop() error

	// SetOnEndpointChange registers an observation reconciliation callback. It
	// may repeat unchanged values so recovery/rejoin and failed writes can retry.
	SetOnEndpointChange(fn func(networkID, publicKey, endpoint string))

	// SetOnHeartbeatTimeout registers a callback invoked when a peer's WG
	// handshake goes stale (no new handshake within the heartbeat window).
	// The coordinator uses this to mark the member offline purely based on
	// UDP liveness, independent of the mTLS control connection.
	SetOnHeartbeatTimeout(fn func(networkID, publicKey string))

	// LocalSubnets returns the edge's local physical subnets scanned at startup.
	LocalSubnets() []net.IPNet

	// SuggestCIDRs returns up to 5 non-conflicting CIDR suggestions based on
	// the scanned local subnets and the provided existing network CIDRs.
	SuggestCIDRs(existingCIDRs []string) []string

	// DetectSameNATPeers returns pairs of peers within the given network
	// that share the same observed public IP, indicating they are likely
	// behind the same NAT.
	DetectSameNATPeers(networkID string) []SameNATPair

	// GetNetworkRuntimeInfo returns runtime forwarding statistics, route table
	// info, and per-peer traffic data for a network. Returns an error if the
	// network is not active.
	GetNetworkRuntimeInfo(networkID string) (*NetworkRuntimeInfo, error)

	// SetPeerRateLimit adds or updates a per-peer egress rate limit (bytes/sec).
	SetPeerRateLimit(networkID, peerIP string, rate, ceil uint64) error

	// RemovePeerRateLimit removes a per-peer egress rate limit.
	RemovePeerRateLimit(networkID, peerIP string) error

	// GetPeerRateLimit returns the rate limit for a specific peer, or
	// false if no limit is configured.
	GetPeerRateLimit(networkID, peerIP string) (PeerRateLimitInfo, bool)

	// SetPeerRateLimitStore injects the persistence layer for rate limits.
	// Called once during startup; nil disables persistence.
	SetPeerRateLimitStore(store PeerRateLimitStore)

	// RestorePeerRateLimits re-applies persisted rate limits from the store
	// to all active network interfaces. Called once after all networks are
	// created during startup.
	RestorePeerRateLimits() error
}

type CreateInterfaceRequest struct {
	NetworkID string
	CIDR      string // e.g. "10.0.0.0/24", relay will take .1
	// ObservationOnly keeps the WireGuard interface for endpoint observation
	// but does not create per-peer UDP relay listeners.
	ObservationOnly bool
}

type PeerConfig struct {
	PublicKey  string
	AssignedIP string // e.g. "10.0.0.2"
	// Endpoint is the peer's last known UDP address (e.g. "1.2.3.4:51820").
	// When set, the WG interface is configured with this endpoint so that
	// the kernel can proactively initiate handshakes instead of waiting
	// for the peer to send traffic first.  This is critical for recovery
	// after Edge restart when the peer's NAT mapping may have expired.
	Endpoint string
	// RelayPort is optional. Zero allocates a stable per-peer relay port.
	RelayPort int
}

// RelayPeerInfo describes a relay endpoint dedicated to one peer.
type RelayPeerInfo struct {
	PublicKey  string
	AssignedIP string
	Endpoint   string
	ListenPort int
}

type RelayNodeInfo struct {
	MemberID   string
	HostName   string
	PublicKey  string
	Endpoint   string // edge public IP:port
	AssignedIP string
	ListenPort int
	// PeerEndpoints contains one independent relay endpoint per client peer.
	PeerEndpoints []RelayPeerInfo
}

type ObservedEndpoint struct {
	InterfaceGeneration  string
	StartedAt, SampledAt time.Time
	PublicKey            string
	Endpoint             *net.UDPAddr
	LastHandshakeTime    time.Time
	// RxBytes is the total bytes received from this peer (wgctrl ReceiveBytes).
	// Includes all WG traffic: handshake, keepalive (PK), and data packets.
	// Logged for debugging; liveness is determined by LastHandshakeTime.
	RxBytes int64
}

// SameNATPair describes two peers observed behind the same public IP
// (and therefore likely behind the same NAT).  The coordinator uses
// this to trigger LAN-endpoint gathering so that the peers can
// communicate directly over the LAN instead of through the relay.
type SameNATPair struct {
	PeerA    string // public key of the first peer
	PeerB    string // public key of the second peer
	PublicIP string // shared public IP address
}

// NetworkRuntimeInfo holds runtime forwarding and routing information
// for an active network. Unlike database-persisted data, this reflects
// the live state of the relay manager and its forwarder.
type NetworkRuntimeInfo struct {
	// InterfaceName is the Linux WG interface name (e.g. "wg-yat0-abc").
	InterfaceName string
	// ForwarderStrategy is the active forwarding strategy ("kernel" or "ebpf").
	ForwarderStrategy string
	// RouteTableID is the Linux routing table allocated for this network.
	// Zero means no table is allocated.
	RouteTableID uint32
	// ForwarderStats holds aggregated forwarding counters.
	ForwarderStats ForwarderStats
	// PeerStats holds per-peer traffic counters keyed by assigned IP.
	PeerStats map[string]PeerTrafficStats
	// RateLimits holds configured per-peer rate limits keyed by assigned IP.
	RateLimits map[string]PeerRateLimitInfo
}
