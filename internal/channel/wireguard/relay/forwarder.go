package relay

// ForwarderStrategy identifies a same-interface forwarding strategy.
type ForwarderStrategy string

const (
	// ForwarderStrategyKernel relies on the Linux kernel's native ip_forward
	// path for same-interface peer-to-peer forwarding. No userspace packet
	// capture or injection. Requires rp_filter=0 (global + per-interface)
	// and an nftables FORWARD rule to allow same-interface traffic.
	// This is the default strategy.
	ForwarderStrategyKernel ForwarderStrategy = "kernel"

	// ForwarderStrategyEBPF redirects WG ingress directly to WG egress via TC.
	// Requires root + Linux 5.8+ + cilium/ebpf. Zero userspace packet copies.
	// Build with: go build -tags ebpf
	ForwarderStrategyEBPF ForwarderStrategy = "ebpf"
)

// Forwarder relays decrypted traffic between peers on one WireGuard interface.
// The default "kernel" strategy uses the Linux kernel's native ip_forward path;
// the optional "ebpf" strategy bypasses routing and netfilter FORWARD via TC.
//
// Both strategies support per-peer traffic statistics (via BPF HashMap) and
// per-peer egress rate limiting (via TC HTB), making them suitable for tunnel
// proxy integration where per-tenant accounting and bandwidth control are needed.
type Forwarder interface {
	// Start begins the forwarding loop.
	Start() error

	// Stop shuts down the forwarder and releases all resources.
	Stop() error

	// Stats returns a snapshot of aggregated forwarding statistics.
	// Both kernel and eBPF strategies aggregate from per-peer BPF HashMap.
	Stats() ForwarderStats

	// PeerStats returns per-peer traffic statistics keyed by assigned IP.
	// Returns nil if per-peer stats are not available (e.g. eBPF not compiled).
	PeerStats() map[string]PeerTrafficStats

	// SetPeerRateLimit adds or updates a per-peer egress rate limit.
	// rate is the guaranteed bandwidth in bytes per second; ceil is the max burst.
	// Uses TC HTB under the hood; creates the rate limiter lazily on first call.
	SetPeerRateLimit(peerIP string, rate, ceil uint64) error

	// RemovePeerRateLimit removes the per-peer egress rate limit.
	RemovePeerRateLimit(peerIP string) error

	// PeerRateLimits returns a snapshot of configured per-peer rate limits
	// keyed by peer IP. Returns nil if no rate limits are configured.
	PeerRateLimits() map[string]PeerRateLimitInfo

	// Name returns the strategy name (e.g. "kernel", "ebpf").
	Name() string
}

// ForwarderStats holds a snapshot of aggregated forwarding counters.
// Values are plain uint64 (not atomic) because this is a point-in-time copy.
// Both kernel and eBPF strategies aggregate from per-peer BPF HashMap:
//   - Forwarded: total packets forwarded across all peers
//   - Dropped:   total packets dropped (from BPF counter, not kernel drops)
//   - Errors:    reserved for future use (currently always 0)
type ForwarderStats struct {
	Forwarded uint64
	Dropped   uint64
	Errors    uint64
}

// PeerTrafficStats holds per-peer traffic counters.
type PeerTrafficStats struct {
	Bytes   uint64
	Packets uint64
	Dropped uint64
}

// PeerRateLimitInfo describes a configured per-peer egress rate limit.
type PeerRateLimitInfo struct {
	Rate uint64 // guaranteed bandwidth in bytes/sec
	Ceil uint64 // max burst bandwidth in bytes/sec
}
