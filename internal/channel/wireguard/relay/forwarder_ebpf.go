//go:build linux && ebpf

package relay

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"icool.io/yat/edge/internal/channel/tc"
	"icool.io/yat/edge/internal/channel/wireguard/relay/counter"
	logger "icool.io/yat/edge/pkg/log"
)

// ebpfForwarder sends intra-subnet IPv4 traffic from WireGuard ingress directly
// to the same device's egress, where WireGuard selects the peer by AllowedIPs:
//
//	peerA -> WG decrypt -> TC ingress -> bpf_redirect(wg_ifindex, 0)
//	    -> WG egress -> WG encrypt -> peerB
//
// Both ends use raw IP; no Ethernet header or veth is needed. bpf_redirect_peer
// cannot be used with a veth pair whose two ends remain in this network namespace:
// its peer must be in a DIFFERENT namespace. Returning TC_ACT_REDIRECT from that
// helper does not mean that the subsequent kernel delivery succeeded.
//
// This fast path bypasses IP routing and the netfilter FORWARD chain. Traffic
// outside the relay subnet and traffic to the relay itself use the normal stack.
type ebpfForwarder struct {
	ifName  string
	cidr    string
	relayIP string
	config  tcRedirectConfig

	mu       sync.Mutex
	ebpfProg *ebpf.Program
	statsMap *ebpf.Map // per-peer HashMap: srcIP(uint32) → PeerStatsBPFValue
	filter   *netlink.BpfFilter
	stats    ForwarderStats

	// rateLimiter provides per-peer egress rate limiting via HTB.
	rateLimiter *tc.RateLimiter
	// rateLimits tracks configured rate limits per peer IP.
	rateLimits map[string]PeerRateLimitInfo
}

// NewEBPFForwarder creates an eBPF-based IPv4 relay forwarder.
func NewEBPFForwarder(ifName, cidr, relayIP string) (Forwarder, error) {
	cfg, err := parseTCRedirectConfig(cidr, relayIP)
	if err != nil {
		return nil, err
	}
	return &ebpfForwarder{
		ifName:     ifName,
		cidr:       cidr,
		relayIP:    relayIP,
		config:     cfg,
		rateLimits: make(map[string]PeerRateLimitInfo),
	}, nil
}

func (f *ebpfForwarder) Name() string { return "ebpf" }

func (f *ebpfForwarder) Stats() ForwarderStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readStatsLocked()
}

// PeerStats returns per-peer traffic statistics from the BPF hash map.
func (f *ebpfForwarder) PeerStats() map[string]PeerTrafficStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statsMap == nil {
		return nil
	}
	stats, err := counter.ReadPeerStats(f.statsMap)
	if err != nil {
		return nil
	}
	result := make(map[string]PeerTrafficStats, len(stats))
	for ip, s := range stats {
		result[ip] = PeerTrafficStats{Bytes: s.Bytes, Packets: s.Packets, Dropped: s.Dropped}
	}
	return result
}

func (f *ebpfForwarder) readStatsLocked() ForwarderStats {
	if f.statsMap == nil {
		return f.stats
	}
	// Aggregate all per-peer stats into a global snapshot.
	allStats, err := counter.ReadPeerStats(f.statsMap)
	if err != nil {
		return f.stats
	}
	var total ForwarderStats
	for _, s := range allStats {
		total.Forwarded += s.Packets
		total.Dropped += s.Dropped
	}
	f.stats = total
	return total
}

func (f *ebpfForwarder) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ebpfProg != nil {
		return nil
	}

	link, err := netlink.LinkByName(f.ifName)
	if err != nil {
		return fmt.Errorf("lookup WireGuard interface %s: %w", f.ifName, err)
	}
	if link.Type() != "wireguard" {
		return fmt.Errorf("interface %s has type %s, want wireguard", f.ifName, link.Type())
	}
	cfg := f.config
	cfg.IfIndex = uint32(link.Attrs().Index)
	cfg.MTU = uint32(link.Attrs().MTU)

	m, err := ebpf.NewMap(counter.PeerStatsMapSpec())
	if err != nil {
		return fmt.Errorf("create eBPF peer stats map: %w", err)
	}
	prog, err := ebpf.NewProgram(newTCProgramSpec(cfg, m.FD()))
	if err != nil {
		m.Close()
		return fmt.Errorf("load eBPF program: %w", err)
	}

	// Use netlink's acknowledged requests. A nonblocking Recvfrom that treats
	// EAGAIN as success can hide a qdisc/filter installation failure.
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		prog.Close()
		m.Close()
		return fmt.Errorf("create clsact on %s: %w", f.ifName, err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "yat_redirect",
		DirectAction: true,
	}
	// FilterAdd uses CREATE|EXCL: never replace somebody else's filter.
	if err := netlink.FilterAdd(filter); err != nil {
		prog.Close()
		m.Close()
		return fmt.Errorf("attach TC ingress on %s: %w", f.ifName, err)
	}
	f.ebpfProg, f.statsMap, f.filter = prog, m, filter
	f.stats = ForwarderStats{}
	logger.Infof("ebpfForwarder started: iface=%s ifindex=%d cidr=%s relayIP=%s redirect=egress",
		f.ifName, cfg.IfIndex, f.cidr, f.relayIP)
	return nil
}

func (f *ebpfForwarder) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.filter != nil {
		if err := netlink.FilterDel(f.filter); err != nil &&
			!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENODEV) {
			return fmt.Errorf("detach TC ingress on %s: %w", f.ifName, err)
		}
		f.filter = nil
	}
	f.readStatsLocked()
	if f.ebpfProg != nil {
		f.ebpfProg.Close()
		f.ebpfProg = nil
	}
	if f.statsMap != nil {
		f.statsMap.Close()
		f.statsMap = nil
	}
	if f.rateLimiter != nil {
		if err := f.rateLimiter.Stop(); err != nil {
			logger.Warnf("ebpfForwarder: rate limiter stop failed for %s: %v", f.ifName, err)
		}
		f.rateLimiter = nil
	}
	f.rateLimits = make(map[string]PeerRateLimitInfo)
	return nil
}

// SetPeerRateLimit adds or updates a per-peer egress rate limit.
func (f *ebpfForwarder) SetPeerRateLimit(peerIP string, rate, ceil uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.rateLimiter == nil {
		rl, err := tc.NewRateLimiter(f.ifName)
		if err != nil {
			return fmt.Errorf("create rate limiter: %w", err)
		}
		if err := rl.Start(); err != nil {
			return fmt.Errorf("start rate limiter: %w", err)
		}
		f.rateLimiter = rl
	}
	if err := f.rateLimiter.AddPeer(peerIP, tc.RateLimit{Rate: rate, Ceil: ceil}); err != nil {
		return err
	}
	f.rateLimits[peerIP] = PeerRateLimitInfo{Rate: rate, Ceil: ceil}
	return nil
}

// RemovePeerRateLimit removes a per-peer egress rate limit.
func (f *ebpfForwarder) RemovePeerRateLimit(peerIP string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rateLimiter == nil {
		return nil
	}
	if err := f.rateLimiter.RemovePeer(peerIP); err != nil {
		return err
	}
	delete(f.rateLimits, peerIP)
	return nil
}

// PeerRateLimits returns a snapshot of configured per-peer rate limits.
func (f *ebpfForwarder) PeerRateLimits() map[string]PeerRateLimitInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rateLimits) == 0 {
		return nil
	}
	out := make(map[string]PeerRateLimitInfo, len(f.rateLimits))
	for ip, l := range f.rateLimits {
		out[ip] = l
	}
	return out
}
