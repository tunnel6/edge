//go:build linux && ebpf

package counter

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	logger "icool.io/yat/edge/pkg/log"
)

// PeerCounter attaches a TC ingress BPF program that counts per-peer
// traffic into a BPF hash map. It works alongside any existing TC filter
// (e.g. the eBPF forwarder's redirect program) at a different priority.
//
// For the kernel forwarder: counts ALL ingress traffic (complete stats).
// For the eBPF forwarder: counts only traffic that the redirect program
// passes (non-intra-subnet, to-relay-IP, etc.) — the eBPF forwarder
// tracks its own redirected traffic internally.
type PeerCounter struct {
	ifName    string
	linkIndex int
	mu        sync.Mutex
	statsMap  *ebpf.Map
	prog      *ebpf.Program
	filter    *netlink.BpfFilter
}

// NewPeerCounter creates a PeerCounter for the given interface.
func NewPeerCounter(ifName string) (*PeerCounter, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", ifName, err)
	}
	return &PeerCounter{
		ifName:    ifName,
		linkIndex: link.Attrs().Index,
	}, nil
}

// Start creates the BPF map and program, then attaches the counter filter
// to the TC ingress hook at priority 10 (after the forwarder's priority 1).
func (c *PeerCounter) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.prog != nil {
		return nil
	}

	m, err := ebpf.NewMap(PeerStatsMapSpec())
	if err != nil {
		return fmt.Errorf("create peer stats map: %w", err)
	}

	prog, err := ebpf.NewProgram(PeerCounterProgramSpec(m.FD()))
	if err != nil {
		m.Close()
		return fmt.Errorf("load peer counter program: %w", err)
	}

	// Ensure clsact qdisc exists (shared with the forwarder).
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: c.linkIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		prog.Close()
		m.Close()
		return fmt.Errorf("create clsact on %s: %w", c.ifName, err)
	}

	// Attach at priority 10, after the forwarder's redirect (priority 1).
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: c.linkIndex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    10,
			Priority:  10,
			Protocol:  syscall.ETH_P_IP,
		},
		Fd:           prog.FD(),
		Name:         "yat_peer_count",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		prog.Close()
		m.Close()
		return fmt.Errorf("attach peer counter on %s: %w", c.ifName, err)
	}

	c.statsMap = m
	c.prog = prog
	c.filter = filter
	logger.Infof("peer counter started: iface=%s priority=10", c.ifName)
	return nil
}

// Stop detaches the counter filter and releases BPF resources.
func (c *PeerCounter) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.filter != nil {
		if err := netlink.FilterDel(c.filter); err != nil &&
			!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENODEV) {
			return fmt.Errorf("detach peer counter on %s: %w", c.ifName, err)
		}
		c.filter = nil
	}
	if c.prog != nil {
		c.prog.Close()
		c.prog = nil
	}
	if c.statsMap != nil {
		c.statsMap.Close()
		c.statsMap = nil
	}
	return nil
}

// GetPeerStats returns the traffic statistics for a single peer.
func (c *PeerCounter) GetPeerStats(peerIP string) (PeerStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.statsMap == nil {
		return PeerStats{}, fmt.Errorf("peer counter not started")
	}
	ip := net.ParseIP(peerIP)
	if ip == nil {
		return PeerStats{}, fmt.Errorf("invalid peer IP: %s", peerIP)
	}
	key := IPToMapKey(ip)
	var value PeerStatsBPFValue
	if err := c.statsMap.Lookup(key, &value); err != nil {
		return PeerStats{}, err
	}
	return PeerStats{Bytes: value.Bytes, Packets: value.Packets, Dropped: value.Dropped}, nil
}

// AllPeerStats returns a snapshot of all per-peer statistics.
func (c *PeerCounter) AllPeerStats() (map[string]PeerStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.statsMap == nil {
		return nil, fmt.Errorf("peer counter not started")
	}
	return ReadPeerStats(c.statsMap)
}
