//go:build linux

// Package tc provides reusable Linux Traffic Control primitives for rate
// limiting. It encapsulates HTB qdisc management with per-peer classes and
// u32 classifiers, and is designed to be shared by WireGuard relay and
// tunnel proxy channels.
package tc

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

// RateLimit describes a peer's bandwidth envelope.
type RateLimit struct {
	// Rate is the guaranteed bandwidth in bytes per second.
	Rate uint64
	// Ceil is the maximum burst bandwidth in bytes per second.
	// Zero defaults to Rate (no bursting).
	Ceil uint64
}

// RateLimiter manages an HTB egress qdisc with per-peer classes and
// u32 source-IP classifiers on a network interface.
//
// Equivalent tc commands:
//
//	tc qdisc add dev <ifName> root handle 1: htb default 1
//	tc class add dev <ifName> parent 1: classid 1:2 htb rate <Rate> ceil <Ceil>
//	tc filter add dev <ifName> parent 1: protocol ip u32 \
//	   match ip src <peerIP>/32 classid 1:2
type RateLimiter struct {
	ifName    string
	linkIndex int
	mu        sync.Mutex
	peers     map[string]uint32 // peerIP → class minor number
	nextMinor uint32
}

// NewRateLimiter creates a RateLimiter for the given interface.
// Call Start to install the HTB qdisc.
func NewRateLimiter(ifName string) (*RateLimiter, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", ifName, err)
	}
	return &RateLimiter{
		ifName:    ifName,
		linkIndex: link.Attrs().Index,
		peers:     make(map[string]uint32),
		nextMinor: 2, // 1:1 is the root class
	}, nil
}

// Start installs the HTB root qdisc on the interface.
func (r *RateLimiter) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	htb := netlink.NewHtb(netlink.QdiscAttrs{
		LinkIndex: r.linkIndex,
		Handle:    netlink.MakeHandle(1, 0),
		Parent:    netlink.HANDLE_ROOT,
	})
	htb.Defcls = 1 // unclassified → class 1:1 (no rate limit)
	if err := netlink.QdiscAdd(htb); err != nil {
		return fmt.Errorf("add HTB qdisc on %s: %w", r.ifName, err)
	}
	return nil
}

// Stop removes the HTB qdisc and all associated classes and filters.
func (r *RateLimiter) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove all peer filters and classes.
	for ip, minor := range r.peers {
		r.removePeerLocked(ip, minor)
	}

	// Remove the root qdisc.
	link, _ := netlink.LinkByIndex(r.linkIndex)
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs on %s: %w", r.ifName, err)
	}
	for _, q := range qdiscs {
		if q.Attrs().Handle == netlink.MakeHandle(1, 0) && q.Attrs().Parent == netlink.HANDLE_ROOT {
			if err := netlink.QdiscDel(q); err != nil {
				return fmt.Errorf("remove HTB qdisc on %s: %w", r.ifName, err)
			}
			break
		}
	}
	return nil
}

// AddPeer adds or updates a per-peer rate limit class.
// Traffic from the given IP is classified into an HTB class with the
// specified rate and ceil.
func (r *RateLimiter) AddPeer(peerIP string, limit RateLimit) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if limit.Ceil == 0 {
		limit.Ceil = limit.Rate
	}

	// Update existing class if present.
	if minor, ok := r.peers[peerIP]; ok {
		return r.updateClassLocked(minor, limit)
	}

	minor := r.nextMinor
	r.nextMinor++

	classHandle := netlink.MakeHandle(1, uint16(minor))
	class := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: r.linkIndex,
			Handle:    classHandle,
			Parent:    netlink.MakeHandle(1, 0),
		},
		Rate:    limit.Rate,
		Ceil:    limit.Ceil,
		Buffer:  15 * 1024, // 15 KB buffer
		Cbuffer: 15 * 1024,
	}
	if err := netlink.ClassAdd(class); err != nil {
		return fmt.Errorf("add HTB class 1:%d: %w", minor, err)
	}

	// Add u32 filter: match ip src <peerIP>/32 → classid 1:<minor>
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: r.linkIndex,
			Parent:    netlink.MakeHandle(1, 0),
			Priority:  1,
			Protocol:  syscall.ETH_P_IP,
		},
		ClassId: netlink.MakeHandle(1, uint16(minor)),
		Sel: &netlink.TcU32Sel{
			Nkeys: 1,
			Flags: netlink.TC_U32_TERMINAL,
			Keys: []netlink.TcU32Key{{
				Mask: 0xFFFFFFFF,
				Val:  binary.BigEndian.Uint32(net.ParseIP(peerIP).To4()),
				Off:  12, // IPv4 source address offset
			}},
		},
	}
	if err := netlink.FilterAdd(filter); err != nil {
		netlink.ClassDel(class)
		return fmt.Errorf("add u32 filter for %s: %w", peerIP, err)
	}

	r.peers[peerIP] = minor
	return nil
}

// RemovePeer removes a peer's rate limit class and filter.
func (r *RateLimiter) RemovePeer(peerIP string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	minor, ok := r.peers[peerIP]
	if !ok {
		return nil
	}
	r.removePeerLocked(peerIP, minor)
	return nil
}

// SetRate updates an existing peer's rate limit.
func (r *RateLimiter) SetRate(peerIP string, limit RateLimit) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	minor, ok := r.peers[peerIP]
	if !ok {
		return fmt.Errorf("no rate limit class for peer %s", peerIP)
	}
	return r.updateClassLocked(minor, limit)
}

func (r *RateLimiter) removePeerLocked(peerIP string, minor uint32) {
	classHandle := netlink.MakeHandle(1, uint16(minor))

	// Delete the u32 filter.
	link, _ := netlink.LinkByIndex(r.linkIndex)
	filters, _ := netlink.FilterList(link, netlink.MakeHandle(1, 0))
	for _, f := range filters {
		if u32, ok := f.(*netlink.U32); ok && u32.ClassId == classHandle {
			netlink.FilterDel(f)
			break
		}
	}

	// Delete the HTB class.
	class := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: r.linkIndex,
			Handle:    classHandle,
			Parent:    netlink.MakeHandle(1, 0),
		},
	}
	netlink.ClassDel(class)

	delete(r.peers, peerIP)
}

func (r *RateLimiter) updateClassLocked(minor uint32, limit RateLimit) error {
	if limit.Ceil == 0 {
		limit.Ceil = limit.Rate
	}
	classHandle := netlink.MakeHandle(1, uint16(minor))
	class := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: r.linkIndex,
			Handle:    classHandle,
			Parent:    netlink.MakeHandle(1, 0),
		},
		Rate:    limit.Rate,
		Ceil:    limit.Ceil,
		Buffer:  15 * 1024,
		Cbuffer: 15 * 1024,
	}
	return netlink.ClassChange(class)
}

// LinkIndex returns the interface index for use by other TC consumers.
func (r *RateLimiter) LinkIndex() int {
	return r.linkIndex
}
