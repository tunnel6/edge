//go:build linux

package relay

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// ScanLocalSubnets enumerates all UP, non-loopback network interfaces and
// returns their configured IP subnets. These subnets are used as forbidden
// zones when validating user-provided WireGuard network CIDRs.
func ScanLocalSubnets() ([]net.IPNet, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}

	var subnets []net.IPNet
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		// Skip loopback and down interfaces.
		if attrs.Flags&net.FlagLoopback != 0 {
			continue
		}
		if attrs.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.IPNet == nil {
				continue
			}
			// Normalise to network address.
			network := addr.IPNet.IP.Mask(addr.IPNet.Mask)
			if network == nil {
				continue
			}
			subnets = append(subnets, net.IPNet{
				IP:   network,
				Mask: addr.IPNet.Mask,
			})
		}
	}
	return subnets, nil
}
