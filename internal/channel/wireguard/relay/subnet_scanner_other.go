//go:build !linux

package relay

import "net"

// ScanLocalSubnets is a no-op on non-Linux platforms.
func ScanLocalSubnets() ([]net.IPNet, error) {
	return nil, nil
}
