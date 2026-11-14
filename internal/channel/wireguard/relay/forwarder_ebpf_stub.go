//go:build linux && !ebpf

package relay

import "fmt"

// NewEBPFForwarder returns an error when the ebpf build tag is not set.
// To enable eBPF forwarding, build with: go build -tags ebpf
// Requires Linux 5.8+ kernel.
func NewEBPFForwarder(ifName, cidr, relayIP string) (Forwarder, error) {
	return nil, fmt.Errorf("ebpf forwarder not available: rebuild with -tags ebpf (requires Linux 5.8+)")
}
