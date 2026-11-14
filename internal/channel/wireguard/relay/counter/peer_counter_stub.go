//go:build linux && !ebpf

package counter

import "fmt"

// PeerCounter is not available without the ebpf build tag.
type PeerCounter struct {
	ifName string
}

// NewPeerCounter returns an error when the ebpf build tag is not set.
func NewPeerCounter(ifName string) (*PeerCounter, error) {
	return nil, fmt.Errorf("peer counter not available: rebuild with -tags ebpf")
}

// Start is a no-op stub.
func (c *PeerCounter) Start() error {
	return fmt.Errorf("peer counter not available: rebuild with -tags ebpf")
}

// Stop is a no-op stub.
func (c *PeerCounter) Stop() error { return nil }

// GetPeerStats is a no-op stub.
func (c *PeerCounter) GetPeerStats(peerIP string) (PeerStats, error) {
	return PeerStats{}, fmt.Errorf("peer counter not available")
}

// AllPeerStats is a no-op stub.
func (c *PeerCounter) AllPeerStats() (map[string]PeerStats, error) {
	return nil, fmt.Errorf("peer counter not available")
}
