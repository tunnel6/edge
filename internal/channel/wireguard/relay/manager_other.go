//go:build !linux

package relay

import "fmt"

// NewLinuxRelayManager is only available on Linux.
// On other platforms, it returns an error.
func NewLinuxRelayManager(cfg *Config) (RelayManager, error) {
	return nil, fmt.Errorf("relay manager only supported on linux")
}
