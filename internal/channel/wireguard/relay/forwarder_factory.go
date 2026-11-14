//go:build linux

package relay

import (
	"fmt"
)

// NewForwarder creates a Forwarder for the given strategy.
// Returns an error if the strategy is unknown or unsupported on the current platform.
func NewForwarder(strategy ForwarderStrategy, ifName, cidr, relayIP string) (Forwarder, error) {
	switch strategy {
	case ForwarderStrategyKernel, "":
		return NewKernelForwarder(ifName, cidr, relayIP)
	case ForwarderStrategyEBPF:
		return NewEBPFForwarder(ifName, cidr, relayIP)
	default:
		return nil, fmt.Errorf("unknown forwarder strategy: %s", strategy)
	}
}
