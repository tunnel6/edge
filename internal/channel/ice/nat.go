package ice

import (
	"fmt"
	"net"
	"sync"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

type NATDetector struct {
	probes map[string]*natProbeState
	mu     sync.Mutex
}

type natProbeState struct {
	primaryAddr *net.UDPAddr
	altAddr     *net.UDPAddr

	filterProbeStarted bool
	filterProbeDone    bool
	filterProbePass    bool
}

func NewNATDetector() *NATDetector {
	return &NATDetector{
		probes: make(map[string]*natProbeState),
	}
}

func (d *NATDetector) RecordProbe(ufrag string, addr *net.UDPAddr, isAlt bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.probes[ufrag]
	if !ok {
		state = &natProbeState{}
		d.probes[ufrag] = state
	}

	if isAlt {
		state.altAddr = cloneUDPAddr(addr)
	} else {
		state.primaryAddr = cloneUDPAddr(addr)
	}
}

func (d *NATDetector) Detect(ufrag string) (p2p.NATType, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.probes[ufrag]
	if !ok || state.primaryAddr == nil {
		return p2p.NATUnknown, false
	}
	if state.altAddr == nil {
		return p2p.NATUnknown, false
	}

	if state.primaryAddr.Port == state.altAddr.Port {
		if state.filterProbeDone {
			if state.filterProbePass {
				return p2p.NATRestrictedCone, true
			}
			return p2p.NATPortRestricted, true
		}
		return p2p.NATFullCone, true
	}
	return p2p.NATSymmetric, true
}

// StartFilterProbe marks a non-symmetric candidate for asynchronous
// NAT2/NAT3 filter probing and returns the mapped public target address.
func (d *NATDetector) StartFilterProbe(ufrag string) (*net.UDPAddr, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.probes[ufrag]
	if !ok || state.primaryAddr == nil || state.altAddr == nil {
		return nil, false
	}
	if state.primaryAddr.Port != state.altAddr.Port {
		return nil, false
	}
	if state.filterProbeStarted || state.filterProbeDone {
		return nil, false
	}
	state.filterProbeStarted = true
	return cloneUDPAddr(state.primaryAddr), true
}

// RecordFilterProbeResult persists asynchronous filter probe outcome.
func (d *NATDetector) RecordFilterProbeResult(ufrag string, pass bool) (p2p.NATType, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.probes[ufrag]
	if !ok || state.primaryAddr == nil || state.altAddr == nil {
		return p2p.NATUnknown, false
	}
	if state.primaryAddr.Port != state.altAddr.Port {
		return p2p.NATSymmetric, true
	}
	state.filterProbeDone = true
	state.filterProbePass = pass
	if pass {
		return p2p.NATRestrictedCone, true
	}
	return p2p.NATPortRestricted, true
}

func (d *NATDetector) Clear(ufrag string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.probes, ufrag)
}

func (d *NATDetector) GetPublicAddr(ufrag string) *net.UDPAddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.probes[ufrag]
	if !ok || state.primaryAddr == nil {
		return nil
	}
	return cloneUDPAddr(state.primaryAddr)
}

func (d *NATDetector) PredictPorts(ufrag string, peerIP string, count int) []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.probes[ufrag]
	if !ok || state.primaryAddr == nil || state.altAddr == nil {
		return nil
	}

	basePort := state.altAddr.Port
	delta := state.altAddr.Port - state.primaryAddr.Port

	var predicted []string
	if delta != 0 {
		for i := 1; i <= count; i++ {
			port := basePort + delta*i
			if port > 0 && port <= 65535 {
				predicted = append(predicted, fmt.Sprintf("%s:%d", peerIP, port))
			}
		}
	} else {
		spread := count / 2
		for i := 1; i <= spread; i++ {
			if p := basePort + i; p <= 65535 {
				predicted = append(predicted, fmt.Sprintf("%s:%d", peerIP, p))
			}
			if p := basePort - i; p > 0 {
				predicted = append(predicted, fmt.Sprintf("%s:%d", peerIP, p))
			}
		}
	}
	return predicted
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	cp := *addr
	if addr.IP != nil {
		cp.IP = append(net.IP(nil), addr.IP...)
	}
	return &cp
}
