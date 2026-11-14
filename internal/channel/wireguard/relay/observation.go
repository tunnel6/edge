package relay

import (
	"fmt"
	"sync"
	"time"
)

// Observation is a local raw WG read, not a peer-pair reachability report.
// StartedAt brackets the read so membership changes during it fail closed.
// InterfaceGeneration is ephemeral and changes on every interface creation.
type Observation struct {
	NetworkID, InterfaceGeneration, PublicKey, Endpoint string
	StartedAt, SampledAt, LastHandshakeTime             time.Time
	RxBytes                                             int64
}

// ObservationSource is optional: non-Linux/legacy implementations need not
// support it. WithCurrentObservation pins the interface lifetime during a short
// in-memory consume, invoked under the Owner gate. consume must not reenter the
// source or do I/O. Delivery callbacks themselves run without source locks.
type ObservationSource interface {
	SetOnObservation(func(Observation))
	WithCurrentObservation(Observation, func() error) error
}

// ObservationMutationSource optionally serializes interface lifetime facts
// with an authority. The gate must execute change exactly once, including after
// authority shutdown. change only updates memory; kernel setup/cleanup and
// delivery callbacks must run outside it. Detach waits for pending mutations
// and only removes its own binding. Bind before using observations in an Owner.
type ObservationMutationSource interface {
	BindObservationMutations(gate func(change func() error) error) (detach func(), err error)
}

type observationMutationBinding struct {
	gate func(func() error) error
}

// observationLifetimes has no dependency on the kernel-operation mutex. An
// Owner can validate/prune facts while netlink, wgctrl or a forwarder is blocked.
// Lock order: binding -> Owner -> mu. Reads take only mu, never binding.
type observationLifetimes struct {
	bindingMu sync.RWMutex
	binding   *observationMutationBinding
	mu        sync.RWMutex
	current   map[string]string
}

func (s *observationLifetimes) bind(gate func(func() error) error) (func(), error) {
	if gate == nil {
		return nil, fmt.Errorf("missing WG observation mutation gate")
	}
	s.bindingMu.Lock()
	defer s.bindingMu.Unlock()
	if s.binding != nil {
		return nil, fmt.Errorf("WG observation mutation gate already bound")
	}
	binding := &observationMutationBinding{gate: gate}
	s.binding = binding
	return func() {
		s.bindingMu.Lock()
		defer s.bindingMu.Unlock()
		if s.binding == binding {
			s.binding = nil
		}
	}, nil
}

func (s *observationLifetimes) change(change func()) error {
	s.bindingMu.RLock()
	defer s.bindingMu.RUnlock()
	mutate := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		change()
		return nil
	}
	if s.binding != nil {
		return s.binding.gate(mutate)
	}
	return mutate()
}

func (s *observationLifetimes) publish(network, generation string) error {
	if network == "" || generation == "" {
		return fmt.Errorf("missing WG observation interface identity")
	}
	return s.change(func() {
		if s.current == nil {
			s.current = make(map[string]string)
		}
		s.current[network] = generation
	})
}

func (s *observationLifetimes) retire(network string) error {
	return s.change(func() { delete(s.current, network) })
}

func (s *observationLifetimes) retireAll() error {
	return s.change(func() { s.current = nil })
}

func (s *observationLifetimes) withCurrent(sample Observation, consume func() error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sample.InterfaceGeneration == "" || s.current[sample.NetworkID] != sample.InterfaceGeneration || consume == nil {
		return fmt.Errorf("WG observation interface retired or unavailable")
	}
	return consume()
}

func observationFromEndpoint(networkID string, ep ObservedEndpoint) Observation {
	endpoint := ""
	if ep.Endpoint != nil {
		endpoint = ep.Endpoint.String()
	}
	return Observation{NetworkID: networkID, InterfaceGeneration: ep.InterfaceGeneration,
		PublicKey: ep.PublicKey, Endpoint: endpoint, StartedAt: ep.StartedAt,
		SampledAt: ep.SampledAt, LastHandshakeTime: ep.LastHandshakeTime, RxBytes: ep.RxBytes}
}
