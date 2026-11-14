//go:build linux

package relay

import "testing"

func TestAllocateInterfaceListenPortSkipsLivePorts(t *testing.T) {
	m := &linuxRelayManager{
		cfg: &Config{ListenPortBase: 58021},
		interfaces: map[string]*networkInterface{
			"network-a": {ListenPort: 58021},
			"network-b": {ListenPort: 58023},
		},
	}

	if got := m.allocateInterfaceListenPortLocked(); got != 58022 {
		t.Fatalf("first free interface port = %d, want 58022", got)
	}

	m.interfaces["network-c"] = &networkInterface{ListenPort: 58022}
	if got := m.allocateInterfaceListenPortLocked(); got != 58024 {
		t.Fatalf("port after filling gap = %d, want 58024", got)
	}
}

func TestAllocateInterfaceListenPortUsesDefaultBase(t *testing.T) {
	m := &linuxRelayManager{
		cfg:        &Config{},
		interfaces: map[string]*networkInterface{},
	}
	if got := m.allocateInterfaceListenPortLocked(); got != 58021 {
		t.Fatalf("default interface port = %d, want 58021", got)
	}
}

func TestObservationSourcePinsCurrentInterfaceWithoutWGIO(t *testing.T) {
	m := &linuxRelayManager{interfaces: map[string]*networkInterface{"net": {Generation: "generation-1"}}}
	if err := m.observations.publish("net", "generation-1"); err != nil {
		t.Fatal(err)
	}
	sample := Observation{NetworkID: "net", InterfaceGeneration: "generation-1"}
	calls := 0
	if err := m.WithCurrentObservation(sample, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := m.observations.publish("net", "generation-2"); err != nil {
		t.Fatal(err)
	}
	if err := m.WithCurrentObservation(sample, func() error { calls++; return nil }); err == nil {
		t.Fatal("old generation accepted")
	}
	sample.InterfaceGeneration = "generation-2"
	if err := m.WithCurrentObservation(sample, nil); err == nil {
		t.Fatal("nil consumer accepted")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- m.WithCurrentObservation(sample, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	if m.observations.mu.TryLock() {
		m.observations.mu.Unlock()
		t.Fatal("interface lifetime not pinned")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Holding the kernel-operation mutex does not block source validation or
	// retirement. No netlink/wgctrl/forwarder is invoked in this test.
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.WithCurrentObservation(sample, func() error { return nil }); err != nil {
		t.Fatal("kernel-operation mutex blocked current observation", err)
	}
	if err := m.observations.retire("net"); err != nil {
		t.Fatal(err)
	}
	if err := m.WithCurrentObservation(sample, func() error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("removed interface reached consumer")
	}
}
