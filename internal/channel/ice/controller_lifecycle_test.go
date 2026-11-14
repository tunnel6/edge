package ice

import (
	"sync"
	"testing"
	"time"
)

// Exercise cancellation without opening a socket. The running fixture has no
// listener; only tests of captured addresses enter gatherEndpoints directly.
func lifecycleFixture(t *testing.T) (*Controller, *Session, *negotiationBridge) {
	t.Helper()
	b := &negotiationBridge{
		policy:   &LinkPolicy{P2PMode: "preferred", AllowRelayFallback: true},
		messages: make(map[int]int), notify: make(chan struct{}, 32),
	}
	cfg := DefaultConfig()
	cfg.GatherTimeout = 0
	c := NewController(cfg, b)
	c.running = true
	s, err := NewSession("lifecycle", "pub", "con")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(StateGathering); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return c, s, b
}

func TestGatheringAfterControllerStopDoesNotSendOrFallback(t *testing.T) {
	for _, entry := range []string{"listener-lookup", "captured-addresses"} {
		t.Run(entry, func(t *testing.T) {
			c, s, b := lifecycleFixture(t)
			stopCh := c.stopCh
			c.Stop()
			if entry == "listener-lookup" {
				c.startGathering(s)
			} else {
				c.gatherEndpoints(s, "127.0.0.1:50000", "127.0.0.1:50001", stopCh)
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.messages) != 0 || len(b.states) != 0 || s.GetState() != StateGathering {
				t.Fatal("stopped gathering sent messages or reported a path failure")
			}
		})
	}
}

func TestGatheringBridgeCanReenterAndStopController(t *testing.T) {
	c, s, b := lifecycleFixture(t)
	b.onSend = func(kind int) {
		if kind == int(msgTypeICEStart) {
			_ = c.Snapshot()
			c.Stop()
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.gatherEndpoints(s, "127.0.0.1:50000", "127.0.0.1:50001", c.stopCh)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Bridge reentry deadlocked gathering")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.messages[int(msgTypeICEStart)] != 1 || len(b.states) != 0 || s.GetState() != StateGathering {
		t.Fatal("gathering continued sends or fell back after Bridge stopped controller")
	}
}

func TestControllerStartFailureDoesNotPublishRunningListener(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:invalid-port"
	c := NewController(cfg, nil)
	t.Cleanup(c.Stop)
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.Start(); err == nil {
			t.Fatal("invalid listener address was accepted after a failed Start")
		}
		c.mu.RLock()
		running, listener := c.running, c.udpListener
		c.mu.RUnlock()
		if running || listener != nil {
			t.Fatal("failed Start published a running controller or listener")
		}
	}
}

// Requires real loopback UDP. Run with the complete ICE integration suite; the
// socket-free cancellation tests above do not replace this race regression.
func TestControllerStopConcurrentGathering(t *testing.T) {
	for attempt := 0; attempt < 16; attempt++ {
		c, s, b := lifecycleFixture(t)
		// Replace the fixture's synthetic running state with a real Start.
		c.running = false
		c.config.UDPAddr, c.config.UDPAddrAlt = "127.0.0.1:0", "127.0.0.1:0"
		c.config.GatherTimeout = time.Hour
		b.onSend = func(int) { _ = c.Snapshot() }
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-ready
			c.startGathering(s)
		}()
		go func() {
			defer workers.Done()
			<-ready
			c.Stop()
		}()
		close(ready)
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("concurrent Stop and gathering did not finish")
		}
		c.mu.RLock()
		stopped := !c.running && c.udpListener == nil
		c.mu.RUnlock()
		if !stopped {
			t.Fatal("Stop retained the active listener")
		}
	}
}
