package wireguard

import (
	"testing"
	"time"
)

func TestMeshCoordinatorStopIsIdempotent(t *testing.T) {
	c := NewMeshCoordinator()

	if err := c.Stop(); err != nil {
		t.Fatalf("stop before start failed: %v", err)
	}

	if err := c.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("second stop should be no-op, got error: %v", err)
	}
}

func TestMeshCoordinatorCanRestartAfterStop(t *testing.T) {
	c := NewMeshCoordinator()

	for i := 0; i < 3; i++ {
		if err := c.Start(); err != nil {
			t.Fatalf("start #%d failed: %v", i+1, err)
		}

		time.Sleep(5 * time.Millisecond)

		if err := c.Stop(); err != nil {
			t.Fatalf("stop #%d failed: %v", i+1, err)
		}
	}
}

func TestMeshCoordinatorStopAllowsMaintenanceToAcquireStateLock(t *testing.T) {
	c := NewMeshCoordinator()
	c.running = true
	c.stopCh = make(chan struct{})
	stopCh := c.stopCh
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-stopCh
		c.isRelayForwardingEnabled()
	}()
	done := make(chan error, 1)
	go func() { done <- c.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop blocked maintenance state access")
	}
}
