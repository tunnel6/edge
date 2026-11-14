package p2p

import (
	"fmt"
	"sync"
	"testing"
)

func TestCoordinatorRetireNetworkExcludesConcurrentAndQueuedProjection(t *testing.T) {
	c := NewCoordinator(nil)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			for j := 0; j < 10; j++ {
				s := &Session{ID: fmt.Sprintf("retired-%d", i), NetworkID: "retired", Status: SessionStatusGathering}
				_ = c.OnSessionCreated(s)
				s.Status = SessionStatusConnected
				_ = c.OnSessionStateChange(s)
			}
		}(i)
	}
	close(start)
	c.RetireNetwork("retired")
	workers.Wait()
	// Queued callbacks and a repeated explicit creation cannot republish it.
	_ = c.OnSessionCreated(&Session{ID: "late", NetworkID: "retired"})
	_ = c.OnSessionStateChange(&Session{ID: "late", NetworkID: "retired", Status: SessionStatusConnected})
	if len(c.SnapshotSessions()) != 0 || len(c.SnapshotSessionStatuses()) != 0 {
		t.Fatal("retired network returned to legacy projections")
	}
	_ = c.OnSessionCreated(&Session{ID: "healthy", NetworkID: "other", Status: SessionStatusGathering})
	if state, ok := c.GetSessionStatus("healthy"); !ok || state != SessionStatusGathering {
		t.Fatal("unaffected network stopped tracking")
	}
}
