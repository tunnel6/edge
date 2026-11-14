package p2p

import "testing"

func TestStatusTrackerUpsertAndDelete(t *testing.T) {
	tracker := NewStatusTracker()
	old, changed := tracker.Upsert("s1", SessionStatusGathering)
	if old != SessionStatusNew {
		t.Fatalf("expected old state NEW, got %v", old)
	}
	if !changed {
		t.Fatalf("expected changed=true on first insert")
	}

	old, changed = tracker.Upsert("s1", SessionStatusGathering)
	if old != SessionStatusGathering {
		t.Fatalf("expected old state GATHERING, got %v", old)
	}
	if changed {
		t.Fatalf("expected changed=false when state unchanged")
	}

	old, changed = tracker.Upsert("s1", SessionStatusConnected)
	if old != SessionStatusGathering {
		t.Fatalf("expected old state GATHERING, got %v", old)
	}
	if !changed {
		t.Fatalf("expected changed=true when state changes")
	}

	tracker.Delete("s1")
	old, changed = tracker.Upsert("s1", SessionStatusPunching)
	if old != SessionStatusNew || !changed {
		t.Fatalf("expected fresh NEW after delete, got old=%v changed=%v", old, changed)
	}
}

func TestStatusTrackerGetAndSnapshot(t *testing.T) {
	tracker := NewStatusTracker()
	if _, ok := tracker.Get("missing"); ok {
		t.Fatalf("expected missing session status to be absent")
	}

	_, _ = tracker.Upsert("s1", SessionStatusGathering)
	_, _ = tracker.Upsert("s2", SessionStatusConnected)

	s1, ok := tracker.Get("s1")
	if !ok || s1 != SessionStatusGathering {
		t.Fatalf("unexpected s1 status: state=%v ok=%v", s1, ok)
	}

	snapshot := tracker.Snapshot()
	if len(snapshot) != 2 {
		t.Fatalf("unexpected snapshot size: got=%d want=2", len(snapshot))
	}
	if snapshot["s2"] != SessionStatusConnected {
		t.Fatalf("unexpected snapshot s2 status: %v", snapshot["s2"])
	}

	// Mutating snapshot must not affect tracker state.
	snapshot["s1"] = SessionStatusFailed
	s1After, ok := tracker.Get("s1")
	if !ok || s1After != SessionStatusGathering {
		t.Fatalf("tracker state should be immutable from snapshot mutation: state=%v ok=%v", s1After, ok)
	}
}
