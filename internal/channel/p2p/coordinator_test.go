package p2p

import (
	"testing"
)

type testAdapter struct {
	created     []*Session
	transitions []struct {
		sessionID string
		oldState  SessionStatus
		newState  SessionStatus
	}
	clientInfoCalls int
	sessions        map[string]bool
}

func newTestAdapter() *testAdapter {
	return &testAdapter{
		sessions: make(map[string]bool),
	}
}

func (a *testAdapter) OnSessionCreated(session *Session) error {
	a.created = append(a.created, session)
	if session != nil {
		a.sessions[session.ID] = true
	}
	return nil
}

func (a *testAdapter) OnStateTransition(sessionID string, oldState, newState SessionStatus) error {
	a.transitions = append(a.transitions, struct {
		sessionID string
		oldState  SessionStatus
		newState  SessionStatus
	}{
		sessionID: sessionID,
		oldState:  oldState,
		newState:  newState,
	})
	return nil
}

func (a *testAdapter) UpdateClientInfo(sessionID, clientID string, info *ClientInfo) error {
	a.clientInfoCalls++
	return nil
}

func (a *testAdapter) HasSession(sessionID string) bool {
	return a.sessions[sessionID]
}

func TestCoordinatorTracksTransitions(t *testing.T) {
	adapter := newTestAdapter()
	coordinator := NewCoordinator(adapter)

	s := &Session{ID: "s1", Status: SessionStatusNew}
	if err := coordinator.OnSessionCreated(s); err != nil {
		t.Fatalf("OnSessionCreated failed: %v", err)
	}

	if len(adapter.created) != 1 {
		t.Fatalf("expected 1 created callback, got %d", len(adapter.created))
	}

	s.Status = SessionStatusGathering
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange NEW->GATHERING failed: %v", err)
	}
	s.Status = SessionStatusPunching
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange GATHERING->PUNCHING failed: %v", err)
	}

	if len(adapter.transitions) != 2 {
		t.Fatalf("expected 2 transition callbacks, got %d", len(adapter.transitions))
	}
	if adapter.transitions[0].oldState != SessionStatusNew || adapter.transitions[0].newState != SessionStatusGathering {
		t.Fatalf("unexpected first transition: %+v", adapter.transitions[0])
	}
	if adapter.transitions[1].oldState != SessionStatusGathering || adapter.transitions[1].newState != SessionStatusPunching {
		t.Fatalf("unexpected second transition: %+v", adapter.transitions[1])
	}
}

func TestCoordinatorDeleteOnTerminalState(t *testing.T) {
	adapter := newTestAdapter()
	coordinator := NewCoordinator(adapter)

	s := &Session{ID: "s2", Status: SessionStatusNew}
	_ = coordinator.OnSessionCreated(s)

	s.Status = SessionStatusFailed
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange to failed failed: %v", err)
	}

	s.Status = SessionStatusGathering
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange after failed failed: %v", err)
	}

	if len(adapter.transitions) < 2 {
		t.Fatalf("expected at least 2 transition callbacks, got %d", len(adapter.transitions))
	}

	last := adapter.transitions[len(adapter.transitions)-1]
	if last.oldState != SessionStatusNew {
		t.Fatalf("expected old state reset to NEW after terminal cleanup, got %v", last.oldState)
	}
}

func TestCoordinatorUpdateClientInfoDelegates(t *testing.T) {
	adapter := newTestAdapter()
	coordinator := NewCoordinator(adapter)

	if err := coordinator.UpdateClientInfo("s", "c", &ClientInfo{ClientID: "c"}); err != nil {
		t.Fatalf("UpdateClientInfo failed: %v", err)
	}
	if adapter.clientInfoCalls != 1 {
		t.Fatalf("expected 1 client info call, got %d", adapter.clientInfoCalls)
	}
}

func TestCoordinatorTransitionObserverAndSnapshot(t *testing.T) {
	adapter := newTestAdapter()
	coordinator := NewCoordinator(adapter)

	var events []TransitionEvent
	coordinator.SetTransitionObserver(func(event TransitionEvent) {
		events = append(events, event)
	})

	s := &Session{
		ID:                 "obs-1",
		Status:             SessionStatusNew,
		PreferredLinks:     []string{"p2p", "relay"},
		AllowRelayFallback: true,
	}
	if err := coordinator.OnSessionCreated(s); err != nil {
		t.Fatalf("OnSessionCreated failed: %v", err)
	}

	s.Status = SessionStatusGathering
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange NEW->GATHERING failed: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 transition event, got %d", len(events))
	}
	if events[0].SessionID != "obs-1" || events[0].OldState != SessionStatusNew || events[0].NewState != SessionStatusGathering {
		t.Fatalf("unexpected transition event: %+v", events[0])
	}
	if events[0].Session == nil || events[0].Session.ID != "obs-1" {
		t.Fatalf("expected transition event snapshot session")
	}

	state, ok := coordinator.GetSessionStatus("obs-1")
	if !ok || state != SessionStatusGathering {
		t.Fatalf("unexpected tracked status: state=%v ok=%v", state, ok)
	}

	snapshot := coordinator.SnapshotSessionStatuses()
	if len(snapshot) != 1 || snapshot["obs-1"] != SessionStatusGathering {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}

	sessionSnapshot, ok := coordinator.GetSessionSnapshot("obs-1")
	if !ok || sessionSnapshot == nil {
		t.Fatalf("expected session snapshot for obs-1")
	}
	if sessionSnapshot.Status != SessionStatusGathering {
		t.Fatalf("unexpected session snapshot status: %v", sessionSnapshot.Status)
	}
	if len(sessionSnapshot.PreferredLinks) != 2 || sessionSnapshot.PreferredLinks[0] != "p2p" || !sessionSnapshot.AllowRelayFallback {
		t.Fatalf("unexpected session snapshot policy: %+v", sessionSnapshot)
	}

	allSessionSnapshots := coordinator.SnapshotSessions()
	if len(allSessionSnapshots) != 1 || allSessionSnapshots["obs-1"] == nil {
		t.Fatalf("unexpected session snapshots map: %+v", allSessionSnapshots)
	}
	allSessionSnapshots["obs-1"].PreferredLinks[0] = "tampered"
	freshSnapshot, ok := coordinator.GetSessionSnapshot("obs-1")
	if !ok || freshSnapshot == nil {
		t.Fatalf("expected fresh session snapshot for immutability check")
	}
	if len(freshSnapshot.PreferredLinks) != 2 || freshSnapshot.PreferredLinks[0] != "p2p" {
		t.Fatalf("session snapshot should be immutable from caller mutation: %+v", freshSnapshot.PreferredLinks)
	}
}

func TestCoordinatorTerminalStateCleanupVisibleInGet(t *testing.T) {
	adapter := newTestAdapter()
	coordinator := NewCoordinator(adapter)
	s := &Session{ID: "cleanup-1", Status: SessionStatusNew}

	_ = coordinator.OnSessionCreated(s)
	s.Status = SessionStatusFailed
	if err := coordinator.OnSessionStateChange(s); err != nil {
		t.Fatalf("OnSessionStateChange NEW->FAILED failed: %v", err)
	}

	if _, ok := coordinator.GetSessionStatus("cleanup-1"); ok {
		t.Fatalf("expected failed session removed from tracker")
	}
	if _, ok := coordinator.GetSessionSnapshot("cleanup-1"); ok {
		t.Fatalf("expected failed session snapshot removed")
	}
}

func TestCoordinatorStateChangePreservesPolicyWhenUpdateOmitsPolicy(t *testing.T) {
	coordinator := NewCoordinator(newTestAdapter())

	if err := coordinator.OnSessionCreated(&Session{
		ID:                 "policy-1",
		Status:             SessionStatusNew,
		PreferredLinks:     []string{"p2p", "relay"},
		AllowRelayFallback: true,
	}); err != nil {
		t.Fatalf("OnSessionCreated failed: %v", err)
	}

	// Transition payload intentionally omits policy fields.
	if err := coordinator.OnSessionStateChange(&Session{
		ID:       "policy-1",
		Status:   SessionStatusGathering,
		PathType: PathUnknown,
	}); err != nil {
		t.Fatalf("OnSessionStateChange failed: %v", err)
	}

	snapshot, ok := coordinator.GetSessionSnapshot("policy-1")
	if !ok || snapshot == nil {
		t.Fatalf("expected session snapshot after transition")
	}
	if len(snapshot.PreferredLinks) != 2 || snapshot.PreferredLinks[0] != "p2p" || !snapshot.AllowRelayFallback {
		t.Fatalf("expected policy to be preserved from tracked session, got=%+v", snapshot)
	}
}
