package p2p

import "testing"

func TestRuntimeRegisterAndGet(t *testing.T) {
	runtime := NewRuntime()
	adapterA := newTestAdapter()
	adapterB := newTestAdapter()

	coordA := runtime.Register("wireguard", adapterA)
	if coordA == nil {
		t.Fatalf("expected coordinator for wireguard")
	}

	fetched, ok := runtime.Get("wireguard")
	if !ok || fetched == nil {
		t.Fatalf("expected to get wireguard coordinator")
	}
	if fetched != coordA {
		t.Fatalf("expected fetched coordinator to match registered instance")
	}

	coordB := runtime.Register("wireguard", adapterB)
	if coordB != coordA {
		t.Fatalf("expected register on same namespace to reuse coordinator")
	}
	if !coordB.HasAdapter() {
		t.Fatalf("expected coordinator to keep adapter after re-register")
	}
}

func TestRuntimeEnsureNamespace(t *testing.T) {
	runtime := NewRuntime()

	coord := runtime.Ensure(NamespaceQUIC)
	if coord == nil {
		t.Fatalf("expected ensure to create coordinator")
	}
	if coord.HasAdapter() {
		t.Fatalf("expected ensured coordinator to have no adapter by default")
	}

	fetched, ok := runtime.Get(NamespaceQUIC)
	if !ok || fetched == nil {
		t.Fatalf("expected to get ensured coordinator")
	}
	if fetched != coord {
		t.Fatalf("expected ensured and fetched coordinators to match")
	}
}

func TestRuntimeReset(t *testing.T) {
	runtime := NewRuntime()
	_ = runtime.Register(NamespaceWireGuard, newTestAdapter())
	_ = runtime.Ensure(NamespaceQUIC)

	runtime.Reset()

	if _, ok := runtime.Get(NamespaceWireGuard); ok {
		t.Fatalf("expected wireguard namespace removed after reset")
	}
	if _, ok := runtime.Get(NamespaceQUIC); ok {
		t.Fatalf("expected quic namespace removed after reset")
	}
}

func TestRuntimeStopCallsReset(t *testing.T) {
	runtime := NewRuntime()
	_ = runtime.Register(NamespaceWireGuard, newTestAdapter())
	if err := runtime.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if _, ok := runtime.Get(NamespaceWireGuard); ok {
		t.Fatalf("expected namespaces removed after stop")
	}
}

func TestRuntimeEnsureThenRegisterReusesCoordinator(t *testing.T) {
	runtime := NewRuntime()
	ensured := runtime.Ensure(NamespaceWireGuard)
	if ensured == nil {
		t.Fatalf("expected ensure to create wireguard coordinator")
	}
	if ensured.HasAdapter() {
		t.Fatalf("expected ensured coordinator to have no adapter")
	}

	adapter := newTestAdapter()
	registered := runtime.Register(NamespaceWireGuard, adapter)
	if registered == nil {
		t.Fatalf("expected register to return coordinator")
	}
	if registered != ensured {
		t.Fatalf("expected register to reuse ensured coordinator")
	}
	if !registered.HasAdapter() {
		t.Fatalf("expected coordinator to have adapter after register")
	}
}

func TestRuntimeNamespaceStateIsolation(t *testing.T) {
	runtime := NewRuntime()
	wgAdapter := newTestAdapter()
	quicAdapter := newTestAdapter()

	wgCoord := runtime.Register(NamespaceWireGuard, wgAdapter)
	quicCoord := runtime.Register(NamespaceQUIC, quicAdapter)
	if wgCoord == nil || quicCoord == nil {
		t.Fatalf("expected both namespace coordinators")
	}

	wgSession := &Session{ID: "shared", Status: SessionStatusNew}
	quicSession := &Session{ID: "shared", Status: SessionStatusNew}

	if err := wgCoord.OnSessionCreated(wgSession); err != nil {
		t.Fatalf("wg OnSessionCreated failed: %v", err)
	}
	if err := quicCoord.OnSessionCreated(quicSession); err != nil {
		t.Fatalf("quic OnSessionCreated failed: %v", err)
	}

	wgSession.Status = SessionStatusGathering
	if err := wgCoord.OnSessionStateChange(wgSession); err != nil {
		t.Fatalf("wg OnSessionStateChange failed: %v", err)
	}
	quicSession.Status = SessionStatusPunching
	if err := quicCoord.OnSessionStateChange(quicSession); err != nil {
		t.Fatalf("quic OnSessionStateChange failed: %v", err)
	}

	if len(wgAdapter.transitions) != 1 {
		t.Fatalf("expected 1 wg transition, got %d", len(wgAdapter.transitions))
	}
	if len(quicAdapter.transitions) != 1 {
		t.Fatalf("expected 1 quic transition, got %d", len(quicAdapter.transitions))
	}

	if wgAdapter.transitions[0].newState != SessionStatusGathering {
		t.Fatalf("unexpected wg transition state: %+v", wgAdapter.transitions[0])
	}
	if quicAdapter.transitions[0].newState != SessionStatusPunching {
		t.Fatalf("unexpected quic transition state: %+v", quicAdapter.transitions[0])
	}
}

func TestRuntimeListNamespacesAndSessionStatus(t *testing.T) {
	runtime := NewRuntime()
	wgCoord := runtime.Register(NamespaceWireGuard, newTestAdapter())
	quicCoord := runtime.Register(NamespaceQUIC, newTestAdapter())

	_ = wgCoord.OnSessionCreated(&Session{ID: "wg-s1", Status: SessionStatusNew})
	_ = wgCoord.OnSessionStateChange(&Session{ID: "wg-s1", Status: SessionStatusConnected})
	_ = quicCoord.OnSessionCreated(&Session{ID: "quic-s1", Status: SessionStatusNew})
	_ = quicCoord.OnSessionStateChange(&Session{ID: "quic-s1", Status: SessionStatusGathering})

	namespaces := runtime.ListNamespaces()
	if len(namespaces) != 2 {
		t.Fatalf("unexpected namespace count: got=%d want=2", len(namespaces))
	}
	if namespaces[0] != NamespaceQUIC || namespaces[1] != NamespaceWireGuard {
		t.Fatalf("expected sorted namespaces [quic, wireguard], got=%v", namespaces)
	}

	state, ok := runtime.GetSessionStatus(NamespaceWireGuard, "wg-s1")
	if !ok || state != SessionStatusConnected {
		t.Fatalf("unexpected wireguard session status: state=%v ok=%v", state, ok)
	}

	state, ok = runtime.GetSessionStatus(NamespaceQUIC, "quic-s1")
	if !ok || state != SessionStatusGathering {
		t.Fatalf("unexpected quic session status: state=%v ok=%v", state, ok)
	}
}

func TestRuntimeSnapshotIsolation(t *testing.T) {
	runtime := NewRuntime()
	wgCoord := runtime.Register(NamespaceWireGuard, newTestAdapter())
	_ = wgCoord.OnSessionCreated(&Session{ID: "wg-s1", Status: SessionStatusNew})
	_ = wgCoord.OnSessionStateChange(&Session{ID: "wg-s1", Status: SessionStatusPunching})

	snapshot := runtime.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("unexpected runtime snapshot namespace count: %d", len(snapshot))
	}
	if snapshot[NamespaceWireGuard]["wg-s1"] != SessionStatusPunching {
		t.Fatalf("unexpected runtime snapshot state: %+v", snapshot)
	}

	// Snapshot mutations must not affect runtime tracked state.
	snapshot[NamespaceWireGuard]["wg-s1"] = SessionStatusFailed
	state, ok := runtime.GetSessionStatus(NamespaceWireGuard, "wg-s1")
	if !ok || state != SessionStatusPunching {
		t.Fatalf("runtime state should be immutable from snapshot mutation: state=%v ok=%v", state, ok)
	}
}

func TestRuntimeSnapshotSessions(t *testing.T) {
	runtime := NewRuntime()
	wgCoord := runtime.Register(NamespaceWireGuard, newTestAdapter())

	_ = wgCoord.OnSessionCreated(&Session{
		ID:                 "wg-s1",
		Status:             SessionStatusNew,
		PathType:           PathDirect,
		PreferredLinks:     []string{"p2p", "relay"},
		AllowRelayFallback: true,
	})
	_ = wgCoord.OnSessionStateChange(&Session{
		ID:       "wg-s1",
		Status:   SessionStatusConnected,
		PathType: PathDirect,
	})

	snapshot := runtime.SnapshotSessions()
	ns, ok := snapshot[NamespaceWireGuard]
	if !ok || len(ns) != 1 {
		t.Fatalf("unexpected session snapshot namespace payload: %+v", snapshot)
	}
	session, ok := ns["wg-s1"]
	if !ok || session == nil {
		t.Fatalf("expected wireguard session snapshot")
	}
	if session.Status != SessionStatusConnected || session.PathType != PathDirect {
		t.Fatalf("unexpected wireguard session snapshot data: %+v", session)
	}
	if len(session.PreferredLinks) != 2 || session.PreferredLinks[0] != "p2p" || !session.AllowRelayFallback {
		t.Fatalf("unexpected wireguard session policy snapshot data: %+v", session)
	}

	nsSnapshot := runtime.SnapshotNamespaceSessions(NamespaceWireGuard)
	if len(nsSnapshot) != 1 || nsSnapshot["wg-s1"] == nil {
		t.Fatalf("unexpected namespace session snapshot: %+v", nsSnapshot)
	}
	directSnapshot, ok := runtime.GetNamespaceSession(NamespaceWireGuard, "wg-s1")
	if !ok || directSnapshot == nil {
		t.Fatalf("expected direct namespace session snapshot")
	}
	if directSnapshot.Status != SessionStatusConnected || directSnapshot.PathType != PathDirect {
		t.Fatalf("unexpected direct namespace session snapshot: %+v", directSnapshot)
	}

	// Mutating the returned snapshot must not affect runtime state.
	session.Status = SessionStatusFailed
	session.PreferredLinks[0] = "tampered"
	directSnapshot.Status = SessionStatusFailed
	directSnapshot.PreferredLinks[0] = "tampered-direct"
	fresh := runtime.SnapshotNamespaceSessions(NamespaceWireGuard)["wg-s1"]
	if fresh == nil || fresh.Status != SessionStatusConnected {
		t.Fatalf("runtime snapshot should be immutable from caller mutation, got: %+v", fresh)
	}
	if len(fresh.PreferredLinks) != 2 || fresh.PreferredLinks[0] != "p2p" {
		t.Fatalf("runtime snapshot preferred links should be immutable from caller mutation, got: %+v", fresh.PreferredLinks)
	}
}
