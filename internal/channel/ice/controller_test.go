package ice

import (
	"net"
	"testing"
	"time"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

type mockBridge struct {
	stateChanges []struct {
		sessionID string
		state     State
		detail    *StateDetail
	}
	policy *LinkPolicy
}

func (m *mockBridge) SendToClient(string, int, []byte) error { return nil }
func (m *mockBridge) GetTunnelLinkPolicy(string) *LinkPolicy { return m.policy }
func (m *mockBridge) ReportICEStateChange(id, _ string, _ string, _ string, state State, detail *StateDetail) {
	m.stateChanges = append(m.stateChanges, struct {
		sessionID string
		state     State
		detail    *StateDetail
	}{id, state, detail})
}

type reentrantSnapshotBridge struct {
	controller *Controller
	policy     *LinkPolicy
}

func (b *reentrantSnapshotBridge) SendToClient(string, int, []byte) error { return nil }
func (b *reentrantSnapshotBridge) GetTunnelLinkPolicy(string) *LinkPolicy { return b.policy }
func (b *reentrantSnapshotBridge) ReportICEStateChange(string, string, string, string, State, *StateDetail) {
	if b.controller != nil {
		_ = b.controller.Snapshot()
	}
}

func newTestController(t *testing.T, policy *LinkPolicy) (*Controller, *mockBridge) {
	t.Helper()
	bridge := &mockBridge{policy: policy}
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	ctrl := NewController(cfg, bridge)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	t.Cleanup(ctrl.Stop)
	return ctrl, bridge
}

func TestControllerSessionCreation(t *testing.T) {
	ctrl, bridge := newTestController(t, &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	})

	ctrl.OnPeerSessionEstablished("tunnel-1", "pub-sess", "con-sess")

	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	if len(ctrl.sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(ctrl.sessions))
	}
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()

	if session.GetState() != StateGathering {
		t.Fatalf("expected gathering, got %s", session.GetState())
	}
	if len(bridge.stateChanges) < 1 {
		t.Fatalf("expected at least 1 state change report")
	}
	if bridge.stateChanges[0].state != StateGathering {
		t.Fatalf("expected gathering state report, got %s", bridge.stateChanges[0].state)
	}
}

func TestControllerOnPeerSessionEstablished_NoControllerLockReentrancyDeadlock(t *testing.T) {
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	bridge := &reentrantSnapshotBridge{
		policy: &LinkPolicy{
			P2PMode:            "preferred",
			AllowRelayFallback: true,
		},
	}
	ctrl := NewController(cfg, bridge)
	bridge.controller = ctrl
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	t.Cleanup(ctrl.Stop)

	done := make(chan struct{})
	go func() {
		ctrl.OnPeerSessionEstablished("tunnel-lock", "pub-lock", "con-lock")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnPeerSessionEstablished blocked (possible controller lock reentrancy deadlock)")
	}
}

func TestControllerPunchFlowToFallback(t *testing.T) {
	ctrl, bridge := newTestController(t, &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	})

	ctrl.OnPeerSessionEstablished("tunnel-2", "pub-2", "con-2")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()

	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "pub-2",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000},
		NATType:   p2p.NATSymmetric,
	})
	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "con-2",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 6000},
		NATType:   p2p.NATSymmetric,
	})

	time.Sleep(10 * time.Millisecond)

	if session.GetState() != StateFallback {
		t.Fatalf("expected fallback for sym+sym, got %s", session.GetState())
	}

	found := false
	for _, sc := range bridge.stateChanges {
		if sc.state == StateFallback {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected fallback state change report")
	}
}

func TestControllerDuplicateSession(t *testing.T) {
	ctrl, _ := newTestController(t, &LinkPolicy{P2PMode: "preferred"})

	ctrl.OnPeerSessionEstablished("tunnel-3", "pub-3", "con-3")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	count := len(ctrl.sessions)
	ctrl.mu.RUnlock()

	ctrl.OnPeerSessionEstablished("tunnel-3", "pub-3", "con-3")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	countAfter := len(ctrl.sessions)
	ctrl.mu.RUnlock()

	if countAfter != count {
		t.Fatalf("expected no duplicate session, got %d -> %d", count, countAfter)
	}
}

func TestControllerAllowDistinctConsumersUnderSameTunnel(t *testing.T) {
	ctrl, _ := newTestController(t, &LinkPolicy{P2PMode: "preferred"})

	ctrl.OnPeerSessionEstablished("tunnel-3b", "pub-3b", "con-3b-1")
	ctrl.OnPeerSessionEstablished("tunnel-3b", "pub-3b", "con-3b-2")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	count := len(ctrl.sessions)
	ctrl.mu.RUnlock()
	if count != 2 {
		t.Fatalf("expected 2 sessions for distinct consumers, got %d", count)
	}

	ctrl.OnPeerSessionEstablished("tunnel-3b", "pub-3b", "con-3b-1")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	countAfter := len(ctrl.sessions)
	ctrl.mu.RUnlock()
	if countAfter != 2 {
		t.Fatalf("expected duplicate pair to be ignored, got %d sessions", countAfter)
	}
}

func TestControllerCleanupOnTerminalState(t *testing.T) {
	ctrl, _ := newTestController(t, &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	})

	ctrl.OnPeerSessionEstablished("tunnel-cleanup", "pub-c", "con-c")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	tokenCount := len(ctrl.tokenIndex)
	ctrl.mu.RUnlock()

	if tokenCount != 2 {
		t.Fatalf("expected 2 tokens, got %d", tokenCount)
	}

	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "pub-c",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000},
		NATType:   p2p.NATSymmetric,
	})
	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "con-c",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 6000},
		NATType:   p2p.NATSymmetric,
	})
	time.Sleep(10 * time.Millisecond)

	if session.GetState() != StateFallback {
		t.Fatalf("expected fallback, got %s", session.GetState())
	}

	ctrl.mu.RLock()
	tokenCountAfter := len(ctrl.tokenIndex)
	ctrl.mu.RUnlock()

	if tokenCountAfter != 0 {
		t.Fatalf("expected tokens cleaned up, got %d", tokenCountAfter)
	}
}

func TestControllerSnapshot(t *testing.T) {
	ctrl, _ := newTestController(t, &LinkPolicy{P2PMode: "preferred"})

	ctrl.OnPeerSessionEstablished("tunnel-snap", "pub-s", "con-s")
	time.Sleep(10 * time.Millisecond)

	snap := ctrl.Snapshot()
	if snap.TotalCount != 1 {
		t.Fatalf("expected 1 total session, got %d", snap.TotalCount)
	}
	if snap.ActiveCount != 1 {
		t.Fatalf("expected 1 active session, got %d", snap.ActiveCount)
	}
	if len(snap.Sessions) != 1 {
		t.Fatalf("expected 1 session snapshot, got %d", len(snap.Sessions))
	}
	if snap.Sessions[0].State != StateGathering {
		t.Fatalf("expected gathering, got %s", snap.Sessions[0].State)
	}
	if snap.UDPAddr == "" || snap.UDPAddrAlt == "" {
		t.Fatal("expected UDP addresses in snapshot")
	}
}

func TestControllerGatherTimeout(t *testing.T) {
	bridge := &mockBridge{policy: &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	}}
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	cfg.GatherTimeout = 100 * time.Millisecond
	ctrl := NewController(cfg, bridge)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	t.Cleanup(ctrl.Stop)

	ctrl.OnPeerSessionEstablished("tunnel-timeout", "pub-t", "con-t")
	time.Sleep(200 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()

	if session.GetState() != StateFallback {
		t.Fatalf("expected fallback after timeout, got %s", session.GetState())
	}
}

func TestControllerFullHappyPath(t *testing.T) {
	bridge := &mockBridge{policy: &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	}}
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	cfg.PunchTimeout = 2 * time.Second
	cfg.ConnectTimeout = 2 * time.Second
	ctrl := NewController(cfg, bridge)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	t.Cleanup(ctrl.Stop)

	ctrl.OnPeerSessionEstablished("tunnel-happy", "pub-h", "con-h")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()

	if session.GetState() != StateGathering {
		t.Fatalf("expected gathering, got %s", session.GetState())
	}

	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "pub-h",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000},
		NATType:   p2p.NATFullCone,
	})
	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "con-h",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 6000},
		NATType:   p2p.NATFullCone,
	})
	time.Sleep(10 * time.Millisecond)

	if session.GetState() != StatePunching {
		t.Fatalf("expected punching after cone+cone, got %s", session.GetState())
	}

	ctrl.OnPunchResultReceived("pub-h", session.ID, &PunchResult{
		Success:          true,
		PeerObservedAddr: "5.6.7.8:6000",
		AttemptsSent:     3,
	})
	ctrl.OnPunchResultReceived("con-h", session.ID, &PunchResult{
		Success:          true,
		PeerObservedAddr: "1.2.3.4:5000",
		AttemptsSent:     2,
	})
	time.Sleep(10 * time.Millisecond)

	if session.GetState() != StateConnecting {
		t.Fatalf("expected connecting, got %s", session.GetState())
	}

	ctrl.OnQuicConnected(session.ID, &QuicConnInfo{
		ConnectionID: "conn-123",
		LocalAddr:    "1.2.3.4:5000",
		PeerAddr:     "5.6.7.8:6000",
		RTTMs:        15,
	})

	if session.GetState() != StateConnected {
		t.Fatalf("expected connected, got %s", session.GetState())
	}

	states := make([]State, 0, len(bridge.stateChanges))
	for _, sc := range bridge.stateChanges {
		states = append(states, sc.state)
	}
	expected := []State{StateGathering, StatePunching, StateConnecting, StateConnected}
	if len(states) != len(expected) {
		t.Fatalf("expected %d state changes, got %d: %v", len(expected), len(states), states)
	}
	for i, s := range expected {
		if states[i] != s {
			t.Fatalf("state[%d]: expected %s, got %s", i, s, states[i])
		}
	}
}

func TestControllerClientDisconnect(t *testing.T) {
	ctrl, _ := newTestController(t, &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	})

	ctrl.OnPeerSessionEstablished("tunnel-dc", "pub-dc", "con-dc")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()

	if session.GetState() != StateGathering {
		t.Fatalf("expected gathering, got %s", session.GetState())
	}

	ctrl.OnClientSessionDisconnected("pub-dc")
	time.Sleep(10 * time.Millisecond)

	if session.GetState() != StateClosed {
		t.Fatalf("expected closed after disconnect, got %s", session.GetState())
	}

	ctrl.mu.RLock()
	tokenCount := len(ctrl.tokenIndex)
	ctrl.mu.RUnlock()
	if tokenCount != 0 {
		t.Fatalf("expected tokens cleaned up, got %d", tokenCount)
	}
}

func TestComputePortPredictPlanPreferred(t *testing.T) {
	cfg := DefaultConfig()
	plan := computePortPredictPlan(cfg, &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
		RequireDirect:      false,
	})

	if plan.extraCount != portPredictPreferredExtraCount {
		t.Fatalf("expected preferred extra count %d, got %d", portPredictPreferredExtraCount, plan.extraCount)
	}
	if plan.attempts != portPredictPreferredMaxAttempts {
		t.Fatalf("expected preferred attempts %d, got %d", portPredictPreferredMaxAttempts, plan.attempts)
	}
	if plan.timeout != portPredictPreferredTimeoutCap {
		t.Fatalf("expected preferred timeout cap %s, got %s", portPredictPreferredTimeoutCap, plan.timeout)
	}
	if plan.burstPerAttempt != 1 {
		t.Fatalf("expected preferred burst_per_attempt=1, got %d", plan.burstPerAttempt)
	}
}

func TestComputePortPredictPlanRequireDirect(t *testing.T) {
	cfg := DefaultConfig()
	plan := computePortPredictPlan(cfg, &LinkPolicy{
		P2PMode:            "required",
		AllowRelayFallback: false,
		RequireDirect:      true,
	})

	if plan.extraCount != portPredictRequireExtraCount {
		t.Fatalf("expected require_direct extra count %d, got %d", portPredictRequireExtraCount, plan.extraCount)
	}
	if plan.attempts != portPredictRequireMaxAttempts {
		t.Fatalf("expected require_direct attempts %d, got %d", portPredictRequireMaxAttempts, plan.attempts)
	}
	if plan.timeout != portPredictRequireTimeoutCap {
		t.Fatalf("expected require_direct timeout cap %s, got %s", portPredictRequireTimeoutCap, plan.timeout)
	}
	if plan.burstPerAttempt != portPredictRequireBurst {
		t.Fatalf("expected require_direct burst_per_attempt=%d, got %d", portPredictRequireBurst, plan.burstPerAttempt)
	}
}

func TestControllerStatsTracksAttemptsSent(t *testing.T) {
	bridge := &mockBridge{policy: &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	}}
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	cfg.ConnectTimeout = 500 * time.Millisecond
	ctrl := NewController(cfg, bridge)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	t.Cleanup(ctrl.Stop)

	ctrl.OnPeerSessionEstablished("tunnel-stats", "pub-stats", "con-stats")
	time.Sleep(10 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()
	if session == nil {
		t.Fatal("expected session")
	}

	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "pub-stats",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000},
		NATType:   p2p.NATFullCone,
	})
	ctrl.handleProbe(session, &PeerEndpoint{
		SessionID: "con-stats",
		UDPAddr:   &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 6000},
		NATType:   p2p.NATFullCone,
	})
	time.Sleep(10 * time.Millisecond)

	ctrl.OnPunchResultReceived("pub-stats", session.ID, &PunchResult{
		Success:          true,
		PeerObservedAddr: "5.6.7.8:6000",
		AttemptsSent:     21,
	})

	stats := ctrl.Stats()
	if stats.AttemptsSamples != 1 {
		t.Fatalf("expected attempts samples=1, got %d", stats.AttemptsSamples)
	}
	if stats.AvgAttemptsSent != 21 {
		t.Fatalf("expected avg attempts sent=21, got %f", stats.AvgAttemptsSent)
	}
}
