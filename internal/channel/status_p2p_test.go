package channel

import (
	"testing"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

func TestStatusManagerIncludesP2PSnapshot(t *testing.T) {
	runtime := p2p.NewRuntime()
	wgCoord := runtime.Ensure(p2p.NamespaceWireGuard)
	quicCoord := runtime.Ensure(p2p.NamespaceQUIC)

	if err := wgCoord.OnSessionCreated(&p2p.Session{ID: "wg-1", Status: p2p.SessionStatusNew, PathType: p2p.PathDirect}); err != nil {
		t.Fatalf("wg OnSessionCreated failed: %v", err)
	}
	if err := wgCoord.OnSessionStateChange(&p2p.Session{ID: "wg-1", Status: p2p.SessionStatusConnected, PathType: p2p.PathDirect}); err != nil {
		t.Fatalf("wg OnSessionStateChange failed: %v", err)
	}
	if err := quicCoord.OnSessionCreated(&p2p.Session{ID: "quic-1", Status: p2p.SessionStatusNew, PathType: p2p.PathRelay}); err != nil {
		t.Fatalf("quic OnSessionCreated failed: %v", err)
	}
	if err := quicCoord.OnSessionStateChange(&p2p.Session{
		ID:        "quic-1",
		Status:    p2p.SessionStatusConnected,
		PathType:  p2p.PathRelay,
		LastError: "direct punch failed",
	}); err != nil {
		t.Fatalf("quic OnSessionStateChange failed: %v", err)
	}

	mgr := NewStatusManager(&StatusManagerConfig{
		EdgeID:     "edge-1",
		StatusDir:  t.TempDir(),
		Registry:   nil,
		P2PRuntime: runtime,
	})

	status := mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if len(status.P2P) != 2 {
		t.Fatalf("unexpected p2p namespace count: got=%d want=2", len(status.P2P))
	}
	if status.P2P[p2p.NamespaceWireGuard]["wg-1"] != "connected" {
		t.Fatalf("unexpected wireguard p2p status: %+v", status.P2P[p2p.NamespaceWireGuard])
	}
	if status.P2P[p2p.NamespaceQUIC]["quic-1"] != "connected" {
		t.Fatalf("unexpected quic p2p status: %+v", status.P2P[p2p.NamespaceQUIC])
	}

	if len(status.P2PSessions) != 2 {
		t.Fatalf("unexpected p2p session namespace count: got=%d want=2", len(status.P2PSessions))
	}
	wg := status.P2PSessions[p2p.NamespaceWireGuard]["wg-1"]
	if wg.Status != "connected" || wg.PathState != "connected" || wg.PathType != "direct" || wg.LinkType != "p2p" {
		t.Fatalf("unexpected wireguard p2p session info: %+v", wg)
	}
	quic := status.P2PSessions[p2p.NamespaceQUIC]["quic-1"]
	if quic.Status != "connected" || quic.PathState != "fallback" || quic.PathType != "relay" || quic.LinkType != "relay" {
		t.Fatalf("unexpected quic p2p session info: %+v", quic)
	}
	if quic.FallbackReason != "direct punch failed" {
		t.Fatalf("unexpected quic fallback reason: %q", quic.FallbackReason)
	}
}

func TestStatusManagerP2PSnapshotOmitsTerminalSessions(t *testing.T) {
	runtime := p2p.NewRuntime()
	wgCoord := runtime.Ensure(p2p.NamespaceWireGuard)

	if err := wgCoord.OnSessionCreated(&p2p.Session{ID: "wg-1", Status: p2p.SessionStatusNew}); err != nil {
		t.Fatalf("OnSessionCreated failed: %v", err)
	}
	if err := wgCoord.OnSessionStateChange(&p2p.Session{ID: "wg-1", Status: p2p.SessionStatusFailed}); err != nil {
		t.Fatalf("OnSessionStateChange NEW->FAILED failed: %v", err)
	}

	mgr := NewStatusManager(&StatusManagerConfig{
		EdgeID:     "edge-1",
		StatusDir:  t.TempDir(),
		P2PRuntime: runtime,
	})

	status := mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if len(status.P2P) != 0 {
		t.Fatalf("expected no active p2p sessions after terminal cleanup, got %+v", status.P2P)
	}
	if len(status.P2PSessions) != 0 {
		t.Fatalf("expected no active p2p session infos after terminal cleanup, got %+v", status.P2PSessions)
	}
}

func TestStatusManagerIncludesSubdomainResolutionStats(t *testing.T) {
	expected := &SubdomainResolutionStats{
		StartTotal:                    8,
		StartFieldTotal:               5,
		StartMetadataFallbackTotal:    2,
		StartNoneTotal:                1,
		JoinHintTotal:                 6,
		JoinHintFieldTotal:            3,
		JoinHintMetadataFallbackTotal: 2,
		JoinHintNoneTotal:             1,
		JoinHintMismatchTotal:         1,
		UpdatedAtUnix:                 1716000000,
	}

	mgr := NewStatusManager(&StatusManagerConfig{
		EdgeID:    "edge-1",
		StatusDir: t.TempDir(),
		SubdomainResolutionStatsProvider: func() *SubdomainResolutionStats {
			return expected
		},
	})

	status := mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if status.SubdomainResolution == nil {
		t.Fatalf("expected subdomain resolution stats in status")
	}
	got := status.SubdomainResolution
	if got.StartMetadataFallbackTotal != expected.StartMetadataFallbackTotal || got.JoinHintMismatchTotal != expected.JoinHintMismatchTotal {
		t.Fatalf("unexpected subdomain resolution stats: got=%+v want=%+v", got, expected)
	}
}

func TestStatusManagerIncludesWireGuardRelayRuntimeReady(t *testing.T) {
	mgr := NewStatusManager(&StatusManagerConfig{
		EdgeID:                     "edge-1",
		StatusDir:                  t.TempDir(),
		WireGuardRelayRuntimeReady: true,
	})

	status := mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if !status.WireGuardRelayRuntimeReady {
		t.Fatalf("expected wireguard relay runtime ready to be true")
	}

	mgr.SetWireGuardRelayRuntimeReady(false)
	status = mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status after update")
	}
	if status.WireGuardRelayRuntimeReady {
		t.Fatalf("expected wireguard relay runtime ready to be false after update")
	}
}

func TestStatusManagerIncludesWireGuardConfig(t *testing.T) {
	mgr := NewStatusManager(&StatusManagerConfig{
		EdgeID:                   "edge-1",
		StatusDir:                t.TempDir(),
		WireGuardEnabled:         true,
		WireGuardRelayEnabled:    true,
		WireGuardInterfacePrefix: "wg-yat",
		WireGuardListenPortBase:  58021,
		WireGuardKeyDir:          "/tmp/wireguard/keys",
		WireGuardPublicEndpoint:  "relay.example.com",
	})

	status := mgr.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if !status.WireGuardEnabled || !status.WireGuardRelayEnabled {
		t.Fatalf("unexpected wireguard flags: %+v", status)
	}
	if status.WireGuardInterfacePrefix != "wg-yat" {
		t.Fatalf("wireguard interface prefix = %q, want %q", status.WireGuardInterfacePrefix, "wg-yat")
	}
	if status.WireGuardListenPortBase != 58021 {
		t.Fatalf("wireguard listen port base = %d, want %d", status.WireGuardListenPortBase, 58021)
	}
	if status.WireGuardKeyDir != "/tmp/wireguard/keys" {
		t.Fatalf("wireguard key dir = %q, want %q", status.WireGuardKeyDir, "/tmp/wireguard/keys")
	}
	if status.WireGuardPublicEndpoint != "relay.example.com" {
		t.Fatalf("wireguard public endpoint = %q, want %q", status.WireGuardPublicEndpoint, "relay.example.com")
	}
}
