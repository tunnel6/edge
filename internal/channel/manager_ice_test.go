package channel

import (
	"fmt"
	"sync"
	"testing"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	icepkg "icool.io/yat/edge/internal/channel/ice"
	p2p "icool.io/yat/edge/internal/channel/p2p"
)

type staticDomainProvider struct {
	assigned string
	custom   string
}

func (p *staticDomainProvider) GetAssignedDomain() string {
	return p.assigned
}

func (p *staticDomainProvider) GetCustomDomain() string {
	return p.custom
}

type recordingClientPusher struct {
	mu         sync.Mutex
	allowed    map[string]struct{}
	calls      []string
	unexpected []string
}

func newRecordingClientPusher(allowed ...string) *recordingClientPusher {
	set := make(map[string]struct{}, len(allowed))
	for _, id := range allowed {
		set[id] = struct{}{}
	}
	return &recordingClientPusher{allowed: set}
}

func (p *recordingClientPusher) PushToClient(clientID string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, clientID)
	if _, ok := p.allowed[clientID]; !ok {
		p.unexpected = append(p.unexpected, clientID)
		return fmt.Errorf("unexpected client id: %s", clientID)
	}
	return nil
}

func (p *recordingClientPusher) AsyncPushToClients(targetClients []string, _ []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range targetClients {
		p.calls = append(p.calls, id)
		if _, ok := p.allowed[id]; !ok {
			p.unexpected = append(p.unexpected, id)
		}
	}
}

func (p *recordingClientPusher) hasCall(clientID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range p.calls {
		if id == clientID {
			return true
		}
	}
	return false
}

func (p *recordingClientPusher) unexpectedCalls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.unexpected))
	copy(out, p.unexpected)
	return out
}

func newICEEnabledManagerForTest(t *testing.T, pusher ClientPusher, gatherTimeout time.Duration) *ChannelManager {
	t.Helper()

	iceCfg := icepkg.DefaultConfig()
	iceCfg.UDPAddr = "127.0.0.1:0"
	iceCfg.UDPAddrAlt = "127.0.0.1:0"
	iceCfg.GatherTimeout = gatherTimeout

	manager, err := NewChannelManager(&Config{
		DomainProvider: &staticDomainProvider{assigned: "edge.example.com"},
		StatusDir:      t.TempDir(),
		ICEConfig:      &iceCfg,
	}, nil, pusher)
	if err != nil {
		t.Fatalf("NewChannelManager failed: %v", err)
	}
	if err := manager.Start(); err != nil {
		t.Fatalf("manager start failed: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.Stop()
	})
	return manager
}

func addActiveP2PTarget(
	manager *ChannelManager,
	channelID, sessionID, userID, deviceID string,
	role fbMsg.TunnelActorRole,
) *Channel {
	target := NewChannel(channelID, fbMsg.ChannelTypeTCP, sessionID, userID, deviceID, "host", "127.0.0.1:22")
	target.ActorRole = role
	target.LinkType = "p2p"
	target.SetState(StateActive)

	manager.registry.targets[channelID] = target
	manager.registry.sessionTargets[sessionID] = append(manager.registry.sessionTargets[sessionID], channelID)
	return target
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool, reason string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("wait timeout: %s", reason)
}

func TestStatusIncludesICEWhenICEEnabled(t *testing.T) {
	manager := newICEEnabledManagerForTest(t, newRecordingClientPusher(), 2*time.Second)

	status := manager.GetStatus()
	if status == nil {
		t.Fatalf("expected non-nil status")
	}
	if status.ICE == nil {
		t.Fatalf("expected ICE snapshot in status when ICE is enabled")
	}
	if status.ICEStats == nil {
		t.Fatalf("expected ICE stats in status when ICE is enabled")
	}
}

func TestMaybeStartICEUsesClientIDInsteadOfTransportSessionID(t *testing.T) {
	const (
		tunnelID     = "tun-ice-client-id"
		pubSessionID = "a9c2a3cf-acae-46b4-b30d-7695c93586d8"
		conSessionID = "b9e36a58-2e65-4628-919e-41d9a9fce1f3"
		pubClientID  = "device-pub"
		conClientID  = "device-con"
		pubChannelID = "tun-ice-client-id:tcp-main"
		conChannelID = "tun-ice-client-id:tcp-main:consumer:device-con"
	)

	pusher := newRecordingClientPusher(pubClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 2*time.Second)

	addActiveP2PTarget(manager, pubChannelID, pubSessionID, "user-a", "device-pub", fbMsg.TunnelActorRolePUBLISHER)
	addActiveP2PTarget(manager, conChannelID, conSessionID, "user-a", "device-con", fbMsg.TunnelActorRoleCONSUMER)

	manager.maybeStartICE(tunnelID)

	waitUntil(t, time.Second, func() bool {
		return pusher.hasCall(pubClientID) && pusher.hasCall(conClientID)
	}, "ICE messages should be pushed to both client IDs")

	if pusher.hasCall(pubSessionID) || pusher.hasCall(conSessionID) {
		t.Fatalf("transport session IDs should never be used for PushToClient, calls=%v", pusher.calls)
	}
	if unexpected := pusher.unexpectedCalls(); len(unexpected) > 0 {
		t.Fatalf("unexpected PushToClient targets: %v", unexpected)
	}
}

func TestStartICEForConsumerTriggersNegotiation(t *testing.T) {
	const (
		tunnelID     = "tun-ice-join-trigger"
		pubSessionID = "transport-session-pub-join"
		pubClientID  = "device-pub"
		conClientID  = "device-con"
		pubChannelID = "tun-ice-join-trigger:tcp-main"
	)

	pusher := newRecordingClientPusher(pubClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 2*time.Second)

	addActiveP2PTarget(manager, pubChannelID, pubSessionID, "user-join", "device-pub", fbMsg.TunnelActorRolePUBLISHER)

	if err := manager.StartICEForConsumer(tunnelID, "user-join", "device-con"); err != nil {
		t.Fatalf("StartICEForConsumer failed: %v", err)
	}

	waitUntil(t, time.Second, func() bool {
		return pusher.hasCall(pubClientID) && pusher.hasCall(conClientID)
	}, "ICE messages should be pushed to publisher and joining consumer")
}

func TestStartICEForConsumerRejectsWhenP2PDisabled(t *testing.T) {
	const tunnelID = "tun-ice-join-disabled"

	pusher := newRecordingClientPusher()
	manager := newICEEnabledManagerForTest(t, pusher, 2*time.Second)

	relayOnly := NewChannel("tun-ice-join-disabled:tcp-main", fbMsg.ChannelTypeTCP, "sess-relay", "u", "relay-pub", "host", "127.0.0.1:22")
	relayOnly.ActorRole = fbMsg.TunnelActorRolePUBLISHER
	relayOnly.LinkType = "relay"
	relayOnly.SetState(StateActive)
	manager.registry.targets[relayOnly.ID] = relayOnly
	manager.registry.sessionTargets[relayOnly.SessionID] = append(manager.registry.sessionTargets[relayOnly.SessionID], relayOnly.ID)

	err := manager.StartICEForConsumer(tunnelID, "u", "consumer-a")
	if err == nil {
		t.Fatalf("expected StartICEForConsumer to fail when tunnel has no active p2p publisher")
	}
}

func TestStopICEForConsumerClosesOnlyCurrentTunnel(t *testing.T) {
	const (
		tunnelA      = "tun-ice-leave-a"
		tunnelB      = "tun-ice-leave-b"
		pubAChannel  = "tun-ice-leave-a:tcp-main"
		pubBChannel  = "tun-ice-leave-b:tcp-main"
		pubAClientID = "device-pub-a"
		pubBClientID = "device-pub-b"
		conClientID  = "device-con"
	)

	pusher := newRecordingClientPusher(pubAClientID, pubBClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 2*time.Second)

	addActiveP2PTarget(manager, pubAChannel, "sess-pub-a", "user-leave", "device-pub-a", fbMsg.TunnelActorRolePUBLISHER)
	addActiveP2PTarget(manager, pubBChannel, "sess-pub-b", "user-leave", "device-pub-b", fbMsg.TunnelActorRolePUBLISHER)

	if err := manager.StartICEForConsumer(tunnelA, "user-leave", "device-con"); err != nil {
		t.Fatalf("start tunnelA failed: %v", err)
	}
	if err := manager.StartICEForConsumer(tunnelB, "user-leave", "device-con"); err != nil {
		t.Fatalf("start tunnelB failed: %v", err)
	}

	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		return snap != nil && snap.ActiveCount >= 2
	}, "both tunnels should have active ICE sessions")

	closed := manager.StopICEForConsumer(tunnelA, "user-leave", "device-con", "leave tunnel a")
	if closed == 0 {
		t.Fatalf("expected at least one ICE session closed for tunnelA")
	}

	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		if snap == nil {
			return false
		}
		var aClosed, bStillActive bool
		for _, s := range snap.Sessions {
			if s.TunnelID == tunnelA && s.State == icepkg.StateClosed {
				aClosed = true
			}
			if s.TunnelID == tunnelB && !s.State.IsTerminal() {
				bStillActive = true
			}
		}
		return aClosed && bStillActive
	}, "leave should close only matching tunnel session")
}

func TestCloseBySessionNotifiesICEByClientID(t *testing.T) {
	const (
		tunnelID     = "tun-ice-disconnect"
		pubSessionID = "transport-session-pub"
		conSessionID = "transport-session-con"
		pubClientID  = "device-pub"
		conClientID  = "device-con"
		pubChannelID = "tun-ice-disconnect:tcp-main"
		conChannelID = "tun-ice-disconnect:tcp-main:consumer:device-con"
	)

	pusher := newRecordingClientPusher(pubClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 2*time.Second)

	pubTarget := addActiveP2PTarget(manager, pubChannelID, pubSessionID, "user-b", "device-pub", fbMsg.TunnelActorRolePUBLISHER)
	addActiveP2PTarget(manager, conChannelID, conSessionID, "user-b", "device-con", fbMsg.TunnelActorRoleCONSUMER)

	manager.maybeStartICE(tunnelID)
	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		return snap != nil && snap.TotalCount >= 1
	}, "ICE session should be created")

	manager.CloseBySession(pubTarget.SessionID)

	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		if snap == nil {
			return false
		}
		for _, s := range snap.Sessions {
			if s.TunnelID == tunnelID {
				return s.State == icepkg.StateClosed
			}
		}
		return false
	}, "ICE session should close when publisher transport session disconnects")
}

func TestCollectICEPairsForTunnelTargets_PublisherToEveryConsumer(t *testing.T) {
	tunnelID := "tunnel-multi-consumer"
	targets := map[string]*Channel{
		"pub-main": {
			SessionID: "pub-main-session",
			UserID:    "u",
			DeviceID:  "pub-main",
			ActorRole: fbMsg.TunnelActorRolePUBLISHER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"pub-backup": {
			SessionID: "pub-backup-session",
			UserID:    "u",
			DeviceID:  "pub-backup",
			ActorRole: fbMsg.TunnelActorRolePUBLISHER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"con-a": {
			SessionID: "con-a-session",
			UserID:    "u",
			DeviceID:  "con-a",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"con-b": {
			SessionID: "con-b-session",
			UserID:    "u",
			DeviceID:  "con-b",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"con-relay": {
			SessionID: "con-relay-session",
			UserID:    "u",
			DeviceID:  "con-relay",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "relay",
			State:     StateActive,
		},
		"con-paused": {
			SessionID: "con-paused-session",
			UserID:    "u",
			DeviceID:  "con-paused",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "p2p",
			State:     StatePaused,
		},
	}

	pairs := collectICEPairsForTunnelTargets(tunnelID, targets)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}

	want := map[string]struct{}{
		"pub-backup|con-a": {},
		"pub-backup|con-b": {},
	}
	for _, pair := range pairs {
		key := pair.publisherClientID + "|" + pair.consumerClientID
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected pair: %s", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected pairs: %+v", want)
	}
}

func TestCollectICEPairsForTunnelTargets_SkipInvalidOrSameIdentity(t *testing.T) {
	tunnelID := "tunnel-skip-invalid"
	targets := map[string]*Channel{
		"pub": {
			SessionID: "pub-session",
			UserID:    "u",
			DeviceID:  "same",
			ActorRole: fbMsg.TunnelActorRolePUBLISHER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"con-same": {
			SessionID: "con-same-session",
			UserID:    "u",
			DeviceID:  "same",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "p2p",
			State:     StateActive,
		},
		"con-empty-id": {
			SessionID: "con-empty-id-session",
			UserID:    "u",
			DeviceID:  "",
			ActorRole: fbMsg.TunnelActorRoleCONSUMER,
			LinkType:  "p2p",
			State:     StateActive,
		},
	}

	pairs := collectICEPairsForTunnelTargets(tunnelID, targets)
	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs, got %d", len(pairs))
	}
}

func TestBuildP2PSessionFromICEConnectedIncludesPeers(t *testing.T) {
	iceSession := &icepkg.Session{
		ID:                 "ice:tun-1:session",
		TunnelID:           "tun-1",
		PublisherSessionID: "publisher-client",
		ConsumerSessionID:  "consumer-client",
	}
	policy := &icepkg.LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
		RequireDirect:      false,
	}

	p2pSession := buildP2PSessionFromICE(iceSession, icepkg.StateConnected, nil, policy)
	if p2pSession == nil {
		t.Fatalf("expected non-nil p2p session")
	}
	if p2pSession.ID != iceSession.ID || p2pSession.NetworkID != "tun-1" {
		t.Fatalf("unexpected identity mapping: %+v", p2pSession)
	}
	if p2pSession.PeerA != "publisher-client" || p2pSession.PeerB != "consumer-client" {
		t.Fatalf("unexpected peer mapping: %+v", p2pSession)
	}
	if p2pSession.Status != p2p.SessionStatusConnected || p2pSession.PathType != p2p.PathDirect {
		t.Fatalf("expected connected+direct mapping, got status=%v pathType=%v", p2pSession.Status, p2pSession.PathType)
	}
	if len(p2pSession.PreferredLinks) != 2 || p2pSession.PreferredLinks[0] != "p2p" || p2pSession.PreferredLinks[1] != "relay" {
		t.Fatalf("unexpected preferred links: %+v", p2pSession.PreferredLinks)
	}
}

func TestBuildP2PSessionFromICEFallbackUsesRelayAndError(t *testing.T) {
	iceSession := &icepkg.Session{
		ID:                 "ice:tun-2:session",
		TunnelID:           "tun-2",
		PublisherSessionID: "pub",
		ConsumerSessionID:  "con",
	}
	detail := &icepkg.StateDetail{Error: "punch timeout"}
	policy := &icepkg.LinkPolicy{
		P2PMode:            "required",
		AllowRelayFallback: false,
		RequireDirect:      true,
	}

	p2pSession := buildP2PSessionFromICE(iceSession, icepkg.StateFallback, detail, policy)
	if p2pSession == nil {
		t.Fatalf("expected non-nil p2p session")
	}
	if p2pSession.Status != p2p.SessionStatusConnected || p2pSession.PathType != p2p.PathRelay {
		t.Fatalf("expected fallback mapping to connected+relay, got status=%v pathType=%v", p2pSession.Status, p2pSession.PathType)
	}
	if p2pSession.LastError != "punch timeout" {
		t.Fatalf("expected last error propagated, got=%q", p2pSession.LastError)
	}
	if len(p2pSession.PreferredLinks) != 1 || p2pSession.PreferredLinks[0] != "p2p" {
		t.Fatalf("unexpected preferred links under required mode: %+v", p2pSession.PreferredLinks)
	}
	if !p2pSession.RequireDirect {
		t.Fatalf("expected require_direct=true")
	}
}

func TestMaybeStopICEForStoppedTunnelTargets_ClosesStaleSessionAndAllowsRestart(t *testing.T) {
	const (
		tunnelID     = "tun-ice-stop-restart"
		pubSessionID = "pub-transport-s1"
		conSessionID = "con-transport-s1"
		pubClientID  = "device-pub"
		conClientID  = "device-con"
		pubChannelID = "tun-ice-stop-restart:tcp-main"
		conChannelID = "tun-ice-stop-restart:tcp-main:consumer:device-con"
	)

	pusher := newRecordingClientPusher(pubClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 5*time.Second)

	addActiveP2PTarget(manager, pubChannelID, pubSessionID, "user-stop", "device-pub", fbMsg.TunnelActorRolePUBLISHER)
	conTarget := addActiveP2PTarget(manager, conChannelID, conSessionID, "user-stop", "device-con", fbMsg.TunnelActorRoleCONSUMER)

	manager.maybeStartICE(tunnelID)
	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		return snap != nil && snap.ActiveCount >= 1
	}, "ICE session should be active before stop")

	// Mimic tunnel stop: consumer channel is no longer in active tunnel targets.
	delete(manager.registry.targets, conChannelID)

	manager.maybeStopICEForStoppedTunnelTargets(tunnelID, []*Channel{conTarget})
	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		if snap == nil {
			return false
		}
		for _, s := range snap.Sessions {
			if s.TunnelID == tunnelID && s.State == icepkg.StateClosed {
				return true
			}
		}
		return false
	}, "stopped consumer should close stale ICE session")

	addActiveP2PTarget(manager, conChannelID, conSessionID, "user-stop", "device-con", fbMsg.TunnelActorRoleCONSUMER)
	manager.maybeStartICE(tunnelID)
	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		return snap != nil && snap.ActiveCount >= 1 && snap.TotalCount >= 2
	}, "consumer rejoin should create a fresh ICE session")
}

func TestMaybeStopICEForStoppedTunnelTargets_KeepsSessionWhenClientStillActive(t *testing.T) {
	const (
		tunnelID      = "tun-ice-stop-partial"
		pubSessionID  = "pub-transport-s2"
		conSessionID  = "con-transport-s2"
		pubClientID   = "device-pub"
		conClientID   = "device-con"
		pubChannelID  = "tun-ice-stop-partial:tcp-main"
		conChannelIDA = "tun-ice-stop-partial:tcp-main:consumer:device-con"
		conChannelIDB = "tun-ice-stop-partial:tcp-alt:consumer:device-con"
	)

	pusher := newRecordingClientPusher(pubClientID, conClientID)
	manager := newICEEnabledManagerForTest(t, pusher, 5*time.Second)

	addActiveP2PTarget(manager, pubChannelID, pubSessionID, "user-partial", "device-pub", fbMsg.TunnelActorRolePUBLISHER)
	conTargetA := addActiveP2PTarget(manager, conChannelIDA, conSessionID, "user-partial", "device-con", fbMsg.TunnelActorRoleCONSUMER)
	addActiveP2PTarget(manager, conChannelIDB, conSessionID, "user-partial", "device-con", fbMsg.TunnelActorRoleCONSUMER)

	manager.maybeStartICE(tunnelID)
	waitUntil(t, time.Second, func() bool {
		snap := manager.iceController.Snapshot()
		return snap != nil && snap.ActiveCount >= 1
	}, "ICE session should be active before partial stop")

	// Remove one consumer target, but keep another active target for the same client.
	delete(manager.registry.targets, conChannelIDA)

	manager.maybeStopICEForStoppedTunnelTargets(tunnelID, []*Channel{conTargetA})
	time.Sleep(150 * time.Millisecond)

	snap := manager.iceController.Snapshot()
	if snap == nil || snap.ActiveCount < 1 {
		t.Fatalf("ICE session should remain active when same client still has active p2p targets, snap=%+v", snap)
	}
}
