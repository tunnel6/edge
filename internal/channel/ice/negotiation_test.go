package ice

import (
	"net"
	"sync"
	"testing"
	"time"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

// Exercise the real controller's orchestration without a UDP listener. Network
// messages are recorded, never interpreted as successful transport evidence.
type negotiationBridge struct {
	mu       sync.Mutex
	policy   *LinkPolicy
	states   []State
	messages map[int]int
	notify   chan struct{}
	onSend   func(int)
}

func (b *negotiationBridge) SendToClient(_ string, kind int, _ []byte) error {
	b.mu.Lock()
	b.messages[kind]++
	b.mu.Unlock()
	if b.onSend != nil {
		b.onSend(kind)
	}
	select {
	case b.notify <- struct{}{}:
	default:
	}
	return nil
}
func (b *negotiationBridge) GetTunnelLinkPolicy(string) *LinkPolicy { return b.policy }
func (b *negotiationBridge) ReportICEStateChange(_, _, _, _ string, state State, _ *StateDetail) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.states = append(b.states, state)
}
func (b *negotiationBridge) waitMessages(t *testing.T, kind, count int) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		b.mu.Lock()
		actual := b.messages[kind]
		b.mu.Unlock()
		if actual >= count {
			return
		}
		select {
		case <-b.notify:
		case <-timer.C:
			t.Fatalf("expected %d messages of kind %d, got %d", count, kind, actual)
		}
	}
}

func negotiationController(t *testing.T, relay bool) (*Controller, *Session, *negotiationBridge) {
	t.Helper()
	mode := "preferred"
	if !relay {
		mode = "required"
	}
	b := &negotiationBridge{
		policy:   &LinkPolicy{P2PMode: mode, AllowRelayFallback: relay, RequireDirect: !relay},
		messages: make(map[int]int), notify: make(chan struct{}, 32),
	}
	cfg := DefaultConfig()
	cfg.PunchTimeout = time.Hour
	cfg.ConnectTimeout = time.Hour
	c := NewController(cfg, b)
	s, err := NewSession("tunnel", "pub", "con")
	if err != nil {
		t.Fatal(err)
	}
	c.sessions[s.ID] = s
	c.tokenIndex[s.PubToken] = &tokenEntry{sessionID: s.ID, role: "pub"}
	c.tokenIndex[s.ConToken] = &tokenEntry{sessionID: s.ID, role: "con"}
	if err := s.Transition(StateGathering); err != nil {
		t.Fatal(err)
	}
	c.reportState(s, nil)
	// Start is deliberately not called: no socket, GC loop or live Edge service.
	t.Cleanup(func() { close(c.stopCh) })
	return c, s, b
}

func installNegotiationEndpoints(s *Session) {
	s.SetPublisherEndpoint(&PeerEndpoint{
		SessionID: s.PublisherSessionID, NATType: p2p.NATFullCone,
		UDPAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 58020},
	})
	s.SetConsumerEndpoint(&PeerEndpoint{
		SessionID: s.ConsumerSessionID, NATType: p2p.NATFullCone,
		UDPAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 58020},
	})
}

func TestNegotiationTunnelFlowPreservesBothReportOrders(t *testing.T) {
	for _, first := range []string{"pub", "con"} {
		t.Run(first, func(t *testing.T) {
			c, s, b := negotiationController(t, true)
			pub := &PeerEndpoint{SessionID: "pub", NATType: p2p.NATFullCone,
				UDPAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 58020}}
			con := &PeerEndpoint{SessionID: "con", NATType: p2p.NATFullCone,
				UDPAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 58020}}
			c.handleProbe(s, pub)
			if s.GetState() != StateGathering {
				t.Fatal("one endpoint started punching")
			}
			c.handleProbe(s, con)
			b.waitMessages(t, int(msgTypeICEPunch), 2)
			second := "pub"
			if first == "pub" {
				second = "con"
			}
			for _, sender := range []string{first, first, "outsider"} {
				c.OnPunchResultReceived(sender, s.ID, &PunchResult{Success: true})
				if s.GetState() != StatePunching {
					t.Fatal("one participant/duplicate/outsider completed punching")
				}
			}
			c.OnPunchResultReceived(second, s.ID, &PunchResult{Success: true})
			b.waitMessages(t, int(msgTypeICEQuic), 2)
			if s.GetState() != StateConnecting {
				t.Fatalf("both successes did not start QUIC: %s", s.GetState())
			}
			c.OnPunchResultReceived(first, s.ID, &PunchResult{FailureReason: "late"})
			if s.GetState() != StateConnecting {
				t.Fatal("late failure interrupted QUIC")
			}
			c.OnQuicConnected(s.ID, &QuicConnInfo{ConnectionID: "native-quic-evidence"})
			c.OnPunchResultReceived(second, s.ID, &PunchResult{Success: true})
			if s.GetState() != StateConnected {
				t.Fatal("late success changed connected state")
			}
			b.mu.Lock()
			states := append([]State(nil), b.states...)
			b.mu.Unlock()
			want := []State{StateGathering, StatePunching, StateConnecting, StateConnected}
			if len(states) != len(want) {
				t.Fatalf("unexpected transitions: %v", states)
			}
			for i := range want {
				if states[i] != want[i] {
					t.Fatalf("unexpected transitions: %v", states)
				}
			}
			if len(c.tokenIndex) != 0 {
				t.Fatal("connected session retained active probe tokens")
			}
		})
	}
}

func TestNegotiationTunnelTimeoutPreservesFallbackPolicy(t *testing.T) {
	for _, relay := range []bool{true, false} {
		for _, phase := range []State{StateGathering, StatePunching, StateConnecting} {
			t.Run(string(phase)+map[bool]string{true: "/preferred", false: "/required"}[relay], func(t *testing.T) {
				c, s, _ := negotiationController(t, relay)
				if phase != StateGathering {
					installNegotiationEndpoints(s)
					if err := s.Transition(StatePunching); err != nil {
						t.Fatal(err)
					}
				}
				switch phase {
				case StateGathering:
					c.config.GatherTimeout = 0
					c.gatherEndpoints(s, "127.0.0.1:50000", "127.0.0.1:50001", c.stopCh)
				case StateConnecting:
					if err := s.Transition(StateConnecting); err != nil {
						t.Fatal(err)
					}
					c.config.ConnectTimeout = 0
					c.startQuicConnect(s)
				case StatePunching:
					c.config.PunchTimeout = 0
					c.startPunching(s)
				}
				want := StateFailed
				if relay {
					want = StateFallback
				}
				if s.GetState() != want || len(c.tokenIndex) != 0 {
					t.Fatalf("timeout result=%s tokens=%d", s.GetState(), len(c.tokenIndex))
				}
			})
		}
	}
}

func TestNegotiationTunnelGatherRetransmitsUntilClosed(t *testing.T) {
	c, s, b := negotiationController(t, true)
	c.config.GatherTimeout = time.Hour
	starts := 0
	b.onSend = func(kind int) {
		if kind == int(msgTypeICEStart) {
			starts++
			if starts == 3 {
				// Close during the retransmitted pair. The existing execution
				// finishes its pair of sends, then stops before waiting again.
				c.OnSessionClosed(s.ID)
			}
		}
	}
	c.gatherEndpoints(s, "127.0.0.1:50000", "127.0.0.1:50001", c.stopCh)
	if starts != 4 || s.GetState() != StateClosed {
		t.Fatalf("gather retry/close changed: sends=%d state=%s", starts, s.GetState())
	}
}

func TestNegotiationTunnelCloseInvalidatesCapturedTimeout(t *testing.T) {
	for _, closeBy := range []string{"close", "disconnect", "leave"} {
		t.Run(closeBy, func(t *testing.T) {
			c, s, _ := negotiationController(t, true)
			window := s.phaseWindow(StateGathering, 0)
			if !s.phaseTimeoutDue(window, time.Now()) {
				t.Fatal("active gather deadline was not due")
			}
			switch closeBy {
			case "close":
				c.OnSessionClosed(s.ID)
			case "disconnect":
				c.OnClientSessionDisconnected("pub")
			case "leave":
				if c.OnConsumerLeftTunnel("tunnel", "con", "left") != 1 {
					t.Fatal("consumer leave missed session")
				}
			}
			if s.GetState() != StateClosed || s.phaseTimeoutDue(window, time.Now()) || len(c.tokenIndex) != 0 {
				t.Fatal("closed session retained timeout authority/tokens")
			}
			// Retained old sessions still collect diagnostics, but cannot advance
			// a new attempt for the same pair or restart their own execution.
			next, err := NewSession("tunnel", "pub", "con")
			if err != nil {
				t.Fatal(err)
			}
			c.sessions[next.ID] = next
			if err := next.Transition(StateGathering); err != nil {
				t.Fatal(err)
			}
			for _, sender := range []string{"pub", "con"} {
				c.OnPunchResultReceived(sender, s.ID, &PunchResult{Success: true})
			}
			if next.GetState() != StateGathering || s.GetState() != StateClosed {
				t.Fatal("old results advanced a replaced attempt")
			}
		})
	}
}

func TestNegotiationTunnelKeepsLegacyUnknownFailureHandling(t *testing.T) {
	c, s, _ := negotiationController(t, true)
	c.OnPunchResultReceived("outsider", s.ID, &PunchResult{FailureReason: "legacy input"})
	if s.GetState() != StateFallback {
		t.Fatal("extraction silently changed legacy unknown-sender failure policy")
	}
}

func TestNegotiationTunnelWaitHonorsControllerStop(t *testing.T) {
	c := NewController(DefaultConfig(), nil)
	s, err := NewSession("t", "p", "c")
	if err != nil {
		t.Fatal(err)
	}
	close(c.stopCh)
	if c.waitPhaseTimeout(s, StateIdle, time.Hour) {
		t.Fatal("controller cancellation became a timeout failure")
	}
}
