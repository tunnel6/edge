package ice

import (
	"net"
	"testing"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

func TestSessionTransitions(t *testing.T) {
	s, err := NewSession("tunnel-1", "pub-sess", "con-sess")
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if s.GetState() != StateIdle {
		t.Fatalf("expected idle, got %s", s.GetState())
	}

	if err := s.Transition(StateGathering); err != nil {
		t.Fatalf("idle->gathering failed: %v", err)
	}
	if err := s.Transition(StatePunching); err != nil {
		t.Fatalf("gathering->punching failed: %v", err)
	}
	if err := s.Transition(StateConnecting); err != nil {
		t.Fatalf("punching->connecting failed: %v", err)
	}
	if err := s.Transition(StateConnected); err != nil {
		t.Fatalf("connecting->connected failed: %v", err)
	}
	if err := s.Transition(StateGathering); err == nil {
		t.Fatalf("expected error on transition from terminal state")
	}
}

func TestSessionInvalidTransition(t *testing.T) {
	s, _ := NewSession("t", "p", "c")
	if err := s.Transition(StateConnected); err == nil {
		t.Fatalf("expected error for idle->connected")
	}
}

func TestSessionDetermineStrategy(t *testing.T) {
	tests := []struct {
		name     string
		natA     p2p.NATType
		natB     p2p.NATType
		expected PunchStrategy
	}{
		{"cone+cone", p2p.NATFullCone, p2p.NATRestrictedCone, StrategyStandard},
		{"cone+sym", p2p.NATFullCone, p2p.NATSymmetric, StrategyPortPredict},
		{"sym+cone", p2p.NATSymmetric, p2p.NATPortRestricted, StrategyPortPredict},
		{"sym+sym", p2p.NATSymmetric, p2p.NATSymmetric, StrategyRelay},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := NewSession("t", "p", "c")
			s.SetPublisherEndpoint(&PeerEndpoint{NATType: tt.natA})
			s.SetConsumerEndpoint(&PeerEndpoint{NATType: tt.natB})
			got := s.DetermineStrategy()
			if got != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestSessionBothEndpointsReady(t *testing.T) {
	s, _ := NewSession("t", "p", "c")
	if s.BothEndpointsReady() {
		t.Fatal("expected not ready with no endpoints")
	}

	s.SetPublisherEndpoint(&PeerEndpoint{
		UDPAddr: &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5000},
	})
	if s.BothEndpointsReady() {
		t.Fatal("expected not ready with only publisher")
	}

	s.SetConsumerEndpoint(&PeerEndpoint{
		UDPAddr: &net.UDPAddr{IP: net.ParseIP("5.6.7.8"), Port: 6000},
	})
	if !s.BothEndpointsReady() {
		t.Fatal("expected ready with both endpoints")
	}
}
