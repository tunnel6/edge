package ice

import (
	"net"
	"testing"
	"time"
)

func TestUDPProbeEndToEnd(t *testing.T) {
	bridge := &mockBridge{policy: &LinkPolicy{
		P2PMode:            "preferred",
		AllowRelayFallback: true,
	}}
	cfg := DefaultConfig()
	cfg.UDPAddr = "127.0.0.1:0"
	cfg.UDPAddrAlt = "127.0.0.1:0"
	ctrl := NewController(cfg, bridge)
	if err := ctrl.Start(); err != nil {
		t.Fatalf("controller start failed: %v", err)
	}
	defer ctrl.Stop()

	ctrl.OnPeerSessionEstablished("tunnel-e2e", "pub-e2e", "con-e2e")
	time.Sleep(20 * time.Millisecond)

	ctrl.mu.RLock()
	var session *Session
	for _, s := range ctrl.sessions {
		session = s
	}
	ctrl.mu.RUnlock()
	if session == nil {
		t.Fatal("expected session to be created")
	}

	primaryAddr := ctrl.udpListener.Addr()
	altAddr := ctrl.udpListener.AddrAlt()

	sendProbe(t, primaryAddr, session.PubToken, session.Pwd, false)
	sendProbe(t, altAddr, session.PubToken, session.Pwd, true)
	sendProbe(t, primaryAddr, session.ConToken, session.Pwd, false)
	sendProbe(t, altAddr, session.ConToken, session.Pwd, true)

	time.Sleep(50 * time.Millisecond)

	state := session.GetState()
	if state != StatePunching && state != StateFallback {
		t.Fatalf("expected punching or fallback after both probes, got %s", state)
	}

	if session.PublisherEndpoint == nil {
		t.Fatal("expected publisher endpoint to be set")
	}
	if session.ConsumerEndpoint == nil {
		t.Fatal("expected consumer endpoint to be set")
	}
}

func sendProbe(t *testing.T, addr string, token, pwd string, isAlt bool) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolve addr %s: %v", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("dial udp %s: %v", addr, err)
	}
	defer conn.Close()

	pktType := UDPPacketProbe
	if isAlt {
		pktType = UDPPacketProbeAlt
	}
	pkt := buildUDPPacket(pktType, token, pwd)

	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write probe: %v", err)
	}
}
