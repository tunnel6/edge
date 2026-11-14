package channel

import (
	"strings"
	"testing"
)

func TestIsProtocolAllowedByCapabilities_BackwardCompatibleWhenEmpty(t *testing.T) {
	if !isProtocolAllowedByCapabilities("tcp", nil) {
		t.Fatalf("expected protocol allowed when capabilities are absent")
	}
	if !isProtocolAllowedByCapabilities("udp", []string{"", "   "}) {
		t.Fatalf("expected protocol allowed when capabilities are effectively empty")
	}
}

func TestIsProtocolAllowedByCapabilities_HTTPAndHTTPSCompatibility(t *testing.T) {
	if !isProtocolAllowedByCapabilities("http", []string{"https"}) {
		t.Fatalf("expected http allowed by https capability")
	}
	if !isProtocolAllowedByCapabilities("https", []string{"http"}) {
		t.Fatalf("expected https allowed by http capability")
	}
	if isProtocolAllowedByCapabilities("https", []string{"tcp"}) {
		t.Fatalf("expected https denied without http/https capability")
	}
}

func TestIsProtocolAllowedByCapabilities_TCPAndUDP(t *testing.T) {
	if !isProtocolAllowedByCapabilities("tcp", []string{"tcp"}) {
		t.Fatalf("expected tcp allowed with tcp capability")
	}
	if isProtocolAllowedByCapabilities("tcp", []string{"udp"}) {
		t.Fatalf("expected tcp denied without tcp capability")
	}
	if !isProtocolAllowedByCapabilities("udp", []string{"udp"}) {
		t.Fatalf("expected udp allowed with udp capability")
	}
	if isProtocolAllowedByCapabilities("udp", []string{"tcp"}) {
		t.Fatalf("expected udp denied without udp capability")
	}
}

func TestIsProtocolAllowedByCapabilities_WireGuardAliases(t *testing.T) {
	if !isProtocolAllowedByCapabilities("wireguard", []string{"wg"}) {
		t.Fatalf("expected wireguard allowed by wg capability")
	}
	if !isProtocolAllowedByCapabilities("wg", []string{"wireguard"}) {
		t.Fatalf("expected wg allowed by wireguard capability")
	}
	if isProtocolAllowedByCapabilities("wireguard", []string{"tcp"}) {
		t.Fatalf("expected wireguard denied without wireguard capability")
	}
}

func TestRequiredCapabilitiesForProtocol(t *testing.T) {
	cases := []struct {
		protocol string
		want     []string
	}{
		{protocol: "http", want: []string{"http", "https"}},
		{protocol: "https", want: []string{"http", "https"}},
		{protocol: "tcp", want: []string{"tcp"}},
		{protocol: "udp", want: []string{"udp"}},
		{protocol: "wireguard", want: []string{"wireguard", "wg"}},
		{protocol: "wg", want: []string{"wireguard", "wg"}},
		{protocol: "unknown", want: nil},
	}
	for _, tc := range cases {
		got := requiredCapabilitiesForProtocol(tc.protocol)
		if len(got) != len(tc.want) {
			t.Fatalf("protocol=%s expected %d required caps, got %d (%v)", tc.protocol, len(tc.want), len(got), got)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("protocol=%s expected required caps %v, got %v", tc.protocol, tc.want, got)
			}
		}
	}
}

func TestCapabilityViolationMessage_StableFormat(t *testing.T) {
	msg := capabilityViolationMessage("tcp")
	if !strings.Contains(msg, "capability mismatch: protocol=tcp") {
		t.Fatalf("unexpected message prefix: %s", msg)
	}
	if !strings.Contains(msg, "requires one of [tcp]") {
		t.Fatalf("unexpected required capabilities in message: %s", msg)
	}
}
