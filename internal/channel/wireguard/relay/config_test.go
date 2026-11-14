package relay

import "testing"

func TestInterfaceNameFitsLinuxLimit(t *testing.T) {
	cfg := &Config{InterfacePrefix: "wg-yat0"}
	name := cfg.InterfaceName("net_x9ktw6icbnw15d")

	if got := len(name); got > maxLinuxInterfaceNameLen {
		t.Fatalf("interface name length = %d, want <= %d (%q)", got, maxLinuxInterfaceNameLen, name)
	}
	if name != cfg.InterfaceName("net_x9ktw6icbnw15d") {
		t.Fatalf("interface name should be deterministic, got %q", name)
	}
	if wantPrefix := "wg-yat0-"; len(name) <= len(wantPrefix) || name[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("interface name = %q, want prefix %q", name, wantPrefix)
	}
}

func TestInterfaceNameTruncatesLongPrefixToLeaveSuffixRoom(t *testing.T) {
	cfg := &Config{InterfacePrefix: "wireguard-relay"}
	name := cfg.InterfaceName("net_x9ktw6icbnw15d")

	if got := len(name); got > maxLinuxInterfaceNameLen {
		t.Fatalf("interface name length = %d, want <= %d (%q)", got, maxLinuxInterfaceNameLen, name)
	}
	if wantPrefix := "wireguar-"; len(name) <= len(wantPrefix) || name[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("interface name = %q, want truncated prefix %q", name, wantPrefix)
	}
}

func TestRelayMemberIDHandlesShortAndLongNetworkIDs(t *testing.T) {
	if got := relayMemberID("net1"); got != "relay-net1" {
		t.Fatalf("relayMemberID(short) = %q, want %q", got, "relay-net1")
	}

	got := relayMemberID("net_x9ktw6icbnw15d")
	if got == "" {
		t.Fatal("relayMemberID(long) returned empty string")
	}
	if got != relayMemberID("net_x9ktw6icbnw15d") {
		t.Fatalf("relayMemberID should be deterministic, got %q", got)
	}
}
