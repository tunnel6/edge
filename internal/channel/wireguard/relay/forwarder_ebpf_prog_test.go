//go:build ebpf

package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestParseTCRedirectConfig(t *testing.T) {
	for _, tt := range []struct{ cidr, relay string }{
		{"invalid", "10.24.0.1"}, {"::/64", "::1"},
		{"10.24.0.0/24", "invalid"}, {"10.24.0.0/24", "::1"},
		{"10.24.0.0/24", "10.25.0.1"}, {"::ffff:10.24.0.0/120", "10.24.0.1"},
	} {
		if _, err := parseTCRedirectConfig(tt.cidr, tt.relay); err == nil {
			t.Errorf("accepted invalid config: %+v", tt)
		}
	}
	cfg, err := parseTCRedirectConfig("192.168.128.123/24", "192.168.128.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != 0xc0a88000 || cfg.Netmask != 0xffffff00 || cfg.RelayIP != 0xc0a88001 {
		t.Fatalf("incorrect address encoding: %+v", cfg)
	}
}

func tcChecksum(packet []byte) uint16 {
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcPacket(src, dst string, ttl byte) []byte {
	packet := make([]byte, 28)
	packet[0], packet[8], packet[9] = 0x45, ttl, 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:16], net.ParseIP(src).To4())
	copy(packet[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(packet[20:], 12345)
	binary.BigEndian.PutUint16(packet[22:], 23456)
	binary.BigEndian.PutUint16(packet[24:], 8)
	binary.BigEndian.PutUint16(packet[10:], tcChecksum(packet))
	return packet
}

type tcPacketCase struct {
	name   string
	cfg    tcRedirectConfig
	packet []byte
	action uint32
}

func tcPacketCases(t *testing.T) []tcPacketCase {
	t.Helper()
	cfg, err := parseTCRedirectConfig("10.24.0.0/24", "10.24.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.IfIndex, cfg.MTU = 17, 1420
	var cases []tcPacketCase
	add := func(name string, packet []byte, action uint32) {
		cases = append(cases, tcPacketCase{name, cfg, packet, action})
	}
	add("peer to peer", tcPacket("10.24.0.2", "10.24.0.3", 64), 7)
	add("reverse direction", tcPacket("10.24.0.3", "10.24.0.2", 64), 7)
	add("relay local delivery", tcPacket("10.24.0.2", "10.24.0.1", 64), 0)
	add("source outside subnet", tcPacket("10.25.0.2", "10.24.0.3", 64), 0)
	add("destination outside subnet", tcPacket("10.24.0.2", "10.25.0.3", 64), 0)
	add("directed broadcast", tcPacket("10.24.0.2", "10.24.0.255", 64), 0)
	add("network address", tcPacket("10.24.0.2", "10.24.0.0", 64), 0)
	add("expired ttl", tcPacket("10.24.0.2", "10.24.0.3", 0), 0)
	add("icmp time exceeded path", tcPacket("10.24.0.2", "10.24.0.3", 1), 0)
	add("last forwardable hop", tcPacket("10.24.0.2", "10.24.0.3", 2), 7)
	add("empty", nil, 0)
	add("truncated header", make([]byte, 19), 0)
	p := make([]byte, 40)
	p[0] = 0x60
	add("ipv6", p, 0)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	p[0] = 0x46
	add("ip options use stack", p, 0)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	p[10] ^= 1
	add("bad checksum", p, 2)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	binary.BigEndian.PutUint16(p[2:], 19)
	add("invalid total length", p, 2)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	add("truncated payload", p[:27], 2)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	add("trailing padding uses stack", append(p, 0), 0)
	p = append(tcPacket("10.24.0.2", "10.24.0.3", 64), make([]byte, 1400)...)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	add("above mtu uses stack", p, 0)
	p = tcPacket("10.24.0.2", "10.24.0.3", 64)
	binary.BigEndian.PutUint16(p[6:], 0x2000) // more fragments
	binary.BigEndian.PutUint16(p[10:], 0)
	binary.BigEndian.PutUint16(p[10:], tcChecksum(p))
	add("fragment", p, 7)

	// Exercise checksum carry and the two representations of one's-complement
	// zero. IP IDs let us generate headers at the checksum boundary exactly.
	for _, target := range []uint16{0xfeff, 0xff00, 0xffff} {
		p = tcPacket("10.24.0.2", "10.24.0.3", 64)
		found := false
		for id := 0; id <= 65535; id++ {
			binary.BigEndian.PutUint16(p[4:], uint16(id))
			binary.BigEndian.PutUint16(p[10:], 0)
			if tcChecksum(p) == target || target == 0xffff && tcChecksum(p) == 0 {
				binary.BigEndian.PutUint16(p[10:], target)
				add(fmt.Sprintf("checksum boundary %04x", target), p, 7)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("could not generate checksum boundary %04x", target)
		}
	}
	for _, tt := range []struct {
		name, cidr, relay, src, dst string
		action                      uint32
	}{
		{"high address bit", "192.168.128.0/24", "192.168.128.1", "192.168.128.2", "192.168.128.3", 7},
		{"valid host ending in 255", "10.24.0.0/16", "10.24.0.1", "10.24.0.2", "10.24.0.255", 7},
		{"31 bit prefix", "10.24.0.0/31", "10.24.0.0", "10.24.0.0", "10.24.0.1", 7},
		{"32 bit local address", "10.24.0.1/32", "10.24.0.1", "10.24.0.1", "10.24.0.1", 0},
		{"multicast in broad cidr", "0.0.0.0/0", "10.24.0.1", "10.24.0.2", "224.0.0.1", 0},
		{"limited broadcast", "0.0.0.0/0", "10.24.0.1", "10.24.0.2", "255.255.255.255", 0},
	} {
		other, err := parseTCRedirectConfig(tt.cidr, tt.relay)
		if err != nil {
			t.Fatal(err)
		}
		other.IfIndex, other.MTU = cfg.IfIndex, cfg.MTU
		cases = append(cases, tcPacketCase{tt.name, other, tcPacket(tt.src, tt.dst, 64), tt.action})
	}
	return cases
}

func checkTCPacket(t *testing.T, tt tcPacketCase, action uint32, out []byte) {
	t.Helper()
	if action != tt.action {
		t.Fatalf("TC action = %d, want %d", action, tt.action)
	}
	want := bytes.Clone(tt.packet)
	if action == 7 {
		want[8]--
		binary.BigEndian.PutUint16(want[10:], 0)
		binary.BigEndian.PutUint16(want[10:], tcChecksum(want))
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("packet = %x, want %x", out, want)
	}
}

func TestTCProgramPackets(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run(order.String(), func(t *testing.T) {
			for _, tt := range tcPacketCases(t) {
				t.Run(tt.name, func(t *testing.T) {
					action, out, stats := runTCBytecode(t, tt.cfg, tt.packet, order, 7, false)
					checkTCPacket(t, tt, action, out)
					var want ForwarderStats
					if action == 7 {
						want.Forwarded = 1
					}
					if stats != want {
						t.Fatalf("stats = %+v, want %+v", stats, want)
					}
				})
			}
		})
	}
}

func TestTCProgramPreservesRedirectAction(t *testing.T) {
	tt := tcPacketCases(t)[0]
	for _, mapMiss := range []bool{false, true} {
		for _, result := range []uint64{2, 7} {
			action, _, stats := runTCBytecode(t, tt.cfg, tt.packet, binary.LittleEndian, result, mapMiss)
			if action != uint32(result) {
				t.Fatalf("helper action %d overwritten by %d", result, action)
			}
			var want ForwarderStats
			if !mapMiss && result == 7 {
				want.Forwarded = 1
			}
			if stats != want {
				t.Fatalf("stats = %+v, want %+v", stats, want)
			}
		}
	}
}
