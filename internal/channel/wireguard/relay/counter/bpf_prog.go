//go:build ebpf

package counter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// PeerStatsBPFValue is the on-wire (BPF map) representation of per-peer stats.
// Field order must match the BPF program's store instructions.
type PeerStatsBPFValue struct {
	Bytes   uint64
	Packets uint64
	Dropped uint64
}

// PeerStatsMapSpec returns the BPF map specification for per-peer traffic
// statistics. The map is a HashMap keyed by source IPv4 address (uint32).
func PeerStatsMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "peer_stats",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  24, // 3 × uint64
		MaxEntries: 1024,
	}
}

// BuildPeerCounterProgram generates BPF instructions for a TC ingress program
// that extracts the IPv4 source address from each packet and atomically
// increments per-peer counters in a BPF hash map.
//
// The program is designed to be attached alongside (at a different priority
// than) the eBPF forwarder's redirect program, or standalone for the kernel
// forwarder path where all ingress traffic is counted.
//
// Equivalent pseudo-C:
//
//	void counter(struct __sk_buff *skb) {
//	    void *data = (void *)(long)skb->data;
//	    if (data + 20 > skb->data_end) return 0;
//	    if (*(u8*)data >> 4 != 4) return 0;        // IPv4
//	    u32 src_ip = *(u32*)(data + 12);            // big-endian
//	    struct stats *s = map_lookup(&stats_map, &src_ip);
//	    if (!s) { struct stats zero = {}; map_update(...); s = map_lookup(...); }
//	    if (s) { s->bytes += skb->len; s->packets++; }
//	    return TC_ACT_OK;
//	}
func BuildPeerCounterProgram(statsMapFD int) asm.Instructions {
	return asm.Instructions{
		// R6 = skb
		asm.Mov.Reg(asm.R6, asm.R1),

		// R7 = skb->data, R2 = skb->data_end
		asm.LoadMem(asm.R7, asm.R6, 76, asm.Word),
		asm.LoadMem(asm.R2, asm.R6, 80, asm.Word),

		// Bounds check: data + 20 <= data_end (minimum IPv4 header)
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 20),
		asm.JGT.Reg(asm.R3, asm.R2, "pass"),

		// Check IPv4: version field (first byte >> 4 == 4 → 0x40)
		asm.LoadMem(asm.R3, asm.R7, 0, asm.Byte),
		asm.JNE.Imm(asm.R3, 0x45, "pass"), // 0x45 = IPv4, IHL=5 (no options)

		// Extract source IP (offset 12, 4 bytes, big-endian)
		asm.LoadMem(asm.R3, asm.R7, 12, asm.Word),

		// Store src_ip on stack (-8) for map lookup key pointer
		asm.StoreMem(asm.R10, -8, asm.R3, asm.Word),

		// Map lookup: R1=map_fd, R2=&key, R3=flags(0)
		asm.LoadMapPtr(asm.R1, statsMapFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnMapLookupElem.Call(),

		// If found (R0 != 0), increment bytes and packets
		asm.JEq.Imm(asm.R0, 0, "pass"),

		// Load skb->len for bytes counter
		asm.LoadMem(asm.R4, asm.R6, 0, asm.Word),

		// Atomic add skb->len to bytes (offset +0)
		asm.Mov.Reg(asm.R1, asm.R4),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),

		// Atomic add 1 to packets (offset +8)
		asm.Mov.Imm(asm.R1, 1),
		asm.Add.Imm(asm.R0, 8),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),

		// Return TC_ACT_OK
		asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"),
		asm.Return(),
	}
}

// PeerCounterProgramSpec creates a TC ingress BPF program spec for per-peer
// traffic counting.
func PeerCounterProgramSpec(statsMapFD int) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:         "yat_peer_counter",
		Type:         ebpf.SchedCLS,
		Instructions: BuildPeerCounterProgram(statsMapFD),
		License:      "GPL",
	}
}

// IPToMapKey converts a net.IP to a uint32 key suitable for the BPF map.
func IPToMapKey(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

// MapKeyToIP converts a uint32 BPF map key back to a net.IP.
func MapKeyToIP(key uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, key)
	return ip
}

// ReadPeerStats reads all per-peer statistics from the BPF map.
func ReadPeerStats(m *ebpf.Map) (map[string]PeerStats, error) {
	result := make(map[string]PeerStats)
	var key uint32
	var value PeerStatsBPFValue

	entries := m.Iterate()
	for entries.Next(&key, &value) {
		ip := MapKeyToIP(key)
		result[ip.String()] = PeerStats{
			Bytes:   value.Bytes,
			Packets: value.Packets,
			Dropped: value.Dropped,
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("iterate peer stats: %w", err)
	}
	return result, nil
}
