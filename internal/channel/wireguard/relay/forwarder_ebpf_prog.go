//go:build ebpf

package relay

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Addresses are host-order integers, compared with IP fields after ntohl.
// Configuration is embedded in the program when the interface is attached.
type tcRedirectConfig struct {
	IfIndex uint32
	Network uint32
	Netmask uint32
	RelayIP uint32
	MTU     uint32
}

func parseTCRedirectConfig(cidr, relayIP string) (tcRedirectConfig, error) {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil || len(subnet.Mask) != net.IPv4len {
		return tcRedirectConfig{}, fmt.Errorf("eBPF forwarder requires an IPv4 CIDR, got %q", cidr)
	}
	relay := net.ParseIP(relayIP).To4()
	if relay == nil || !subnet.Contains(relay) {
		return tcRedirectConfig{}, fmt.Errorf("relay IP %q must be IPv4 within %s", relayIP, cidr)
	}
	return tcRedirectConfig{
		Network: binary.BigEndian.Uint32(subnet.IP.To4()),
		Netmask: binary.BigEndian.Uint32(subnet.Mask),
		RelayIP: binary.BigEndian.Uint32(relay),
	}, nil
}

// buildTCProgram operates on raw IPv4 at WireGuard ingress and redirects it to
// WireGuard egress. bpf_redirect's flags MUST be zero (egress); BPF_F_INGRESS
// would re-enter this program. No peer redirect or Ethernet conversion is used.
//
// Per-peer statistics: after a successful redirect, the program extracts the
// source IP and atomically increments per-peer counters in a BPF HashMap.
//
// The fast path is limited to unicast intra-subnet traffic. Local delivery,
// IPv6, IP options, TTL exhaustion, and packets above the interface MTU stay
// on the normal stack. Validate the IPv4 checksum and decrement TTL since this
// path bypasses ip_forward. Kernel/WireGuard delivery can still fail after the
// helper returns: Forwarded counts redirect submissions, not remote delivery.
func buildTCProgram(cfg tcRedirectConfig, statsFD int) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),               // skb
		asm.LoadMem(asm.R7, asm.R6, 76, asm.Word), // data
		asm.LoadMem(asm.R2, asm.R6, 80, asm.Word), // data_end
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, 20),
		asm.JGT.Reg(asm.R3, asm.R2, "pass"),
		asm.LoadMem(asm.R3, asm.R7, 0, asm.Byte),
		asm.JNE.Imm(asm.R3, 0x45, "pass"), // IPv4 without options

		// Source and destination must both belong to this relay network.
		asm.LoadMem(asm.R3, asm.R7, 12, asm.Word),
		asm.HostTo(asm.BE, asm.R3, asm.Word),
		asm.And.Imm32(asm.R3, int32(cfg.Netmask)),
		asm.JNE.Imm32(asm.R3, int32(cfg.Network), "pass"),
		asm.LoadMem(asm.R4, asm.R7, 16, asm.Word),
		asm.HostTo(asm.BE, asm.R4, asm.Word),
		asm.Mov.Reg(asm.R3, asm.R4),
		asm.And.Imm32(asm.R3, int32(cfg.Netmask)),
		asm.JNE.Imm32(asm.R3, int32(cfg.Network), "pass"),
		asm.JEq.Imm32(asm.R4, int32(cfg.RelayIP), "pass"),
		asm.JGE.Imm32(asm.R4, -536870912, "pass"), // >= 224.0.0.0
	}
	// /31 and /32 do not have directed-broadcast or network addresses.
	if cfg.Netmask < 0xfffffffe {
		ins = append(ins,
			asm.JEq.Imm32(asm.R4, int32(cfg.Network), "pass"),
			asm.JEq.Imm32(asm.R4, int32(cfg.Network|^cfg.Netmask), "pass"),
		)
	}
	ins = append(ins,
		asm.LoadMem(asm.R3, asm.R7, 8, asm.Byte),
		asm.JLE.Imm(asm.R3, 1, "pass"), // let the stack generate ICMP time exceeded
		asm.LoadMem(asm.R3, asm.R7, 2, asm.Half),
		asm.HostTo(asm.BE, asm.R3, asm.Half),
		asm.JLT.Imm(asm.R3, 20, "drop"),
		asm.LoadMem(asm.R4, asm.R6, 0, asm.Word), // skb->len, including nonlinear data
		asm.JGT.Reg(asm.R3, asm.R4, "drop"),
		asm.JNE.Reg(asm.R3, asm.R4, "pass"), // let the stack trim trailing padding
	)
	if cfg.MTU != 0 {
		ins = append(ins, asm.JGT.Imm32(asm.R3, int32(cfg.MTU), "pass"))
	}

	// Validate the complete 20-byte IP header before bypassing ip_rcv.
	ins = append(ins, asm.Mov.Imm(asm.R3, 0))
	for offset := int16(0); offset < 20; offset += 2 {
		ins = append(ins,
			asm.LoadMem(asm.R4, asm.R7, offset, asm.Half),
			asm.Add.Reg(asm.R3, asm.R4),
		)
	}
	for i := 0; i < 2; i++ {
		ins = append(ins,
			asm.Mov.Reg(asm.R4, asm.R3),
			asm.RSh.Imm(asm.R4, 16),
			asm.And.Imm(asm.R3, 0xffff),
			asm.Add.Reg(asm.R3, asm.R4),
		)
	}
	ins = append(ins,
		asm.JNE.Imm(asm.R3, 0xffff, "drop"),

		// ip_decrease_ttl: decrement TTL and fix checksum.
		asm.LoadMem(asm.R3, asm.R7, 8, asm.Byte),
		asm.Sub.Imm(asm.R3, 1),
		asm.StoreMem(asm.R7, 8, asm.R3, asm.Byte),
		asm.LoadMem(asm.R3, asm.R7, 10, asm.Half),
		asm.HostTo(asm.BE, asm.R3, asm.Half),
		asm.Add.Imm(asm.R3, 0x100),
		asm.Mov.Reg(asm.R4, asm.R3),
		asm.RSh.Imm(asm.R4, 16),
		asm.And.Imm(asm.R3, 0xffff),
		asm.Add.Reg(asm.R3, asm.R4),
		asm.JNE.Imm(asm.R3, 0xffff, "store_checksum"),
		asm.Mov.Imm(asm.R3, 0),
		asm.HostTo(asm.BE, asm.R3, asm.Half).WithSymbol("store_checksum"),
		asm.StoreMem(asm.R7, 10, asm.R3, asm.Half),

		// Save source IP (big-endian, already in R3 from earlier extraction).
		// Re-extract src_ip from the packet for the stats map key.
		asm.LoadMem(asm.R3, asm.R7, 12, asm.Word),   // src IP (big-endian)
		asm.StoreMem(asm.R10, -8, asm.R3, asm.Word), // stack[-8] = src_ip

		asm.Mov.Imm32(asm.R1, int32(cfg.IfIndex)),
		asm.Mov.Imm(asm.R2, 0), // egress, never BPF_F_INGRESS
		asm.FnRedirect.Call(),
		asm.Mov.Reg(asm.R8, asm.R0), // preserve redirect result

		// Per-peer stats update: look up src_ip in the hash map.
		asm.LoadMapPtr(asm.R1, statsFD),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8), // &src_ip on stack
		asm.Mov.Imm(asm.R3, 0),  // flags
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "return_action"), // no entry → skip

		// Entry found: atomically increment bytes (offset +0) and packets (offset +8).
		asm.LoadMem(asm.R4, asm.R6, 0, asm.Word), // skb->len
		asm.Mov.Reg(asm.R1, asm.R4),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), // bytes += skb->len
		asm.Mov.Imm(asm.R1, 1),
		asm.Add.Imm(asm.R0, 8),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), // packets += 1
		asm.Ja.Label("return_action"),

		asm.Mov.Imm(asm.R8, 2).WithSymbol("drop"), // TC_ACT_SHOT
		asm.Mov.Imm(asm.R9, 8),                    // Dropped

		asm.Mov.Reg(asm.R0, asm.R8).WithSymbol("return_action"),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("pass"), // TC_ACT_OK, packet untouched
		asm.Return(),
	)
	return ins
}

func newTCProgramSpec(cfg tcRedirectConfig, statsFD int) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:         "yat_redirect",
		Type:         ebpf.SchedCLS,
		Instructions: buildTCProgram(cfg, statsFD),
		License:      "GPL",
	}
}
