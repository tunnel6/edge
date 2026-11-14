//go:build ebpf

package relay

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/asm"
)

// runTCBytecode executes the assembled instructions on both host byte orders.
// Only the instruction subset used here is supported; helpers are mocked. This
// tests packet transformations and register lifetimes without claiming to test
// the kernel verifier, skb metadata, or actual redirect delivery.
func runTCBytecode(t *testing.T, cfg tcRedirectConfig, packet []byte, order binary.ByteOrder, helperResult uint64, mapMiss bool) (uint32, []byte, ForwarderStats) {
	t.Helper()
	var code bytes.Buffer
	insns := buildTCProgram(cfg, 42)
	// cilium rejects Linux helper IDs when marshaling on macOS. Temporarily
	// encode those calls as same-size immediates and restore the call opcode
	// after branch resolution. Linux tests marshal the unmodified program.
	var helperOffsets []int
	if runtime.GOOS != "linux" {
		offset := 0
		for i, ins := range insns {
			if ins.IsBuiltinCall() {
				helperOffsets = append(helperOffsets, offset)
				insns[i] = asm.Mov.Imm(asm.R0, int32(ins.Constant))
			}
			offset += int(ins.Size())
		}
	}
	if err := insns.Marshal(&code, order); err != nil {
		t.Fatal(err)
	}
	for _, offset := range helperOffsets {
		code.Bytes()[offset] = byte(asm.FnRedirect.Call().OpCode)
	}
	const ctx, data, counters, stack = 0x100, 0x1000, 0x12000, 0x13000
	mem := make([]byte, stack)
	copy(mem[data:], packet)
	order.PutUint32(mem[ctx:], uint32(len(packet)))
	order.PutUint32(mem[ctx+76:], data)
	order.PutUint32(mem[ctx+80:], uint32(data+len(packet)))
	reg := [11]uint64{1: ctx, 10: uint64(stack)}
	access := func(addr uint64, size int) []byte {
		end := addr + uint64(size)
		if !(addr >= ctx && end <= ctx+84 || addr >= data && end <= uint64(data+len(packet)) ||
			addr >= counters && end <= counters+24 || addr >= stack-uint64(stack) && end <= stack)
			t.Fatalf("out-of-bounds BPF access: address=%#x size=%d", addr, size)
		}
		return mem[addr:end]
	}
	read := func(addr uint64, size int) uint64 {
		p := access(addr, size)
		switch size {
		case 1:
			return uint64(p[0])
		case 2:
			return uint64(order.Uint16(p))
		case 4:
			return uint64(order.Uint32(p))
		default:
			return order.Uint64(p)
		}
	}
	write := func(addr uint64, size int, value uint64) {
		p := access(addr, size)
		switch size {
		case 1:
			p[0] = byte(value)
		case 2:
			order.PutUint16(p, uint16(value))
		case 4:
			order.PutUint32(p, uint32(value))
		default:
			order.PutUint64(p, value)
		}
	}
	for pc, steps := 0, 0; steps < 1000 && pc < code.Len(); steps++ {
		var ins asm.Instruction
		if err := ins.Unmarshal(bytes.NewReader(code.Bytes()[pc:]), order, "linux"); err != nil {
			t.Fatal(err)
		}
		pc += int(ins.Size())
		op := ins.OpCode
		dst, src := ins.Dst, ins.Src
		value := uint64(ins.Constant)
		if op.Source() == asm.RegSource {
			value = reg[src]
		}
		switch op.Class() {
		case asm.LdClass:
			if !ins.IsLoadFromMap() {
				t.Fatalf("unsupported load: %v", ins)
			}
			reg[dst] = uint64(ins.Constant)
		case asm.LdXClass:
			reg[dst] = read(reg[src]+uint64(ins.Offset), op.Size().Sizeof())
		case asm.StClass:
			write(reg[dst]+uint64(ins.Offset), op.Size().Sizeof(), uint64(ins.Constant))
		case asm.StXClass:
			addr := reg[dst] + uint64(ins.Offset)
			value = reg[src]
			if op == asm.StoreXAddOp(op.Size()) {
				value += read(addr, op.Size().Sizeof())
			}
			write(addr, op.Size().Sizeof(), value)
		case asm.ALUClass, asm.ALU64Class:
			switch op.ALUOp() {
			case asm.Mov:
				reg[dst] = value
			case asm.Add:
				reg[dst] += value
			case asm.Sub:
				reg[dst] -= value
			case asm.And:
				reg[dst] &= value
			case asm.RSh:
				reg[dst] >>= value
			case asm.Swap:
				if (op.Endianness() == asm.BE) == (order == binary.LittleEndian) {
					switch ins.Constant {
					case 16:
						reg[dst] = uint64(bits.ReverseBytes16(uint16(reg[dst])))
					case 32:
						reg[dst] = uint64(bits.ReverseBytes32(uint32(reg[dst])))
					default:
						t.Fatalf("unsupported swap: %v", ins)
					}
				}
			default:
				t.Fatalf("unsupported ALU instruction: %v", ins)
			}
			if op.Class() == asm.ALUClass {
				reg[dst] = uint64(uint32(reg[dst]))
			}
		case asm.JumpClass, asm.Jump32Class:
			lhs := reg[dst]
			if op.Class() == asm.Jump32Class {
				lhs, value = uint64(uint32(lhs)), uint64(uint32(value))
			}
			jump := false
			switch op.JumpOp() {
			case asm.Exit:
				// New BPF program writes packets at map_value+8 = stack-16.
				return uint32(reg[0]), bytes.Clone(mem[data : data+len(packet)]), ForwarderStats{
					Forwarded: read(stack-16, 8),
				}
			case asm.Call:
				switch asm.BuiltinFunc(ins.Constant) {
				case asm.FnRedirect:
					if reg[1] != uint64(cfg.IfIndex) || reg[2] != 0 {
						t.Fatalf("redirect target/flags = %d/%d, want %d/0", reg[1], reg[2], cfg.IfIndex)
					}
					reg[0] = helperResult
				case asm.FnMapLookupElem:
					if reg[1] != 42 {
						t.Fatal("incorrect stats map")
					}
					// New BPF program passes &src_ip on stack as key.
					key := uint32(read(reg[2], 4))
					expectedSrcIP := binary.BigEndian.Uint32(mem[data+12 : data+16])
					if key != expectedSrcIP {
						t.Fatalf("stats map key = %#x, want src_ip %#x", key, expectedSrcIP)
					}
					reg[0] = counters
					if mapMiss {
						reg[0] = 0
					}
				default:
					t.Fatalf("unexpected helper: %v", ins)
				}
				for i := 1; i <= 5; i++ {
					reg[i] = 0xdeadbeef // helpers clobber caller-saved registers
				}
			case asm.Ja:
				jump = true
			case asm.JEq:
				jump = lhs == value
			case asm.JNE:
				jump = lhs != value
			case asm.JGT:
				jump = lhs > value
			case asm.JGE:
				jump = lhs >= value
			case asm.JLT:
				jump = lhs < value
			case asm.JLE:
				jump = lhs <= value
			default:
				t.Fatalf("unsupported jump: %v", ins)
			}
			if jump {
				pc += int(ins.Offset) * 8
			}
		default:
			t.Fatalf("unsupported instruction: %v", ins)
		}
	}
	t.Fatal("BPF program did not return")
	return 0, nil, ForwarderStats{}
}
