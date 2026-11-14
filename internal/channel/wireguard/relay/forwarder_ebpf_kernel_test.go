//go:build linux && ebpf

package relay

import (
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"icool.io/yat/edge/internal/channel/wireguard/relay/counter"
)

func requireEBPFKernelTests(t *testing.T) {
	t.Helper()
	if os.Getenv("YAT_EBPF_KERNEL_TEST") != "1" {
		t.Skip("set YAT_EBPF_KERNEL_TEST=1 on Linux with BPF and network admin capabilities")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
}

// This loads the real program through the verifier and uses BPF_PROG_TEST_RUN.
// The redirect helper records an action; this API does not deliver the packet.
func TestTCProgramKernel(t *testing.T) {
	requireEBPFKernelTests(t)
	for _, tt := range tcPacketCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.packet) < 14 {
				t.Skip("BPF_PROG_TEST_RUN requires at least ETH_HLEN bytes")
			}
			m, err := ebpf.NewMap(counter.PeerStatsMapSpec())
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			prog, err := ebpf.NewProgram(newTCProgramSpec(tt.cfg, m.FD()))
			if err != nil {
				t.Fatalf("load program: %+v", err)
			}
			defer prog.Close()
			action, out, err := prog.Test(tt.packet)
			if err != nil {
				t.Fatal(err)
			}
			checkTCPacket(t, tt, action, out)
		})
	}
}

// Test attachment and cleanup in an isolated namespace; no host interface or
// filter is touched. An unrelated egress filter must survive Start and Stop.
func TestEBPFTCAttachment(t *testing.T) {
	requireEBPFKernelTests(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	defer func() {
		if err := netns.Set(original); err != nil {
			t.Fatalf("restore network namespace: %v", err)
		}
	}()

	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "yat-ebpf-test"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	if err := netlink.QdiscAdd(&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
	}}); err != nil {
		t.Fatal(err)
	}
	other, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Index, Parent: netlink.HANDLE_MIN_EGRESS, Handle: 1, Priority: 1, Protocol: 3},
		Fd:          other.FD(), DirectAction: true, Name: "unrelated",
	}
	if err := netlink.FilterAdd(filter); err != nil {
		t.Fatal(err)
	}
	f, err := NewEBPFForwarder(link.Name, "10.24.0.0/24", "10.24.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Stop()
	for i := 0; i < 2; i++ {
		if err := f.Start(); err != nil {
			t.Fatalf("start: %+v", err)
		}
	}
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil || len(filters) != 1 {
		t.Fatalf("ingress filters after start: %v, %v", filters, err)
	}
	for i := 0; i < 2; i++ {
		if err := f.Stop(); err != nil {
			t.Fatal(err)
		}
	}
	filters, err = netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil || len(filters) != 0 {
		t.Fatalf("ingress filters after stop: %v, %v", filters, err)
	}
	filters, err = netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil || len(filters) != 1 {
		t.Fatalf("unrelated egress filter removed: %v, %v", filters, err)
	}
}

func TestEBPFStopBeforeStart(t *testing.T) {
	f, err := NewEBPFForwarder("missing-interface", "10.24.0.0/24", "10.24.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := f.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}
