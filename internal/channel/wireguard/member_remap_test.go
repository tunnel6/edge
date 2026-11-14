package wireguard

import "testing"

// 构造一个带有若干活跃成员的网络管理器，便于直接驱动 RemapNetworkCIDR。
func newRemapFixture(cidr string, memberIPs map[string]string) (*NetworkManager, *MemberManager) {
	nm := NewNetworkManager()
	mm := NewMemberManager(nm)
	nm.networks["net1"] = &Network{ID: "net1", CIDR: cidr, Status: NetworkStatusActive}
	mm.allocatedIPs["net1"] = make(map[string]bool)
	for id, ip := range memberIPs {
		mm.members[id] = &NetworkMember{ID: id, NetworkID: "net1", IP: ip, Status: MemberStatusActive}
		mm.networkMembers["net1"] = append(mm.networkMembers["net1"], id)
		mm.allocatedIPs["net1"][ip] = true
	}
	return nm, mm
}

func TestRemapNetworkCIDRPreservesHostBits(t *testing.T) {
	nm, mm := newRemapFixture("10.0.0.0/24", map[string]string{
		"m1": "10.0.0.10",
		"m2": "10.0.0.11",
	})

	if err := mm.RemapNetworkCIDR("net1", "192.168.1.0/24"); err != nil {
		t.Fatalf("RemapNetworkCIDR failed: %v", err)
	}

	if got := nm.networks["net1"].CIDR; got != "192.168.1.0/24" {
		t.Errorf("network CIDR = %q, want 192.168.1.0/24", got)
	}
	if got := mm.members["m1"].IP; got != "192.168.1.10" {
		t.Errorf("m1 IP = %q, want 192.168.1.10", got)
	}
	if got := mm.members["m2"].IP; got != "192.168.1.11" {
		t.Errorf("m2 IP = %q, want 192.168.1.11", got)
	}

	// 旧地址应已释放、新地址应已登记。
	alloc := mm.allocatedIPs["net1"]
	if alloc["10.0.0.10"] || alloc["10.0.0.11"] {
		t.Errorf("old IPs still allocated: %v", alloc)
	}
	if !alloc["192.168.1.10"] || !alloc["192.168.1.11"] {
		t.Errorf("new IPs not allocated: %v", alloc)
	}
}

// 当主机位映射后落在网络地址/广播地址或与他人冲突时，应回退到下一个可用地址。
func TestRemapNetworkCIDRFallsBackOnReserved(t *testing.T) {
	// 旧 IP .0 的主机位映射到新网段的网络地址，必须回退。
	_, mm := newRemapFixture("10.0.0.0/24", map[string]string{
		"m1": "10.0.0.0",
		"m2": "10.0.0.1",
	})
	if err := mm.RemapNetworkCIDR("net1", "192.168.5.0/24"); err != nil {
		t.Fatalf("RemapNetworkCIDR failed: %v", err)
	}
	if got := mm.members["m1"].IP; got == "192.168.5.0" {
		t.Errorf("m1 IP = %q, must not be the network address", got)
	}
	if mm.members["m1"].IP == mm.members["m2"].IP {
		t.Errorf("members collided on %q", mm.members["m1"].IP)
	}
}

func TestRemapNetworkCIDRRejectsTooSmall(t *testing.T) {
	nm, mm := newRemapFixture("10.0.0.0/24", map[string]string{
		"m1": "10.0.0.10",
		"m2": "10.0.0.11",
	})
	// /31 在 ones<bits 规则下网络/广播均被排除，无可用主机地址。
	if err := mm.RemapNetworkCIDR("net1", "192.168.9.0/31"); err == nil {
		t.Fatal("expected error for too-small CIDR, got nil")
	}
	// 失败后不得有任何写入：网络子网与成员 IP 保持不变。
	if got := nm.networks["net1"].CIDR; got != "10.0.0.0/24" {
		t.Errorf("network CIDR mutated on failure: %q", got)
	}
	if mm.members["m1"].IP != "10.0.0.10" || mm.members["m2"].IP != "10.0.0.11" {
		t.Errorf("member IPs mutated on failure: m1=%q m2=%q", mm.members["m1"].IP, mm.members["m2"].IP)
	}
}
