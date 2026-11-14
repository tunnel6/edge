package wireguard

import "testing"

func newJoinFixture() *MemberManager {
	nm := NewNetworkManager()
	mm := NewMemberManager(nm)
	nm.networks["net1"] = &Network{ID: "net1", CIDR: "10.0.0.0/24", Status: NetworkStatusActive}
	mm.allocatedIPs["net1"] = make(map[string]bool)
	return mm
}

// 代加成员先以 clientId 占位公钥加入，待其真正启动 WG 用真实公钥重入时应就地升级公钥、保持同一成员/IP。
func TestJoinNetworkUpgradesPlaceholderPublicKey(t *testing.T) {
	mm := newJoinFixture()
	const client = "device-abc"

	first, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "member-1", NetworkID: "net1", ClientID: client, PublicKey: client,
	})
	if err != nil {
		t.Fatalf("first join failed: %v", err)
	}
	if first.IP != "10.0.0.1" {
		t.Errorf("first member IP = %q, want 10.0.0.1", first.IP)
	}
	if first.PublicKey != client {
		t.Errorf("placeholder key = %q, want %q", first.PublicKey, client)
	}
	if memberIsOnline(first) {
		t.Errorf("placeholder member must not be online")
	}

	const realKey = "IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo="
	second, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "member-1", NetworkID: "net1", ClientID: client, PublicKey: realKey,
	})
	if err != nil {
		t.Fatalf("rejoin failed: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("rejoin produced new member %q, want %q", second.ID, first.ID)
	}
	if second.IP != first.IP {
		t.Errorf("IP changed on rejoin: %q -> %q", first.IP, second.IP)
	}
	if second.PublicKey != realKey {
		t.Errorf("public key not upgraded: got %q, want %q", second.PublicKey, realKey)
	}

	second.Status = MemberStatusOnline
	if !memberIsOnline(second) {
		t.Errorf("upgraded member with real key + Online status should count as online")
	}
}

func TestJoinNetworkRestoresExplicitlyReaddedSoftLeftMember(t *testing.T) {
	mm := newJoinFixture()
	const client = "device-soft-left"
	const realKey = "IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo="
	member, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "member-soft-left", NetworkID: "net1", ClientID: client, PublicKey: realKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mm.SetMemberOffline(member.ID); err != nil {
		t.Fatalf("soft leave failed: %v", err)
	}
	if member.Status != MemberStatusLeaved || !member.pathRevoked {
		t.Fatalf("after leave status/revoked = %v/%v", member.Status, member.pathRevoked)
	}

	rejoined, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: member.ID, NetworkID: "net1", ClientID: client, PublicKey: realKey,
	})
	if err != nil {
		t.Fatalf("explicit rejoin failed: %v", err)
	}
	if rejoined.ID != member.ID || rejoined.Status != MemberStatusActive || rejoined.pathRevoked {
		t.Fatalf("rejoin state = id:%s status:%v revoked:%v", rejoined.ID, rejoined.Status, rejoined.pathRevoked)
	}
}

func TestJoinNetworkHonorsRequestedAssignedIP(t *testing.T) {
	mm := newJoinFixture()

	member, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "relay-member", NetworkID: "net1", ClientID: "relay-member", PublicKey: "x8ABrq5+cQiOV7p2VzAC1HNCcsI2+GxOWbO5AjtF4Ao=", IsRelay: true, AssignedIP: "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("join with requested IP failed: %v", err)
	}
	if member.IP != "10.0.0.1" {
		t.Fatalf("member IP = %q, want 10.0.0.1", member.IP)
	}

	second, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "member-2", NetworkID: "net1", ClientID: "device-b", PublicKey: "DFvFfck9wEL9dReoUPLmgCJ6UysHHURIWy7zZ5GB4BQ=",
	})
	if err != nil {
		t.Fatalf("second join failed: %v", err)
	}
	if second.IP != "10.0.0.2" {
		t.Fatalf("second member IP = %q, want 10.0.0.2", second.IP)
	}
}

// 占位公钥(== clientId)的成员即便库内被持久化为 Online，也不应被读模型视为真实在线（自愈历史脏数据）。
func TestMemberIsOnlineIgnoresPlaceholderKey(t *testing.T) {
	m := &NetworkMember{ClientID: "device-x", PublicKey: "device-x", Status: MemberStatusOnline}
	if memberIsOnline(m) {
		t.Errorf("placeholder-key member must not count as online even when status=Online")
	}
	m.PublicKey = "cqYxh6qmQx77NptW1EdO0vVFlqZ9C/086ZPTz1Bccjc="
	if !memberIsOnline(m) {
		t.Errorf("real-key Online member should count as online")
	}
}

func TestTemporaryDisconnectPreservesMembershipAndPathEligibility(t *testing.T) {
	mm := newJoinFixture()
	member, err := mm.JoinNetwork(&JoinNetworkRequest{
		MemberID: "member-1", NetworkID: "net1", ClientID: "device-a",
		PublicKey: "IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo=",
	})
	if err != nil {
		t.Fatal(err)
	}
	member.Status = MemberStatusOnline

	if err := mm.SetMemberDisconnected(member.ID); err != nil {
		t.Fatalf("temporary disconnect failed: %v", err)
	}
	if member.Status != MemberStatusActive {
		t.Fatalf("temporary disconnect status = %v, want Active", member.Status)
	}
	if member.pathRevoked {
		t.Fatal("temporary disconnect revoked path coordination")
	}
	if _, err := pathMembership(member); err != nil {
		t.Fatalf("temporary disconnect revoked path membership: %v", err)
	}
	if got, err := mm.GetClientMember("device-a", "net1"); err != nil || got.ID != member.ID {
		t.Fatalf("temporary disconnect removed membership: member=%v err=%v", got, err)
	}

	if err := mm.SetMemberOffline(member.ID); err != nil {
		t.Fatalf("explicit leave failed: %v", err)
	}
	if member.Status != MemberStatusLeaved || !member.pathRevoked {
		t.Fatalf("explicit leave status/revocation = %v/%v, want Leaved/revoked", member.Status, member.pathRevoked)
	}
	if err := mm.SetMemberDisconnected(member.ID); err != nil {
		t.Fatalf("repeated temporary disconnect failed: %v", err)
	}
	if member.Status != MemberStatusLeaved || !member.pathRevoked {
		t.Fatal("temporary disconnect revived an explicit leave")
	}
}
