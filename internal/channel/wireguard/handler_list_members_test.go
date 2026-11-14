package wireguard

import (
	"testing"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

func TestSelectListedMembersReturnsAllNonRemovedMembersWhenOnlineOnlyFalse(t *testing.T) {
	members := []*NetworkMember{
		{ID: "pending", ClientID: "device-p", PublicKey: "device-p", Status: MemberStatusPending},
		{ID: "active", ClientID: "device-a", PublicKey: "2i5f2t366s/S9CQfAj+oemY3DhaspTjZJ+mroH8FzXY=", Status: MemberStatusActive},
		{ID: "online", ClientID: "device-o", PublicKey: "K8tkgPtESWVBW5iQMqFmEagHt2Kd8+BrzYiaU2q9ZgY=", Status: MemberStatusOnline, LastOnline: time.Unix(100, 0)},
		{ID: "placeholder-online", ClientID: "device-x", PublicKey: "device-x", Status: MemberStatusOnline},
		{ID: "removed", ClientID: "device-r", PublicKey: "13/qccICuNbKW5+XWHRf1BMtQuwJGmAeflj4uA5WO1I=", Status: MemberStatusRemoved},
	}

	selected := selectListedMembers(members, false)
	if len(selected) != 4 {
		t.Fatalf("selected member count = %d, want 4", len(selected))
	}
	if got := mapMemberStatusToFB(selected[0]); got != fbMsg.WGMemberStatusPENDING {
		t.Fatalf("pending member status = %v, want PENDING", got)
	}
	if got := mapMemberStatusToFB(selected[1]); got != fbMsg.WGMemberStatusACTIVE {
		t.Fatalf("active member status = %v, want ACTIVE", got)
	}
	if got := mapMemberStatusToFB(selected[2]); got != fbMsg.WGMemberStatusONLINE {
		t.Fatalf("online member status = %v, want ONLINE", got)
	}
	if got := mapMemberStatusToFB(selected[3]); got != fbMsg.WGMemberStatusACTIVE {
		t.Fatalf("placeholder online status = %v, want ACTIVE after self-healing", got)
	}
}

func TestSelectListedMembersFiltersToRealOnlineMembers(t *testing.T) {
	members := []*NetworkMember{
		{ID: "online", ClientID: "device-o", PublicKey: "IaFvd+1HuJhHT8AWppxjN+DkLH+T5HSYY2Ngt2wzcGI=", Status: MemberStatusOnline},
		{ID: "placeholder-online", ClientID: "device-x", PublicKey: "device-x", Status: MemberStatusOnline},
		{ID: "active", ClientID: "device-a", PublicKey: "hRZSqFRjrlpCybM/XNv4l6bU/8Mz184gDeGZ1gqTPkg=", Status: MemberStatusActive},
	}

	selected := selectListedMembers(members, true)
	if len(selected) != 1 {
		t.Fatalf("selected member count = %d, want 1", len(selected))
	}
	if got := selected[0].ID; got != "online" {
		t.Fatalf("selected member id = %q, want online", got)
	}
}
