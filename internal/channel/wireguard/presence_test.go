package wireguard

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

type presenceSessions struct {
	current map[string]types.SessionIdentity
}

func (s *presenceSessions) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	identity, ok := s.current[device]
	return identity, ok
}
func (*presenceSessions) PushToClient(string, []byte) error   { return nil }
func (*presenceSessions) AsyncPushToClients([]string, []byte) {}

func TestControlPresenceDoesNotDependOnRelayHandshakeOrGrantMembership(t *testing.T) {
	key := "2i5f2t366s/S9CQfAj+oemY3DhaspTjZJ+mroH8FzXY="
	for _, tc := range []struct {
		name                 string
		status               MemberStatus
		connected            bool
		claims               []string
		placeholder, revoked bool
		want                 MemberStatus
	}{
		{"registered_control_online", MemberStatusActive, true, nil, false, false, MemberStatusOnline},
		{"relay_stale_control_online", MemberStatusActive, true, []string{"network:net"}, false, false, MemberStatusOnline},
		{"relay_live_control_offline", MemberStatusOnline, false, nil, false, false, MemberStatusActive},
		{"wrong_network_scope", MemberStatusOnline, true, []string{"network:other"}, false, false, MemberStatusActive},
		{"placeholder", MemberStatusOnline, true, nil, true, false, MemberStatusActive},
		{"revoked", MemberStatusOnline, true, nil, false, true, MemberStatusActive},
		{"joining", MemberStatusPending, true, nil, false, false, MemberStatusPending},
		{"explicit_leave", MemberStatusLeaved, true, nil, false, true, MemberStatusLeaved},
		{"removed", MemberStatusRemoved, true, nil, false, true, MemberStatusRemoved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			member := &NetworkMember{ID: "member", NetworkID: "net", ClientID: "device", PublicKey: key,
				Status: tc.status, pathRevoked: tc.revoked, Endpoint: "198.51.100.2:6609",
				LANEndpointCandidates: []string{"172.17.1.200:58020"}}
			if tc.placeholder {
				member.PublicKey = member.ClientID
			}
			sessions := &presenceSessions{current: map[string]types.SessionIdentity{}}
			if tc.connected {
				sessions.current["device"] = types.SessionIdentity{DeviceID: "device", SessionID: "current", ScopeClaims: tc.claims}
			}
			projected := MembersWithControlPresence([]*NetworkMember{member}, sessions)[0]
			if projected.Status != tc.want {
				t.Fatalf("projected status=%v, want %v", projected.Status, tc.want)
			}
			if member.Status != tc.status {
				t.Fatal("read model modified observer state")
			}
			if projected.Endpoint != member.Endpoint {
				t.Fatal("presence changed endpoint selection")
			}
			projected.LANEndpointCandidates[0] = "changed"
			if member.LANEndpointCandidates[0] != "172.17.1.200:58020" {
				t.Fatal("read model aliases source candidates")
			}
		})
	}
}

type presenceCoordinator struct {
	HandlerCoordinator
	overview *NetworkOverview
}

func (c *presenceCoordinator) GetNetworkOverview(string) (*NetworkOverview, error) {
	return c.overview, nil
}

func TestRuntimePresenceFollowsCurrentControlWithoutRewritingRegistration(t *testing.T) {
	member := &NetworkMember{ID: "member", ClientID: "device", NetworkID: "net", Status: MemberStatusActive,
		PublicKey: "2i5f2t366s/S9CQfAj+oemY3DhaspTjZJ+mroH8FzXY="}
	coordinator := &presenceCoordinator{overview: &NetworkOverview{
		Network: &Network{ID: "net", RelayMode: RelayModeOptional, CIDR: "10.24.0.0/24"}, Members: []*NetworkMember{member},
	}}
	sessions := &presenceSessions{current: map[string]types.SessionIdentity{
		"device": {DeviceID: "device", SessionID: "new-session"},
	}}
	h := NewWireGuardHandler(coordinator, sessions, nil, "edge", nil)
	for _, online := range []bool{true, false, true} {
		if online {
			sessions.current["device"] = types.SessionIdentity{DeviceID: "device", SessionID: "current-session"}
		} else {
			delete(sessions.current, "device")
		}
		overview, err := h.getNetworkOverview("net")
		if err != nil {
			t.Fatal(err)
		}
		builder := flatbuffers.NewBuilder(1024)
		builder.Finish(buildWGNetworkRuntimeSnapshotOffset(builder, overview, "", ""))
		snapshot := fb.GetRootAsWGNetworkRuntimeSnapshotInfo(builder.FinishedBytes(), 0)
		var peer fb.WGNetworkMemberInfo
		if !snapshot.Members(&peer, 0) {
			t.Fatal("missing peer")
		}
		want := fb.WGMemberPresenceStatusOFFLINE
		if online {
			want = fb.WGMemberPresenceStatusONLINE
		}
		if peer.PresenceStatus() != want {
			t.Fatalf("wire presence=%v, want %v", peer.PresenceStatus(), want)
		}
		if peer.MembershipStatus() != fb.WGMemberMembershipStatusACTIVE {
			t.Fatal("presence changed membership")
		}
		if member.Status != MemberStatusActive {
			t.Fatal("read rewrote registered state")
		}
	}
}
