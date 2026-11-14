package wireguard

import (
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
)

func TestCurrentMemberForDeviceExcludesPlaceholderAndLeavedMembership(t *testing.T) {
	members := []*NetworkMember{
		{ID: "placeholder", ClientID: "device-a", PublicKey: "device-a", Status: MemberStatusActive},
		{ID: "leaved", ClientID: "device-a", PublicKey: "IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo=", Status: MemberStatusLeaved},
	}
	if got := currentMemberForDevice(members, "device-a"); got != nil {
		t.Fatalf("current member for placeholder/left device = %q, want nil", got.ID)
	}

	registered := &NetworkMember{
		ID: "registered", ClientID: "device-a", PublicKey: "IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo=",
		Status: MemberStatusActive, CreatedAt: time.Now(),
	}
	if got := currentMemberForDevice([]*NetworkMember{registered}, "device-a"); got != registered {
		t.Fatalf("registered member was not recognized as joined")
	}
}

func TestRuntimeSnapshotPolicyRevisionIsPublicWithoutRecipientBootstrap(t *testing.T) {
	for _, epoch := range []string{"", "authority"} {
		t.Run("epoch="+epoch, func(t *testing.T) {
			overview := &NetworkOverview{
				Network:            &Network{ID: "net", CIDR: "10.24.0.0/24", pathPolicyRevision: 7},
				PathAuthorityEpoch: epoch,
				// Pair projections must remain gated by recipient bootstrap.
				PathPairs: []*fb.WGPathPairRuntimeInfoT{{}},
			}
			builder := flatbuffers.NewBuilder(1024)
			offset := buildWGNetworkRuntimeSnapshotOffset(builder, overview, "", "")
			builder.Finish(offset)
			snapshot := fb.GetRootAsWGNetworkRuntimeSnapshotInfo(builder.FinishedBytes(), 0)
			if snapshot.NetworkPolicyRevision() != 7 {
				t.Fatalf("wire policy revision = %d, want 7; a public progress push must not revoke the client executor", snapshot.NetworkPolicyRevision())
			}
			if string(snapshot.PathAuthorityEpoch()) != epoch {
				t.Fatal("unexpected authority epoch")
			}
			wantPairs := 0
			if epoch != "" {
				wantPairs = 1
			}
			if snapshot.PathPairsLength() != wantPairs {
				t.Fatal("pair projection escaped its bootstrap gate")
			}
		})
	}
}

func TestResolveObservedEndpointForSnapshotFallsBackToRelayNode(t *testing.T) {
	network := &Network{RelayMode: RelayModeOptional}
	member := &NetworkMember{
		ID:       "relay-member",
		ClientID: "relay-member",
		IsRelay:  true,
	}
	relayNode := &relay.RelayNodeInfo{
		MemberID:  "relay-member",
		Endpoint:  "203.0.113.10:51820",
		PublicKey: "relay-public-key",
	}

	got := resolveObservedEndpointForSnapshot(network, member, relayNode)
	if got != "203.0.113.10:51820" {
		t.Fatalf("observed endpoint = %q, want relay node endpoint", got)
	}
}

func TestResolveObservedEndpointForSnapshotPrefersMemberEndpoint(t *testing.T) {
	network := &Network{RelayMode: RelayModeOptional}
	member := &NetworkMember{
		ID:       "relay-member",
		ClientID: "relay-member",
		IsRelay:  true,
		Endpoint: "198.51.100.7:51820",
	}
	relayNode := &relay.RelayNodeInfo{
		Endpoint: "203.0.113.10:51820",
	}

	got := resolveObservedEndpointForSnapshot(network, member, relayNode)
	if got != "198.51.100.7:51820" {
		t.Fatalf("observed endpoint = %q, want member endpoint", got)
	}
}

func TestResolveObservedEndpointForSnapshotForceModeKeepsObservedMemberEndpoint(t *testing.T) {
	network := &Network{RelayMode: RelayModeForce}
	member := &NetworkMember{
		ID:       "member-a",
		ClientID: "member-a",
		Endpoint: "198.51.100.7:51820",
	}
	relayNode := &relay.RelayNodeInfo{
		Endpoint: "203.0.113.10:51820",
	}

	got := resolveObservedEndpointForSnapshot(network, member, relayNode)
	if got != "198.51.100.7:51820" {
		t.Fatalf("observed endpoint = %q, want member observed endpoint in force mode", got)
	}
}

func TestResolveObservedEndpointForSnapshotForceModeWithoutRelayNodeKeepsObservedMemberEndpoint(t *testing.T) {
	network := &Network{RelayMode: RelayModeForce}
	member := &NetworkMember{
		ID:       "member-a",
		ClientID: "member-a",
		Endpoint: "198.51.100.7:51820",
	}

	got := resolveObservedEndpointForSnapshot(network, member, nil)
	if got != "198.51.100.7:51820" {
		t.Fatalf("observed endpoint = %q, want member observed endpoint when relay node is missing", got)
	}
}
