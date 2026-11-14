package wireguard

import (
	"errors"
	"sync"
	"testing"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
)

func newPathMembershipFixture(t *testing.T) (*MemberManager, pathcoord.PairKey) {
	t.Helper()
	nm := NewNetworkManager()
	_, err := nm.CreateNetwork(&CreateNetworkRequest{ID: "net", CIDR: "10.24.0.0/24", CoordinatorEdgeID: "edge", RelayMode: RelayModeOptional})
	if err != nil {
		t.Fatal(err)
	}
	mm := NewMemberManager(nm)
	for i, id := range []string{"a", "b"} {
		_, err := mm.JoinNetwork(&JoinNetworkRequest{MemberID: id, NetworkID: "net", ClientID: "device-" + id,
			PublicKey: []string{"IGYpnCCyZzdQinF1VI+lkNUVfkrXUe53ptWFS2izmSo=", "x8ABrq5+cQiOV7p2VzAC1HNCcsI2+GxOWbO5AjtF4Ao="}[i]})
		if err != nil {
			t.Fatal(err)
		}
	}
	return mm, pathcoord.PairKey{NetworkID: "net", MemberAID: "a", MemberBID: "b"}
}

func TestPathMembershipLifecycleDoesNotConfusePresenceWithRevocation(t *testing.T) {
	mm, pair := newPathMembershipFixture(t)
	before, err := mm.PathPair(pair)
	if err != nil {
		t.Fatal(err)
	}
	if before.Members[0].Generation == "" || before.Members[0].Generation == before.Members[1].Generation {
		t.Fatal("invalid generations")
	}
	if err := mm.SetMemberOnline("a"); err != nil {
		t.Fatal(err)
	}
	if err := mm.SetClientMembersDisconnected("device-a"); err != nil {
		t.Fatal(err)
	}
	if err := mm.UpdateMemberHostname("a", "renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.ApplyObservedEndpoint("net", before.Members[0].PublicKey, "198.51.100.1:58020"); err != nil {
		t.Fatal(err)
	}
	after, err := mm.PathPair(pair)
	if err != nil {
		t.Fatal(err)
	}
	if after.Members[0].Generation != before.Members[0].Generation || after.Members[0].ObservedEndpoint == "" {
		t.Fatal("presence/observer rotated membership")
	}
	if err := mm.SetMemberOffline("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.PathPair(pair); !errors.Is(err, pathcoord.ErrMembershipRevoked) {
		t.Fatal("leave did not revoke", err)
	}
	if err, _ := mm.SetMemberOnlineByPublicKey("net", before.Members[0].PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.PathMember("net", "device-a"); !errors.Is(err, pathcoord.ErrMembershipRevoked) {
		t.Fatal("observer resurrected coordination membership", err)
	}
	_, err = mm.JoinNetwork(&JoinNetworkRequest{NetworkID: "net", ClientID: "device-a", PublicKey: before.Members[0].PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	rejoined, err := mm.PathPair(pair)
	if err != nil || rejoined.Members[0].Generation == before.Members[0].Generation {
		t.Fatal("explicit rejoin did not renew", err)
	}
	if err := mm.RemoveMember("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.PathPair(pair); !errors.Is(err, pathcoord.ErrMembershipRevoked) {
		t.Fatal("removal not revoked", err)
	}
}

func TestPathMembershipExplicitRejoinDoesNotRequireObserverRecovery(t *testing.T) {
	mm, _ := newPathMembershipFixture(t)
	before, err := mm.PathMember("net", "device-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := mm.SetMemberOffline("a"); err != nil {
		t.Fatal(err)
	}
	join := &JoinNetworkRequest{NetworkID: "net", ClientID: "device-a", PublicKey: before.Member.PublicKey}
	if _, err := mm.JoinNetwork(join); err != nil {
		t.Fatal(err)
	}
	after, err := mm.PathMember("net", "device-a")
	if err != nil || after.Member.Generation == before.Member.Generation {
		t.Fatal("rejoin waited for observer", err)
	}
	if _, err := mm.JoinNetwork(join); err != nil {
		t.Fatal(err)
	}
	again, err := mm.PathMember("net", "device-a")
	if err != nil || again.Member.Generation != after.Member.Generation {
		t.Fatal("idempotent rejoin rotated membership", err)
	}
}

func TestPathMembershipPolicyAndIdentityInvalidation(t *testing.T) {
	mm, pair := newPathMembershipFixture(t)
	before, _ := mm.PathPair(pair)
	if err := mm.UpdateMemberIP("a", "10.24.0.9"); err != nil {
		t.Fatal(err)
	}
	changed, _ := mm.PathPair(pair)
	if changed.Members[0].Generation == before.Members[0].Generation || changed.Members[0].AssignedIP != "10.24.0.9" {
		t.Fatal("IP did not invalidate identity")
	}
	if err := mm.UpdateMemberIP("a", "10.24.0.9"); err != nil {
		t.Fatal(err)
	}
	unchanged, _ := mm.PathPair(pair)
	if unchanged.Members[0].Generation != changed.Members[0].Generation {
		t.Fatal("idempotent IP rotated identity")
	}
	if err := mm.networkManager.UpdateRelayMode("net", RelayModeDisabled); err != nil {
		t.Fatal(err)
	}
	policy, _ := mm.PathPair(pair)
	if policy.Network.PolicyRevision <= before.Network.PolicyRevision || policy.Network.RelayMode != fb.WGRelayModeDISABLED {
		t.Fatal("policy not invalidated")
	}
	if err := mm.RemapNetworkCIDR("net", "10.25.0.0/24"); err != nil {
		t.Fatal(err)
	}
	remapped, _ := mm.PathPair(pair)
	if remapped.Network.PolicyRevision <= policy.Network.PolicyRevision || remapped.Members[0].Generation == policy.Members[0].Generation ||
		remapped.Members[1].Generation == policy.Members[1].Generation {
		t.Fatal("CIDR remap did not invalidate scope")
	}
	_, err := mm.JoinNetwork(&JoinNetworkRequest{NetworkID: "net", ClientID: "device-a", PublicKey: before.Members[1].PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, _ := mm.PathPair(pair)
	if rekeyed.Members[0].Generation == remapped.Members[0].Generation {
		t.Fatal("key upgrade did not invalidate identity")
	}
}

func TestPathMembershipSnapshotsConcurrentWithUpdates(t *testing.T) {
	mm, pair := newPathMembershipFixture(t)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 50; j++ {
				b, err := mm.PathPair(pair)
				if err != nil {
					t.Error(err)
					return
				}
				b.Members[0].PublicKey = "local mutation"
				if _, err := mm.PathMember("net", "device-a"); err != nil {
					t.Error(err)
				}
				if err := mm.UpdateMemberHostname("a", "name"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	workers.Wait()
	after, _ := mm.PathPair(pair)
	if after.Members[0].PublicKey == "local mutation" {
		t.Fatal("snapshot aliases member")
	}
	// Persisted endpoint with no accepted fresh observation must not become a candidate.
	mm.mu.Lock()
	mm.members["a"].Endpoint, mm.members["a"].ObservedAt = "198.51.100.1:58020", time.Time{}
	mm.mu.Unlock()
	after, _ = mm.PathPair(pair)
	if after.Members[0].ObservedEndpoint != "" {
		t.Fatal("historical endpoint treated as fresh")
	}
}

func TestPathObservedMemberKeepsGenerationStartAcrossPresence(t *testing.T) {
	mm, _ := newPathMembershipFixture(t)
	original, err := mm.PathMember("net", "device-a")
	if err != nil {
		t.Fatal(err)
	}
	before, err := mm.PathObservedMember("net", original.Member.PublicKey)
	if err != nil || before.Member.GenerationStartedAt.IsZero() {
		t.Fatal("missing local generation clock", err)
	}
	if _, err := mm.ApplyObservedEndpoint("net", original.Member.PublicKey, "198.51.100.1:51820"); err != nil {
		t.Fatal(err)
	}
	after, err := mm.PathObservedMember("net", original.Member.PublicKey)
	if err != nil || after.Member.GenerationStartedAt != before.Member.GenerationStartedAt {
		t.Fatal("observation rotated generation clock", err)
	}
	if err := mm.UpdateMemberIP("a", "10.24.0.20"); err != nil {
		t.Fatal(err)
	}
	after, err = mm.PathObservedMember("net", original.Member.PublicKey)
	if err != nil || after.Member.Generation == before.Member.Generation || after.Member.GenerationStartedAt.Before(before.Member.GenerationStartedAt) {
		t.Fatal("identity update did not renew clock", err)
	}
	if err := mm.SetMemberOffline("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := mm.PathObservedMember("net", original.Member.PublicKey); !errors.Is(err, pathcoord.ErrMembershipRevoked) {
		t.Fatal("revoked member exposed observation identity", err)
	}
}
