package wireguard

import (
	"reflect"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/channel/wireguard/pathcoord"
)

type pathProgressCoordinator struct{ pathReceiptCoordinator }

func (*pathProgressCoordinator) GetNetworkOverview(network string) (*NetworkOverview, error) {
	return &NetworkOverview{
		Network: &Network{ID: network, OwnerUserID: "user", CIDR: "10.24.0.0/24"},
		Members: []*NetworkMember{
			{ID: "a", ClientID: "device-a", Status: MemberStatusOnline},
			{ID: "b", ClientID: "device-b", Status: MemberStatusActive},
			{ID: "c", ClientID: "device-c", Status: MemberStatusOnline},
			{ID: "offline", ClientID: "device-offline", Status: MemberStatusLeaved},
			{ID: "disconnected", ClientID: "device-disconnected", Status: MemberStatusOnline},
		},
	}, nil
}

type pathProgressPusher struct {
	targets  []string
	data     []byte
	payloads [][]byte
	calls    int
}

func (p *pathProgressPusher) PushToClient(_ string, data []byte) error {
	p.data = append([]byte(nil), data...)
	p.payloads = append(p.payloads, append([]byte(nil), data...))
	p.calls++
	return nil
}
func (*pathProgressPusher) HasClientSession(client string) bool {
	return client != "device-disconnected"
}
func (p *pathProgressPusher) AsyncPushToClients(targets []string, data []byte) {
	p.targets = append([]string(nil), targets...)
	p.data = append([]byte(nil), data...)
	p.payloads = append(p.payloads, append([]byte(nil), data...))
	p.calls++
}

type pathProgressReceiver struct {
	before, after []*fb.WGPathPairRuntimeInfoT
	handled       bool
}

func (r *pathProgressReceiver) HandlePathControl(types.SessionIdentity, pathcoord.ControlMessage) error {
	r.handled = true
	return nil
}
func (r *pathProgressReceiver) RuntimePairs(string, types.SessionIdentity, time.Time) ([]*fb.WGPathPairRuntimeInfoT, error) {
	if r.handled {
		return r.after, nil
	}
	return r.before, nil
}

func TestPathBarrierPushOnlyInvalidatesChangedPairParticipants(t *testing.T) {
	pair := func(peer string, phase fb.WGPathPhase, report fb.WGPathReportKind) *fb.WGPathPairRuntimeInfoT {
		return &fb.WGPathPairRuntimeInfoT{
			Plan: &fb.WGPathPlanT{Version: &fb.WGPathVersionT{
				NetworkId: "net", MemberAId: "a", MemberBId: peer, PairRevision: 1,
			}, Phase: phase},
			ReportA: &fb.WGPathReportT{Kind: report},
		}
	}
	waiting := pair("b", fb.WGPathPhaseWAITING_READY, fb.WGPathReportKindUNKNOWN)
	ready := pair("b", fb.WGPathPhaseWAITING_READY, fb.WGPathReportKindREADY)
	commit := pair("b", fb.WGPathPhaseAPPLY, fb.WGPathReportKindUNKNOWN)
	applied := pair("b", fb.WGPathPhaseAPPLY, fb.WGPathReportKindAPPLIED)
	confirmed := pair("b", fb.WGPathPhaseCONFIRMED, fb.WGPathReportKindAPPLIED)
	other := pair("c", fb.WGPathPhaseCONFIRMED, fb.WGPathReportKindAPPLIED)
	for _, tc := range []struct {
		name          string
		before, after *fb.WGPathPairRuntimeInfoT
		request       bool
		changed       bool
	}{
		{"proposal", nil, waiting, true, true},
		{"first_ready", waiting, ready, false, true},
		{"commit", ready, commit, false, true},
		{"first_applied", commit, applied, false, true},
		{"confirmed", applied, confirmed, false, true},
		{"duplicate_ready", ready, ready, false, false},
		{"duplicate_applied", applied, applied, false, false},
		{"pair_removed", confirmed, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receiver := &pathProgressReceiver{before: []*fb.WGPathPairRuntimeInfoT{other}, after: []*fb.WGPathPairRuntimeInfoT{other}}
			if tc.before != nil {
				receiver.before = append(receiver.before, tc.before)
			}
			if tc.after != nil {
				// Pair order is not a change and must never wake c.
				receiver.after = append([]*fb.WGPathPairRuntimeInfoT{tc.after}, receiver.after...)
			}
			pusher := &pathProgressPusher{}
			h := NewWireGuardHandler(&pathProgressCoordinator{}, pusher, nil, "edge", nil)
			if err := h.AttachPathControlReceiver(receiver); err != nil {
				t.Fatal(err)
			}
			msg := &fb.MessageT{
				Header: &fb.MessageHeaderT{Type: fb.MessageTypeWG_PATH_REPORT},
				Body: &fb.MessageBodyT{Type: fb.MessageBodyWGPathReport, Value: &fb.WGPathReportT{
					Version: waiting.Plan.Version, MemberId: "a", Kind: fb.WGPathReportKindREADY,
				}},
			}
			if tc.request {
				msg.Header.Type = fb.MessageTypeWG_PATH_REQUEST
				msg.Header.Seq = 42
				msg.Body = &fb.MessageBodyT{Type: fb.MessageBodyWGPathRequest, Value: &fb.WGPathRequestT{
					NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE,
					RequestedPath: fb.WGPathTypeRELAY, RequestId: "click", ObservedAuthorityEpoch: "epoch",
				}}
			}
			builder := flatbuffers.NewBuilder(512)
			builder.Finish(msg.Pack(builder))
			conn := &pathReceiptConn{}
			if err := h.HandlePathControl(HandlerSession{Conn: conn, UserID: "user", DeviceID: "device-a", SessionID: "session-a"}, fb.GetRootAsMessage(builder.FinishedBytes(), 0)); err != nil {
				t.Fatal(err)
			}
			if tc.changed {
				if pusher.calls != 1 || !reflect.DeepEqual(pusher.targets, []string{"device-a", "device-b"}) {
					t.Fatalf("pair push calls=%d targets=%v", pusher.calls, pusher.targets)
				}
				push := fb.GetRootAsMessage(pusher.data, 0)
				var body flatbuffers.Table
				if !push.Body(&body) {
					t.Fatal("missing push body")
				}
				var event fb.WGNetworkEventPush
				event.Init(body.Bytes, body.Pos)
				if string(event.NetworkId()) != "net" || event.Action() != fb.WGNetworkEventActionRUNTIME_UPDATE {
					t.Fatal("pair progress must remain a runtime invalidation event")
				}
			} else if pusher.calls != 0 {
				t.Fatal("duplicate reports must not cause refreshes")
			}
			// Ordinary topology/endpoint changes still reach every connected,
			// eligible member, independently of the pair filter.
			if err := h.PushNetworkEvent("net", fb.WGNetworkEventActionUPSERT); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pusher.targets, []string{"device-a", "device-b", "device-c"}) {
				t.Fatalf("topology push targets=%v", pusher.targets)
			}
		})
	}
}

func TestNetworkPushUsesOneMonotonicVersionForEventAndSnapshot(t *testing.T) {
	pusher := &pathProgressPusher{}
	h := NewWireGuardHandler(&pathProgressCoordinator{}, pusher, nil, "edge", nil)
	initial, err := h.getVersionedNetworkOverview("net")
	if err != nil {
		t.Fatal(err)
	}
	if initial.Revision != 0 || initial.RevisionEpoch == "" {
		t.Fatalf("initial version = (%s,%d), want a new Edge epoch at revision 0", initial.RevisionEpoch, initial.Revision)
	}

	for _, action := range []fb.WGNetworkEventAction{
		fb.WGNetworkEventActionUPSERT,
		fb.WGNetworkEventActionRUNTIME_UPDATE,
	} {
		if err := h.PushNetworkEvent("net", action); err != nil {
			t.Fatal(err)
		}
	}
	if len(pusher.payloads) != 2 {
		t.Fatalf("push count = %d, want 2", len(pusher.payloads))
	}

	var epoch string
	var previousRevision uint64
	for i, payload := range pusher.payloads {
		root := fb.GetRootAsMessage(payload, 0)
		var body flatbuffers.Table
		if !root.Body(&body) {
			t.Fatalf("push %d has no body", i)
		}
		var event fb.WGNetworkEventPush
		event.Init(body.Bytes, body.Pos)
		gotEpoch := string(event.RevisionEpoch())
		if gotEpoch == "" {
			t.Fatalf("push %d has no Edge revision epoch", i)
		}
		if i == 0 {
			epoch = gotEpoch
		} else if gotEpoch != epoch {
			t.Fatalf("revision epoch changed within one Edge process: %q != %q", gotEpoch, epoch)
		}
		if event.NextRevision() <= previousRevision {
			t.Fatalf("push revision did not increase: got %d after %d", event.NextRevision(), previousRevision)
		}
		previousRevision = event.NextRevision()

		var snapshot fb.WGNetworkRuntimeSnapshotInfo
		if event.Snapshot(&snapshot) == nil {
			t.Fatalf("push %d has no runtime snapshot", i)
		}
		if string(snapshot.RevisionEpoch()) != gotEpoch || snapshot.Revision() != event.NextRevision() {
			t.Fatalf("push %d version mismatch: event=(%s,%d) snapshot=(%s,%d)",
				i, gotEpoch, event.NextRevision(), snapshot.RevisionEpoch(), snapshot.Revision())
		}
	}

	current, err := h.getVersionedNetworkOverview("net")
	if err != nil {
		t.Fatal(err)
	}
	if current.RevisionEpoch != epoch || current.Revision != previousRevision {
		t.Fatalf("runtime GET version=(%s,%d), last push=(%s,%d)", current.RevisionEpoch, current.Revision, epoch, previousRevision)
	}

	// Network deletion has no snapshot, but shares the same Edge sequence.
	h.pushNetworkDeleteEvent("net", []string{"device-a"})
	if len(pusher.payloads) != 3 {
		t.Fatalf("push count after DELETE = %d, want 3", len(pusher.payloads))
	}
	root := fb.GetRootAsMessage(pusher.payloads[2], 0)
	var body flatbuffers.Table
	if !root.Body(&body) {
		t.Fatal("DELETE push has no body")
	}
	var deletion fb.WGNetworkEventPush
	deletion.Init(body.Bytes, body.Pos)
	if deletion.Action() != fb.WGNetworkEventActionDELETE ||
		string(deletion.RevisionEpoch()) != epoch || deletion.NextRevision() != previousRevision+1 {
		t.Fatalf("DELETE version/action mismatch: epoch=%q revision=%d action=%d", deletion.RevisionEpoch(), deletion.NextRevision(), deletion.Action())
	}
	var noSnapshot fb.WGNetworkRuntimeSnapshotInfo
	if deletion.Snapshot(&noSnapshot) != nil {
		t.Fatal("DELETE push unexpectedly carries a snapshot")
	}
}

type recipientProgressPusher struct {
	pathProgressPusher
	identities runtimeBootstrapControls
}

func (p *recipientProgressPusher) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	return p.identities.CurrentClientSession(device)
}

func TestNetworkPushBindsBootstrapAndSelfToEachRecipient(t *testing.T) {
	mm, _ := newPathMembershipFixture(t)
	coordinator := &MeshCoordinator{NetworkManager: mm.networkManager, MemberManager: mm}
	identities := runtimeBootstrapControls{}
	for _, id := range []string{"a", "b"} {
		if err := mm.SetMemberOnline(id); err != nil {
			t.Fatal(err)
		}
		identities["device-"+id] = types.SessionIdentity{UserID: "device:device-" + id, DeviceID: "device-" + id, SessionID: "session-" + id, Capabilities: []string{pathcoord.Capability}, ScopeClaims: []string{"network:net"}}
	}
	owner, err := pathcoord.NewOwner("edge", mm, identities, pathcoord.OwnerConfig{Budgets: pathcoord.Budgets{Prepare: time.Second, Apply: time.Second}, Registry: pathcoord.RegistryLimits{Members: 8}, MaxPairs: 8, ControlBurst: 8, TickInterval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pusher := &recipientProgressPusher{identities: identities}
	h := NewWireGuardHandler(coordinator, pusher, nil, "edge", nil)
	if err := h.AttachPathControlReceiver(owner); err != nil {
		t.Fatal(err)
	}
	if err := h.PushNetworkEvent("net", fb.WGNetworkEventActionRUNTIME_UPDATE); err != nil {
		t.Fatal(err)
	}
	if len(pusher.payloads) != 2 {
		t.Fatalf("recipient pushes=%d", len(pusher.payloads))
	}
	selves := map[string]bool{}
	var revision uint64
	for _, data := range pusher.payloads {
		root := fb.GetRootAsMessage(data, 0)
		var table flatbuffers.Table
		root.Body(&table)
		var event fb.WGNetworkEventPush
		event.Init(table.Bytes, table.Pos)
		var snapshot fb.WGNetworkRuntimeSnapshotInfo
		if event.Snapshot(&snapshot) == nil {
			t.Fatal("missing snapshot")
		}
		network := snapshot.Network(nil)
		if network == nil || !network.SelfJoined() || len(snapshot.PathAuthorityEpoch()) == 0 {
			t.Fatal("recipient bootstrap/self missing")
		}
		selves[string(network.SelfMemberId())] = true
		if revision != 0 && event.NextRevision() != revision {
			t.Fatal("one publication created different recipient revisions")
		}
		revision = event.NextRevision()
	}
	if !selves["a"] || !selves["b"] {
		t.Fatalf("recipient self bindings=%v", selves)
	}
}
