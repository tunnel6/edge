package pathcoord

import (
	"context"
	"reflect"
	"testing"

	fb "icool.io/yat/api/build/fb/golang/message"
)

func TestInvalidFirstProposalDoesNotRetainPairOrSpendRevision(t *testing.T) {
	o, _ := switchOwner(t)
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE,
		RequestId: "invalid-initial-auto", ObservedAuthorityEpoch: o.coordinator.epoch}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err == nil {
		t.Fatal("initial Auto proposal without a concrete path was accepted")
	}
	if len(o.pairs) != 0 || len(o.coordinator.pairs) != 0 || o.coordinator.revision != 0 {
		t.Fatal("rejected proposal allocated authority state")
	}
	r.TargetPath = fb.WGPathTypeDIRECT
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err != nil {
		t.Fatal("valid initial proposal was not admitted", err)
	}
	if s := switchSnapshot(t, o); s.Plan.Phase != fb.WGPathPhaseWAITING_READY || s.Plan.Version.PairRevision != 1 {
		t.Fatal("initial proposal did not directly enter the readiness barrier")
	}
}

func TestAutoProposalWithoutObservedCommandCannotReplaceExistingPair(t *testing.T) {
	o, _ := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeUNKNOWN, "auto")
	finishSwitch(t, o)
	before := switchSnapshot(t, o)
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindSWITCH_PATH,
		RequestedPath: fb.WGPathTypeRELAY, RequestId: "missing-context", ObservedAuthorityEpoch: o.coordinator.epoch}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err == nil {
		t.Fatal("an Auto proposal with no observed command replaced an existing decision")
	}
	if !reflect.DeepEqual(before, switchSnapshot(t, o)) {
		t.Fatal("rejected Auto proposal changed the pair")
	}
}

func TestCurrentRequestContractRejectsLegacyShapes(t *testing.T) {
	base := fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE,
		RequestedPath: fb.WGPathTypeDIRECT, RequestId: "click", ObservedAuthorityEpoch: "epoch"}
	for name, mutate := range map[string]func(*fb.WGPathRequestT){
		"legacy":           func(r *fb.WGPathRequestT) { r.Kind = fb.WGPathRequestKindLEGACY },
		"unknown":          func(r *fb.WGPathRequestT) { r.Kind = 255 },
		"unscoped restore": func(r *fb.WGPathRequestT) { r.Kind = fb.WGPathRequestKindSYNC_MODE; r.RequestId = "" },
		"missing saved mode": func(r *fb.WGPathRequestT) {
			r.Kind = fb.WGPathRequestKindSYNC_MODE
			r.RequestedPath = fb.WGPathTypeUNKNOWN
		},
		"unknown authority": func(r *fb.WGPathRequestT) { r.ObservedAuthorityEpoch = "" },
		"Auto without path": func(r *fb.WGPathRequestT) {
			r.Kind = fb.WGPathRequestKindSWITCH_PATH
			r.RequestedPath = fb.WGPathTypeUNKNOWN
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if err := ValidateRequest(&r); err == nil {
				t.Fatal("obsolete or incomplete request was accepted")
			}
		})
	}
}

func TestMembershipReplacementClearsSavedModeWithoutReusingAppliedBarrier(t *testing.T) {
	o, _ := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeRELAY, "relay")
	finishSwitch(t, o)
	before := switchSnapshot(t, o)
	reader := o.registry.members.(switchMembers)
	reader.binding.Members[1].Generation = "replacement-b"
	o.registry.members = reader
	if err := o.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := switchSnapshot(t, o)
	if after.Plan.ModeSetting != nil || after.ModeSaved != [2]bool{} || after.Plan.CommittedPath != fb.WGPathTypeUNKNOWN ||
		after.Plan.Phase != fb.WGPathPhaseUNREACHABLE || after.Reports != [2]*fb.WGPathReportT{} {
		t.Fatal("replacement inherited the old decision or application barrier")
	}
	if !reflect.DeepEqual(after.Applied, before.Applied) {
		t.Fatal("versioned native readback was lost during invalidation")
	}
	pairs, err := o.RuntimePairs("net", senderFor("a"), o.config.Now())
	if err != nil || len(pairs) != 1 || pairs[0].ModeSavedA || pairs[0].ModeSavedB {
		t.Fatal("projection treated retained readback as saved mode for the replacement", err)
	}
	// Returned read models cannot mutate either current or retained evidence.
	pairs[0].Plan.MemberB.MembershipGeneration = "tampered"
	pairs[0].ReportA.ActualAllowedIps[0] = "0.0.0.0/0"
	if !reflect.DeepEqual(after, switchSnapshot(t, o)) {
		t.Fatal("runtime projection leaked mutable coordinator state")
	}
}
