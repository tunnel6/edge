package pathcoord

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
)

type capacityMembers map[string]Membership

func (m capacityMembers) PathMember(network, device string) (MemberBinding, error) {
	for _, member := range m {
		if member.DeviceID == device {
			return MemberBinding{Network: NetworkBinding{NetworkID: network, CoordinatorID: "edge", PolicyRevision: 1,
				RelayMode: fb.WGRelayModeOPTIONAL, RelayPublicKey: switchKey(3)}, Member: member}, nil
		}
	}
	return MemberBinding{}, ErrMembershipRevoked
}

func (m capacityMembers) PathPair(pair PairKey) (PairBinding, error) {
	a, aOK := m[pair.MemberAID]
	b, bOK := m[pair.MemberBID]
	if !aOK || !bOK {
		return PairBinding{}, ErrMembershipRevoked
	}
	binding, err := m.PathMember(pair.NetworkID, a.DeviceID)
	return PairBinding{Network: binding.Network, Members: [2]Membership{a, b}}, err
}

func capacityOwner(t *testing.T) (*Owner, *time.Time) {
	t.Helper()
	o, now := switchOwner(t)
	members := capacityMembers{}
	for _, member := range o.registry.members.(switchMembers).binding.Members {
		members[member.MemberID] = member
	}
	for i, id := range []string{"c", "d"} {
		members[id] = Membership{MemberID: id, DeviceID: "device-" + id, PublicKey: switchKey(byte(i + 4)),
			AssignedIP: fmt.Sprintf("10.1.0.%d", i+3), Generation: "membership-" + id}
	}
	o.registry.members = members
	o.config.ControlBurst = 1
	if err := o.config.Validate(); err != nil {
		t.Fatal(err)
	}
	return o, now
}

func capacityRequest(o *Owner, network, from, to, id string) (*fb.WGPathRequestT, error) {
	pair, err := NewPairKey(network, from, to)
	if err != nil {
		return nil, err
	}
	command := ""
	if s, ok := o.Snapshot(pair); ok {
		command = s.Plan.CommandId
	}
	r := &fb.WGPathRequestT{NetworkId: network, PeerMemberId: to, Kind: fb.WGPathRequestKindCHANGE_MODE,
		RequestedPath: fb.WGPathTypeDIRECT, TargetPath: fb.WGPathTypeDIRECT, RequestId: id,
		ObservedAuthorityEpoch: o.coordinator.epoch, ObservedCommandId: command}
	return r, o.HandlePathControl(senderFor(from), ControlMessage{Request: r})
}

func TestClientCapacityCountsBothParticipantsAndOnlyInFlightPairs(t *testing.T) {
	o, _ := capacityOwner(t)
	request, err := capacityRequest(o, "net", "a", "b", "click")
	if err != nil {
		t.Fatal(err)
	}
	revision := switchSnapshot(t, o).Plan.Version.PairRevision
	for i := 0; i < 100; i++ {
		if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: request}); err != nil {
			t.Fatal("same request replay must not consume another slot", err)
		}
	}
	// Opposite-end clicks race the same bilateral gate, never supersede it.
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := capacityRequest(o, "net", "b", "a", fmt.Sprintf("other-%d", i))
			failures <- err
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("opposite-end click bypassed pair gate: %v", err)
		}
	}
	if switchSnapshot(t, o).Plan.Version.PairRevision != revision {
		t.Fatal("duplicate/ignored requests restarted the accepted operation")
	}
	for _, endpoints := range [][2]string{{"a", "c"}, {"c", "b"}} {
		if _, err := capacityRequest(o, "net", endpoints[0], endpoints[1], "capacity"); !errors.Is(err, ErrNegotiationCapacity) {
			t.Fatalf("capacity must count requester and responder: %v", err)
		}
		if len(o.pairs) != 1 {
			t.Fatal("rejected operation allocated a retained pair")
		}
	}
	if _, err := capacityRequest(o, "net", "c", "d", "independent"); err != nil {
		t.Fatal("unrelated members should negotiate independently", err)
	}
	if _, err := capacityRequest(o, "other-network", "a", "b", "other-network"); err != nil {
		t.Fatal("member capacity must be scoped to the network", err)
	}
	// Stage reports can be repeated arbitrarily without exhausting operation slots.
	ready := switchReport(t, o, "a", fb.WGPathReportKindREADY)
	for i := 0; i < 100; i++ {
		if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: ready}); err != nil {
			t.Fatal("READY retry was blocked by message count", err)
		}
	}
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	applied := switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
	for i := 0; i < 100; i++ {
		if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: applied}); err != nil {
			t.Fatal("APPLIED retry was blocked by message count", err)
		}
	}
	switchReport(t, o, "b", fb.WGPathReportKindAPPLIED)
	if err := o.Cancel(PairKey{"net", "c", "d"}, "client cancelled"); err != nil {
		t.Fatal(err)
	}
	if _, err := capacityRequest(o, "net", "a", "c", "next"); err != nil {
		t.Fatal("confirmed/cancelled operations must immediately free capacity", err)
	}
}

func TestRetainedPairQuotaEvictsOnlyEndedContexts(t *testing.T) {
	o, _ := capacityOwner(t)
	o.coordinator.maxPairs = 2

	if _, err := capacityRequest(o, "net", "a", "b", "first"); err != nil {
		t.Fatal(err)
	}
	finishSwitch(t, o)

	if _, err := capacityRequest(o, "net", "c", "d", "second"); err != nil {
		t.Fatal(err)
	}
	second, ok := o.Snapshot(PairKey{"net", "c", "d"})
	if !ok {
		t.Fatal("second pair was not retained")
	}
	if err := o.HandlePathControl(senderFor("c"), ControlMessage{Report: &fb.WGPathReportT{
		Version: cloneVersion(second.Plan.Version), CommandId: second.Plan.CommandId,
		MemberId: "c", Kind: fb.WGPathReportKindREJECTED,
		Error: fb.WGPathErrorCONTROL_UNAVAILABLE,
	}}); err != nil {
		t.Fatal(err)
	}

	// The two retained contexts are terminal. A third unique pair must reuse
	// the oldest slot; the owner replay cache must be evicted with it.
	if _, err := capacityRequest(o, "net", "a", "c", "third"); err != nil {
		t.Fatalf("ended pair contexts permanently exhausted max_pairs: %v", err)
	}
	if len(o.coordinator.pairs) != 2 || len(o.pairs) != 2 {
		t.Fatalf("retained pair cache grew after eviction: coordinator=%d owner=%d", len(o.coordinator.pairs), len(o.pairs))
	}
	if _, ok := o.Snapshot(PairKey{"net", "a", "b"}); ok {
		t.Fatal("oldest terminal pair was not evicted")
	}
}

func TestClientCapacityReleaseFollowsBarrierOutcome(t *testing.T) {
	for _, outcome := range []string{"confirmed", "rejected-before-commit", "rejected-after-commit", "ready-timeout", "cancelled", "commit-unconfirmed"} {
		t.Run(outcome, func(t *testing.T) {
			o, now := capacityOwner(t)
			if _, err := capacityRequest(o, "net", "a", "b", "click"); err != nil {
				t.Fatal(err)
			}
			switch outcome {
			case "confirmed":
				finishSwitch(t, o)
			case "rejected-before-commit", "rejected-after-commit":
				if outcome == "rejected-after-commit" {
					switchReport(t, o, "a", fb.WGPathReportKindREADY)
					switchReport(t, o, "b", fb.WGPathReportKindREADY)
				}
				p := switchSnapshot(t, o).Plan
				err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: &fb.WGPathReportT{
					Version: cloneVersion(p.Version), CommandId: p.CommandId, MemberId: "a",
					Kind: fb.WGPathReportKindREJECTED, Error: fb.WGPathErrorCONTROL_UNAVAILABLE}})
				if err != nil {
					t.Fatal(err)
				}
			case "ready-timeout":
				*now = now.Add(2 * time.Second) // release does not wait for a maintenance poll
			case "cancelled":
				if err := o.Cancel(PairKey{"net", "a", "b"}, "client cancelled"); err != nil {
					t.Fatal(err)
				}
			case "commit-unconfirmed":
				switchReport(t, o, "a", fb.WGPathReportKindREADY)
				switchReport(t, o, "b", fb.WGPathReportKindREADY)
				*now = now.Add(24 * time.Hour)
				// A maintenance timeout releases admission but preserves COMMIT.
				if err := o.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
				state := switchSnapshot(t, o)
				if state.LastError != fb.WGPathErrorTIMEOUT || state.Plan.Phase != fb.WGPathPhaseAPPLY {
					t.Fatal("unconfirmed COMMIT must stay recoverable without holding the gate")
				}
				if _, err := capacityRequest(o, "net", "a", "c", "after-timeout"); err != nil {
					t.Fatal("unconfirmed timeout retained capacity", err)
				}
				if err := o.Cancel(PairKey{"net", "a", "c"}, "done"); err != nil {
					t.Fatal(err)
				}
				switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
				switchReport(t, o, "b", fb.WGPathReportKindAPPLIED)
			}
			if _, err := capacityRequest(o, "net", "a", "c", "next"); err != nil {
				t.Fatal("ended operation retained concurrency capacity", err)
			}
		})
	}
}

func TestClientOverallDeadlineAlsoBoundsCommitGate(t *testing.T) {
	o, now := capacityOwner(t)
	o.coordinator.transactionTimeout = 1500 * time.Millisecond
	o.coordinator.budgets.Apply = 100 * time.Millisecond // legacy stage window must not cut the overall gate short
	if _, err := capacityRequest(o, "net", "a", "b", "first"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(900 * time.Millisecond)
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	if remaining := switchSnapshot(t, o).Deadline.Sub(*now); remaining != 600*time.Millisecond {
		t.Fatalf("COMMIT restarted the overall deadline: remaining=%s", remaining)
	}
	*now = now.Add(600 * time.Millisecond)
	if _, err := capacityRequest(o, "net", "b", "a", "next"); err != nil {
		t.Fatal(err)
	}
	if switchSnapshot(t, o).Plan.ModeSetting.RequestId != "next" {
		t.Fatal("expired overall gate blocked next click")
	}
}

type unavailablePairMembers struct{ MembershipReader }

func (m unavailablePairMembers) PathPair(PairKey) (PairBinding, error) {
	return PairBinding{}, fmt.Errorf("temporary source read failure")
}

func TestPollSourceFailureDoesNotPublishUnchangedProjection(t *testing.T) {
	o, _ := capacityOwner(t)
	if _, err := capacityRequest(o, "net", "a", "b", "first"); err != nil {
		t.Fatal(err)
	}
	o.registry.members = unavailablePairMembers{o.registry.members}
	updates := 0
	o.config.OnRuntimeUpdate = func(string, map[string]struct{}) { updates++ }
	for range 3 {
		if err := o.Poll(context.Background()); err == nil {
			t.Fatal("missing source error")
		}
	}
	if updates != 0 {
		t.Fatal("temporary source failures created an event loop")
	}
}

func TestSimultaneousPairClicksKeepFirstDecisionAndAllowNextAfterCompletion(t *testing.T) {
	o, _ := capacityOwner(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, from := range []string{"a", "b"} {
		go func(from string) {
			<-start
			to := "a"
			if from == "a" {
				to = "b"
			}
			_, err := capacityRequest(o, "net", from, to, "click-"+from)
			results <- err
		}(from)
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	winner := switchSnapshot(t, o).Plan
	if winner.ModeSetting.RequestId != "click-a" && winner.ModeSetting.RequestId != "click-b" {
		t.Fatal("missing first arrival")
	}
	finishSwitch(t, o)
	if _, err := capacityRequest(o, "net", "b", "a", "next-click"); err != nil {
		t.Fatal(err)
	}
	if next := switchSnapshot(t, o).Plan; next.ModeSetting.RequestId != "next-click" || next.Version.PairRevision <= winner.Version.PairRevision {
		t.Fatal("completion retained the pair gate")
	}
}

func TestCommitTimeoutNotifiesOnceReleasesPairAndFencesLateReports(t *testing.T) {
	o, now := capacityOwner(t)
	updates := 0
	o.config.OnRuntimeUpdate = func(network string, members map[string]struct{}) {
		if network != "net" {
			t.Fatal("wrong network")
		}
		updates++
		if len(members) != 2 {
			t.Fatalf("timeout invalidated unrelated members: %v", members)
		}
		for _, id := range []string{"a", "b"} {
			if _, ok := members[id]; !ok {
				t.Fatalf("timeout omitted participant %s", id)
			}
		}
		// The observer must be called outside the owner gate.
		if switchSnapshot(t, o).LastError != fb.WGPathErrorTIMEOUT {
			t.Fatal("missing timeout projection")
		}
	}
	if _, err := capacityRequest(o, "net", "a", "b", "first"); err != nil {
		t.Fatal(err)
	}
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	late := switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
	commit := switchSnapshot(t, o).Plan
	*now = now.Add(2 * time.Second)
	for range 3 {
		if err := o.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if updates != 1 || switchSnapshot(t, o).Plan.CommandId != commit.CommandId {
		t.Fatal("timeout must publish once and retain the issued COMMIT")
	}
	if _, err := capacityRequest(o, "net", "b", "a", "after-timeout"); err != nil {
		t.Fatal(err)
	}
	next := switchSnapshot(t, o).Plan
	if next.ModeSetting.RequestId != "after-timeout" || next.Version.PairRevision <= commit.Version.PairRevision {
		t.Fatal("timeout retained pair gate")
	}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: late}); err == nil {
		t.Fatal("old APPLIED crossed the replacement command fence")
	}
	if switchSnapshot(t, o).Plan.CommandId != next.CommandId {
		t.Fatal("late report changed new operation")
	}
}

func TestPairTimeoutDoesNotInvalidateAnotherPairSharingResponder(t *testing.T) {
	o, now := capacityOwner(t)
	if _, err := capacityRequest(o, "net", "c", "b", "c-b"); err != nil {
		t.Fatal(err)
	}
	cb := PairKey{"net", "b", "c"}
	snapshot, _ := o.Snapshot(cb)
	// c-b has already ended. A later a-b timeout must neither notify c nor
	// change c's pair projection, even though both operations use responder b.
	if err := o.HandlePathControl(senderFor("c"), ControlMessage{Report: &fb.WGPathReportT{
		Version: snapshot.Plan.Version, CommandId: snapshot.Plan.CommandId, MemberId: "c",
		Kind: fb.WGPathReportKindREJECTED, Error: fb.WGPathErrorCONTROL_UNAVAILABLE,
	}}); err != nil {
		t.Fatal(err)
	}
	before, err := o.RuntimePairs("net", senderFor("c"), *now)
	if err != nil || len(before) != 1 {
		t.Fatalf("c projection before timeout: %v %v", before, err)
	}
	if _, err := capacityRequest(o, "net", "a", "b", "a-b"); err != nil {
		t.Fatal(err)
	}
	updates := 0
	o.config.OnRuntimeUpdate = func(network string, members map[string]struct{}) {
		updates++
		if network != "net" || !reflect.DeepEqual(members, map[string]struct{}{"a": {}, "b": {}}) {
			t.Fatalf("a-b timeout leaked to c-b: network=%s members=%v", network, members)
		}
		// Callback may read the authority: the owner lock is already released.
		after, err := o.RuntimePairs("net", senderFor("c"), *now)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("a-b timeout changed c-b projection: %v", err)
		}
	}
	*now = now.Add(2 * time.Second)
	for range 3 {
		if err := o.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if updates != 1 {
		t.Fatalf("timeout notifications=%d, want exactly one", updates)
	}
}
