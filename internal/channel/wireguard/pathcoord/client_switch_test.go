package pathcoord

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

type switchMembers struct{ binding PairBinding }

func (m switchMembers) PathPair(PairKey) (PairBinding, error) { return m.binding, nil }
func (m switchMembers) PathMember(_, device string) (MemberBinding, error) {
	for _, member := range m.binding.Members {
		if member.DeviceID == device {
			return MemberBinding{Network: m.binding.Network, Member: member}, nil
		}
	}
	return MemberBinding{}, ErrMembershipRevoked
}

type switchControls struct{}

type switchCurrentControls map[string]types.SessionIdentity

func (c switchCurrentControls) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	identity, ok := c[device]
	return identity, ok
}

func (switchControls) CurrentClientSession(device string) (types.SessionIdentity, bool) {
	return types.SessionIdentity{SessionID: "session-" + device, UserID: "user", DeviceID: device, Capabilities: []string{Capability}}, true
}
func switchKey(n byte) string {
	b := make([]byte, 32)
	b[0] = n
	return base64.StdEncoding.EncodeToString(b)
}
func switchOwner(t *testing.T) (*Owner, *time.Time) {
	t.Helper()
	now := time.Now()
	binding := PairBinding{Network: NetworkBinding{NetworkID: "net", CoordinatorID: "edge", PolicyRevision: 1, RelayMode: fb.WGRelayModeOPTIONAL, RelayPublicKey: switchKey(3)}}
	for i, id := range []string{"a", "b"} {
		binding.Members[i] = Membership{MemberID: id, DeviceID: "device-" + id, PublicKey: switchKey(byte(i + 1)), AssignedIP: []string{"10.1.0.1", "10.1.0.2"}[i], Generation: "membership-" + id}
	}
	o, err := NewOwner("edge", switchMembers{binding}, switchControls{}, OwnerConfig{Budgets: Budgets{Prepare: time.Second, Apply: time.Second}, Registry: RegistryLimits{Members: 8}, MaxPairs: 8, ControlBurst: 100, TickInterval: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return o, &now
}
func senderFor(id string) types.SessionIdentity {
	s, _ := (switchControls{}).CurrentClientSession("device-" + id)
	return s
}
func switchSnapshot(t *testing.T, o *Owner) Snapshot {
	t.Helper()
	s, ok := o.Snapshot(PairKey{"net", "a", "b"})
	if !ok {
		t.Fatal("pair missing")
	}
	return s
}
func switchRequest(t *testing.T, o *Owner, kind fb.WGPathRequestKind, path fb.WGPathType, id string) *fb.WGPathRequestT {
	t.Helper()
	command := ""
	if s, ok := o.Snapshot(PairKey{"net", "a", "b"}); ok {
		command = s.Plan.CommandId
	}
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: kind, RequestedPath: path, RequestId: id, ObservedAuthorityEpoch: o.coordinator.epoch, ObservedCommandId: command, TargetPath: fb.WGPathTypeDIRECT}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err != nil {
		t.Fatal(err)
	}
	return r
}
func switchReport(t *testing.T, o *Owner, id string, kind fb.WGPathReportKind) *fb.WGPathReportT {
	t.Helper()
	p := switchSnapshot(t, o).Plan
	r := &fb.WGPathReportT{Version: cloneVersion(p.Version), CommandId: p.CommandId, MemberId: id, Kind: kind, SavedMode: cloneMode(p.ModeSetting)}
	if kind == fb.WGPathReportKindAPPLIED {
		other := p.MemberB
		if id == "b" {
			other = p.MemberA
		}
		r.ActualAllowedIps = []string{other.AssignedIp + "/32"}
		r.ActualPath = p.TargetPath
		r.AppliedVersion = cloneVersion(p.Version)
		r.ActualOwnerPublicKey = p.MemberB.PublicKey
		if id == "b" {
			r.ActualOwnerPublicKey = p.MemberA.PublicKey
		}
		if p.TargetPath == fb.WGPathTypeRELAY {
			r.ActualOwnerPublicKey = p.RelayPublicKey
		}
	}
	if err := o.HandlePathControl(senderFor(id), ControlMessage{Report: r}); err != nil {
		t.Fatal(err)
	}
	return r
}
func finishSwitch(t *testing.T, o *Owner) {
	t.Helper()
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
	switchReport(t, o, "b", fb.WGPathReportKindAPPLIED)
}

func TestClientSwitchNeedsBothReadyAndBothAppliedWithoutRuntimeOrProbe(t *testing.T) {
	o, _ := switchOwner(t)
	request := switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeRELAY, "click")
	s := switchSnapshot(t, o)
	if s.Plan.Phase != fb.WGPathPhaseWAITING_READY || s.Plan.CommittedPath != fb.WGPathTypeUNKNOWN {
		t.Fatal("request fabricated a commit")
	}
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	if switchSnapshot(t, o).Plan.Phase != fb.WGPathPhaseWAITING_READY {
		t.Fatal("one READY committed")
	}
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	commit := switchSnapshot(t, o).Plan
	if commit.Phase != fb.WGPathPhaseAPPLY || commit.CommandId == s.Plan.CommandId {
		t.Fatal("missing common COMMIT")
	}
	switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
	if switchSnapshot(t, o).Plan.Phase != fb.WGPathPhaseAPPLY {
		t.Fatal("one APPLIED confirmed")
	}
	switchReport(t, o, "b", fb.WGPathReportKindAPPLIED)
	final := switchSnapshot(t, o)
	if final.Plan.Phase != fb.WGPathPhaseCONFIRMED || final.Plan.CommittedPath != fb.WGPathTypeRELAY {
		t.Fatal("both applied did not confirm")
	}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: request}); err != nil {
		t.Fatal(err)
	}
	if switchSnapshot(t, o).Plan.Version.PairRevision != final.Plan.Version.PairRevision {
		t.Fatal("request replay restarted transaction")
	}
	pairs, err := o.RuntimePairs("net", senderFor("a"), time.Now())
	if err != nil || len(pairs) != 1 || !pairs[0].ModeSavedA || !pairs[0].ModeSavedB {
		t.Fatal("missing bilateral saved mode", err)
	}
}

func TestClientMissingPeerCapabilityIdentifiesDeviceAndCanRetryAfterReconnect(t *testing.T) {
	o, _ := switchOwner(t)
	controls := switchCurrentControls{}
	for _, id := range []string{"a", "b"} {
		identity := senderFor(id)
		controls[identity.DeviceID] = identity
	}
	peer := controls["device-b"]
	peer.Hostname = "TV-001"
	peer.Capabilities = []string{"wireguard"}
	controls[peer.DeviceID] = peer
	o.registry.controls = controls
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE,
		RequestedPath: fb.WGPathTypeRELAY, RequestId: "click", ObservedAuthorityEpoch: o.coordinator.epoch}
	err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r})
	if !errors.Is(err, ErrCoordinationAccessRevoked) || !strings.Contains(err.Error(), "device-b") ||
		!strings.Contains(err.Error(), "TV-001") || !strings.Contains(err.Error(), Capability) {
		t.Fatal("capability rejection did not identify the actual peer", err)
	}
	if pairs, err := o.RuntimePairs("net", senderFor("a"), time.Now()); err != nil || len(pairs) != 0 {
		t.Fatal("a rejected proposal broke ordinary snapshot projection", err)
	}
	peer.Capabilities = append(peer.Capabilities, Capability)
	controls[peer.DeviceID] = peer
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err != nil {
		t.Fatal("capable reconnect could not retry the rejected request", err)
	}
	finishSwitch(t, o)
}
func TestClientAutoSwitchPreservesModeAndPairGateSerializesManual(t *testing.T) {
	o, _ := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeUNKNOWN, "auto")
	finishSwitch(t, o)
	setting := cloneMode(switchSnapshot(t, o).Plan.ModeSetting)
	switchRequest(t, o, fb.WGPathRequestKindSWITCH_PATH, fb.WGPathTypeRELAY, "auto-fallback")
	old := switchReport(t, o, "a", fb.WGPathReportKindREADY)
	if !sameMode(setting, switchSnapshot(t, o).Plan.ModeSetting) {
		t.Fatal("Auto path proposal changed mode")
	}
	manual := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindCHANGE_MODE, RequestedPath: fb.WGPathTypeDIRECT, RequestId: "manual", ObservedAuthorityEpoch: o.coordinator.epoch, TargetPath: fb.WGPathTypeDIRECT}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: manual}); err != nil {
		t.Fatal("manual request replaced an in-flight Auto barrier", err)
	}
	finishSwitch(t, o)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeDIRECT, "manual-after-completion")
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: old}); err == nil {
		t.Fatal("old Auto READY accepted after manual")
	}
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindSWITCH_PATH, RequestedPath: fb.WGPathTypeRELAY, RequestId: "old-auto", ObservedAuthorityEpoch: o.coordinator.epoch, ObservedCommandId: old.CommandId}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err != nil {
		t.Fatal("later Auto proposal should be ignored", err)
	}
	if switchSnapshot(t, o).Plan.ModeSetting.Mode != fb.WGPathTypeDIRECT {
		t.Fatal("Auto overrode manual mode")
	}
	finishSwitch(t, o)
	if switchSnapshot(t, o).Plan.CommittedPath != fb.WGPathTypeDIRECT {
		t.Fatal("manual mode was lost")
	}
}
func TestClientCommitFailureAndTimeoutNeverRollBackOrPickAnotherPath(t *testing.T) {
	o, now := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeRELAY, "relay")
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	p := switchSnapshot(t, o).Plan
	r := &fb.WGPathReportT{Version: cloneVersion(p.Version), CommandId: p.CommandId, MemberId: "a", Kind: fb.WGPathReportKindREJECTED, Error: fb.WGPathErrorCONTROL_UNAVAILABLE, ErrorMessage: "native apply outcome unknown"}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: r}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * time.Hour)
	scope, _ := o.registry.Scope(PairKey{"net", "a", "b"})
	result, err := o.coordinator.Tick(scope, *now)
	if err != nil || result.Plan.Phase != fb.WGPathPhaseAPPLY || result.Plan.CommandId != p.CommandId || result.Plan.TargetPath != fb.WGPathTypeRELAY {
		t.Fatal("COMMIT was expired or replaced", err)
	}
	switchReport(t, o, "a", fb.WGPathReportKindAPPLIED)
	switchReport(t, o, "b", fb.WGPathReportKindAPPLIED)
	if switchSnapshot(t, o).Plan.Phase != fb.WGPathPhaseCONFIRMED {
		t.Fatal("same COMMIT could not recover")
	}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: r}); err != nil {
		t.Fatal(err)
	}
	if s := switchSnapshot(t, o); s.LastError != fb.WGPathErrorNONE || s.Plan.Phase != fb.WGPathPhaseCONFIRMED {
		t.Fatal("delayed failure revoked a confirmed application")
	}
	// Health cannot change a manual decision, even with no probe replies.
	switchReport(t, o, "a", fb.WGPathReportKindHEALTH)
	if switchSnapshot(t, o).Plan.CommittedPath != fb.WGPathTypeRELAY {
		t.Fatal("health changed path")
	}
}
func TestClientReadyDeadlineDoesNotCommitAndReadDoesNotMutate(t *testing.T) {
	o, now := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeDIRECT, "direct")
	before := switchSnapshot(t, o)
	*now = now.Add(2 * time.Second)
	if _, err := o.RuntimePairs("net", senderFor("a"), *now); err != nil {
		t.Fatal(err)
	}
	if switchSnapshot(t, o).Plan.Phase != before.Plan.Phase {
		t.Fatal("read advanced transaction")
	}
	scope, _ := o.registry.Scope(PairKey{"net", "a", "b"})
	result, err := o.coordinator.Tick(scope, *now)
	if err != nil || result.Plan.Phase != fb.WGPathPhaseUNREACHABLE || result.Plan.CommittedPath != fb.WGPathTypeUNKNOWN || result.Plan.ModeSetting.Mode != fb.WGPathTypeDIRECT {
		t.Fatal("READY timeout fabricated commit or released mode", err)
	}
}
func TestScopeBeforeRuntimeRegistrationDoesNotCreateNilInputRecord(t *testing.T) {
	o, _ := switchOwner(t)
	pair := PairKey{"net", "a", "b"}
	if _, err := o.registry.Scope(pair); err != nil {
		t.Fatal(err)
	}
	if len(o.registry.runtimes) != 0 {
		t.Fatal("read created partial runtime registration")
	}
	// An invalid registration may return a validation error; it must never panic.
	_, _ = o.registry.Register(senderFor("a"), &fb.WGPathRuntimeReportT{NetworkId: "net", Member: &fb.WGPathMemberContextT{MemberId: "a"}})
}

func TestClientAppliedEvidenceIsValidatedBeforeMutation(t *testing.T) {
	o, _ := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeDIRECT, "direct")
	switchReport(t, o, "a", fb.WGPathReportKindREADY)
	switchReport(t, o, "b", fb.WGPathReportKindREADY)
	p := switchSnapshot(t, o).Plan
	r := &fb.WGPathReportT{Version: cloneVersion(p.Version), AppliedVersion: cloneVersion(p.Version), CommandId: p.CommandId, MemberId: "a", Kind: fb.WGPathReportKindAPPLIED, ActualPath: p.TargetPath, ActualOwnerPublicKey: p.MemberB.PublicKey, SavedMode: cloneMode(p.ModeSetting)}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: r}); err == nil {
		t.Fatal("APPLIED without the peer route was accepted")
	}
	r.ActualAllowedIps = []string{p.MemberB.AssignedIp + "/32"}
	r.SavedMode = nil
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: r}); err == nil {
		t.Fatal("APPLIED without saved user policy was accepted")
	}
	if s := switchSnapshot(t, o); s.Applied[0] != nil || s.Reports[0] != nil {
		t.Fatal("invalid report partially mutated the barrier")
	}
	// A delayed READY cannot count as an APPLIED acknowledgement.
	r.Kind = fb.WGPathReportKindREADY
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Report: r}); err == nil {
		t.Fatal("READY satisfied the COMMIT barrier")
	}
	finish := func(id string) { switchReport(t, o, id, fb.WGPathReportKindAPPLIED) }
	finish("a")
	finish("b")
}

func TestClientCandidateChangesDoNotSupersedeAndStaleEpochCannotRestore(t *testing.T) {
	o, now := switchOwner(t)
	switchRequest(t, o, fb.WGPathRequestKindCHANGE_MODE, fb.WGPathTypeRELAY, "relay")
	before := switchSnapshot(t, o)
	scope, err := o.registry.Scope(PairKey{"net", "a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	member := *scope.Members[0]
	member.RuntimeGeneration = "replacement-runtime"
	member.CandidateRevision++
	member.Candidates = []*fb.WGPathCandidateT{{Endpoint: "203.0.113.1:3000"}}
	scope.Members[0] = &member
	result, err := o.coordinator.Synchronize(scope, *now)
	if err != nil || result.Plan.CommandId != before.Plan.CommandId || result.Plan.Version.PairRevision != before.Plan.Version.PairRevision {
		t.Fatal("candidate/runtime update retired a client intent", err)
	}
	r := &fb.WGPathRequestT{NetworkId: "net", PeerMemberId: "b", Kind: fb.WGPathRequestKindSYNC_MODE, RequestId: "restore", ObservedAuthorityEpoch: "old-epoch", TargetPath: fb.WGPathTypeDIRECT, LocalMode: cloneMode(before.Plan.ModeSetting)}
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err == nil {
		t.Fatal("stale authority restore was accepted")
	}
	r.ObservedAuthorityEpoch = o.coordinator.epoch
	r.LocalMode.Mode = fb.WGPathTypeDIRECT
	if err := o.HandlePathControl(senderFor("a"), ControlMessage{Request: r}); err != nil {
		t.Fatal(err)
	}
	if !sameMode(before.Plan.ModeSetting, switchSnapshot(t, o).Plan.ModeSetting) {
		t.Fatal("restore replaced a current user choice")
	}
}
