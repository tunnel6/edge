package pathcoord

import (
	"fmt"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	fb "icool.io/yat/api/build/fb/golang/message"
)

// Scope is a trusted registry snapshot, not a decoded runtime report. The
// transport adapter must resolve membership, policy, capability and the current
// authenticated control sessions before every operation. Runtime facts cannot
// grant membership or replace Edge-observed candidates.
type Scope struct {
	Pair           PairKey
	CoordinatorID  string
	PolicyRevision uint64
	RelayMode      fb.WGRelayMode
	RelayPublicKey string
	Members        [2]*fb.WGPathMemberContextT // canonical PairKey order
	Sessions       [2]string                   // current authenticated connections
	Capable        [2]bool
}

// Budgets bound readiness and supply the default overall negotiation deadline.
// Apply is used only when TransactionTimeout is unset; COMMIT itself stays
// replayable after the active admission gate expires.
type Budgets struct {
	Prepare time.Duration
	Apply   time.Duration
}

// Snapshot is detached from the coordinator. Applied retains versioned native
// readback across membership/policy invalidation; it cannot acknowledge a new
// command. Reports contains only the current READY or APPLIED barrier.
type Snapshot struct {
	Plan             *fb.WGPathPlanT
	Reports          [2]*fb.WGPathReportT
	Applied          [2]*fb.WGPathReportT
	ModeSaved        [2]bool
	LastError        fb.WGPathError
	LastErrorMessage string
	Deadline         time.Time
}

type transaction struct {
	state            Snapshot
	transactionUntil time.Time
	// lastTouched orders terminal contexts when the bounded retained-context
	// cache needs to make room for a new pair. It never participates in
	// admission; only clientInFlight does.
	lastTouched time.Time
}

// Coordinator retains client-initiated READY/COMMIT/APPLIED barriers. It owns
// no sockets, goroutines, path selection, health rounds or server-side retries.
type Coordinator struct {
	mu                 sync.Mutex
	edgeID             string
	epoch              string
	budgets            Budgets
	transactionTimeout time.Duration
	maxPairs           int
	revision           uint64 // global within this epoch, hence monotonic even after Forget
	pairs              map[PairKey]*transaction
}

func NewCoordinator(edgeID string, budgets Budgets, maxPairs int) (*Coordinator, error) {
	if !validID(edgeID) || maxPairs <= 0 {
		return nil, fmt.Errorf("invalid WG authority or pair quota")
	}
	if err := budgets.validate(); err != nil {
		return nil, err
	}
	return &Coordinator{edgeID: edgeID, epoch: uuid.NewString(), budgets: budgets,
		maxPairs: maxPairs, pairs: make(map[PairKey]*transaction)}, nil
}

func (budgets Budgets) validate() error {
	for _, d := range []time.Duration{budgets.Prepare, budgets.Apply} {
		if d < time.Millisecond || d%time.Millisecond != 0 || d/time.Millisecond > math.MaxUint32 {
			return fmt.Errorf("WG phase budgets must fit positive wire milliseconds")
		}
	}
	return nil
}

func (c *Coordinator) validateScope(s Scope) error {
	pair, err := NewPairKey(s.Pair.NetworkID, s.Pair.MemberAID, s.Pair.MemberBID)
	if err != nil || pair != s.Pair || s.CoordinatorID != c.edgeID || s.PolicyRevision == 0 || s.RelayMode > fb.WGRelayModeFORCE {
		return fmt.Errorf("invalid WG registry authority/policy/pair")
	}
	// Coordination requires membership, not runtime/probe registration.
	// Clients choose and prepare their own endpoint from the current directory.
	for i, m := range []*fb.WGPathMemberContextT{s.Members[0], s.Members[1]} {
		if m == nil {
			return fmt.Errorf("missing WG scope member %d", i)
		}
		expectedID := [2]string{pair.MemberAID, pair.MemberBID}[i]
		if m.MemberId != expectedID {
			return fmt.Errorf("WG scope member %d ID mismatch", i)
		}
		if !validID(m.DeviceId) || !validKey(m.PublicKey) {
			return fmt.Errorf("invalid WG scope member %d identity", i)
		}
		ip, ipErr := netip.ParseAddr(m.AssignedIp)
		if ipErr != nil || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("invalid WG scope member %d address", i)
		}
	}
	if s.Members[0].PublicKey == s.Members[1].PublicKey ||
		s.Members[0].DeviceId == s.Members[1].DeviceId ||
		s.Members[0].AssignedIp == s.Members[1].AssignedIp {
		return fmt.Errorf("WG scope pair has duplicate identity")
	}
	if s.RelayPublicKey != "" && (!validKey(s.RelayPublicKey) ||
		s.RelayPublicKey == s.Members[0].PublicKey || s.RelayPublicKey == s.Members[1].PublicKey) {
		return fmt.Errorf("invalid WG registry relay identity")
	}
	if !s.Capable[0] || !s.Capable[1] {
		return fmt.Errorf("both WG members must support %s", Capability)
	}
	return nil
}

func (c *Coordinator) version(s Scope) (*fb.WGPathVersionT, error) {
	if c.revision == math.MaxUint64 {
		return nil, fmt.Errorf("WG authority revision exhausted; new epoch required")
	}
	c.revision++
	return &fb.WGPathVersionT{NetworkId: s.Pair.NetworkID, MemberAId: s.Pair.MemberAID,
		MemberBId: s.Pair.MemberBID, CoordinatorEdgeId: c.edgeID, AuthorityEpoch: c.epoch,
		PairRevision: c.revision, NetworkPolicyRevision: s.PolicyRevision, AttemptId: uuid.NewString()}, nil
}

func (c *Coordinator) newPlan(s Scope, committed fb.WGPathType) (*fb.WGPathPlanT, error) {
	v, err := c.version(s)
	if err != nil {
		return nil, err
	}
	return &fb.WGPathPlanT{Version: v, MemberA: cloneMember(s.Members[0]), MemberB: cloneMember(s.Members[1]),
		RelayMode: s.RelayMode, RelayPublicKey: s.RelayPublicKey, CommittedPath: committed}, nil
}

// enter starts a fresh command and clears only its acknowledgement barrier.
func (c *Coordinator) enter(t *transaction, phase fb.WGPathPhase, now time.Time) {
	p := t.state.Plan
	p.Phase, p.CommandId = phase, uuid.NewString()
	p.PhaseTimeoutMs = 0
	t.state.Reports = [2]*fb.WGPathReportT{}
	t.state.Deadline = time.Time{}
	if phase == fb.WGPathPhaseWAITING_READY {
		p.PhaseTimeoutMs = uint32(c.budgets.Prepare / time.Millisecond)
		t.state.Deadline = now.Add(c.budgets.Prepare)
		if t.transactionUntil.Before(t.state.Deadline) {
			t.state.Deadline = t.transactionUntil
		}
	} else if phase == fb.WGPathPhaseAPPLY {
		t.state.Deadline = t.transactionUntil
	}
}

func (c *Coordinator) current(s Scope) (*transaction, error) {
	if err := c.validateScope(s); err != nil {
		return nil, err
	}
	t := c.pairs[s.Pair]
	if t == nil || t.state.Plan.Phase == fb.WGPathPhaseCANCELLED {
		return nil, fmt.Errorf("WG pair is absent or revoked")
	}
	if !lightContextMatches(t.state.Plan, s) {
		return nil, fmt.Errorf("WG registry changed; synchronize before continuing")
	}
	return t, nil
}

// Synchronize invalidates commands only on trusted membership/policy changes.
// Runtime, candidate and control reconnect updates do not replace a decision.
func (c *Coordinator) Synchronize(s Scope, now time.Time) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateScope(s); err != nil {
		return Snapshot{}, err
	}
	t := c.pairs[s.Pair]
	if t == nil || t.state.Plan.Phase == fb.WGPathPhaseCANCELLED {
		return Snapshot{}, fmt.Errorf("WG pair is absent or revoked")
	}
	if lightContextMatches(t.state.Plan, s) {
		return cloneSnapshot(t.state), nil
	}
	t.transactionUntil = time.Time{}
	p, err := c.newPlan(s, t.state.Plan.CommittedPath)
	if err != nil {
		return Snapshot{}, err
	}
	p.ModeSetting = cloneMode(t.state.Plan.ModeSetting)
	// Key/address/membership replacement invalidates the old confirmed identity.
	for i, old := range []*fb.WGPathMemberContextT{t.state.Plan.MemberA, t.state.Plan.MemberB} {
		next := s.Members[i]
		if old.RuntimeGeneration != next.RuntimeGeneration || old.NetworkEnvironment != next.NetworkEnvironment {
			t.state.ModeSaved = [2]bool{}
		}
		if old.DeviceId != next.DeviceId || old.MembershipGeneration != next.MembershipGeneration || old.PublicKey != next.PublicKey || old.AssignedIp != next.AssignedIp {
			p.ModeSetting = nil // a replacement member must never inherit a removed pair's preference
			p.CommittedPath = fb.WGPathTypeUNKNOWN
			t.state.ModeSaved = [2]bool{}
		}
	}
	t.state.Plan = p
	t.state.LastError, t.state.LastErrorMessage = fb.WGPathErrorSTALE_VERSION, "membership/policy changed; refresh pair proposal"
	c.enter(t, fb.WGPathPhaseUNREACHABLE, now)
	return cloneSnapshot(t.state), nil
}

func (c *Coordinator) sender(s Scope, memberID, deviceID, sessionID string) (int, error) {
	for i, m := range s.Members {
		if memberID == m.MemberId && deviceID == m.DeviceId &&
			sessionID != "" && sessionID == s.Sessions[i] {
			return i, nil
		}
	}
	return -1, fmt.Errorf("WG report is not from the current authenticated member session")
}

// Tick releases expired admission without revoking a retained COMMIT.
func (c *Coordinator) Tick(s Scope, now time.Time) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, err := c.current(s)
	if err != nil {
		return Snapshot{}, err
	}
	c.clientTick(t, now)
	return cloneSnapshot(t.state), nil
}

// Cancel is used for leave, revoked capability, network removal or authority
// loss. Revocation comes from registry events and needs no client cooperation.
func (c *Coordinator) Cancel(pair PairKey, reason string, now time.Time) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.pairs[pair]
	if t == nil {
		return Snapshot{}, fmt.Errorf("WG pair not found")
	}
	if t.state.Plan.Phase != fb.WGPathPhaseCANCELLED {
		if c.revision == math.MaxUint64 {
			return Snapshot{}, fmt.Errorf("WG authority revision exhausted; new epoch required")
		}
		c.revision++
		t.state.Plan.Version = cloneVersion(t.state.Plan.Version)
		t.state.Plan.Version.PairRevision, t.state.Plan.Version.AttemptId = c.revision, uuid.NewString()
		t.state.LastError, t.state.LastErrorMessage = fb.WGPathErrorCANCELLED, reason
		c.enter(t, fb.WGPathPhaseCANCELLED, now)
	}
	return cloneSnapshot(t.state), nil
}

func (c *Coordinator) Forget(pair PairKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.pairs[pair]; t != nil && t.state.Plan.Phase != fb.WGPathPhaseCANCELLED {
		return fmt.Errorf("WG pair must be revoked before release")
	}
	delete(c.pairs, pair)
	return nil
}

// Snapshot is a diagnostic copy, not authorization to dispatch a stale command.
func (c *Coordinator) Snapshot(pair PairKey) (Snapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.pairs[pair]
	if t == nil {
		return Snapshot{}, false
	}
	return cloneSnapshot(t.state), true
}

func cloneVersion(v *fb.WGPathVersionT) *fb.WGPathVersionT {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}

func cloneMember(m *fb.WGPathMemberContextT) *fb.WGPathMemberContextT {
	if m == nil {
		return nil
	}
	x := *m
	if m.Candidates != nil {
		x.Candidates = make([]*fb.WGPathCandidateT, len(m.Candidates))
	}
	for i, candidate := range m.Candidates {
		if candidate != nil {
			v := *candidate
			x.Candidates[i] = &v
		}
	}
	return &x
}

func clonePlan(p *fb.WGPathPlanT) *fb.WGPathPlanT {
	if p == nil {
		return nil
	}
	x := *p
	x.Version, x.MemberA, x.MemberB = cloneVersion(p.Version), cloneMember(p.MemberA), cloneMember(p.MemberB)
	x.VerificationNonce = append([]byte(nil), p.VerificationNonce...)
	x.ModeSetting = cloneMode(p.ModeSetting)
	return &x
}

func cloneReport(r *fb.WGPathReportT) *fb.WGPathReportT {
	if r == nil {
		return nil
	}
	x := *r
	x.Version, x.AppliedVersion = cloneVersion(r.Version), cloneVersion(r.AppliedVersion)
	x.LastConfirmedPlan = clonePlan(r.LastConfirmedPlan)
	x.SavedMode = cloneMode(r.SavedMode)
	x.ActualAllowedIps = append([]string(nil), r.ActualAllowedIps...)
	if r.Business != nil {
		b := *r.Business
		b.VerificationNonce = append([]byte(nil), r.Business.VerificationNonce...)
		x.Business = &b
	}
	return &x
}

func cloneSnapshot(s Snapshot) Snapshot {
	x := s
	x.Plan = clonePlan(s.Plan)
	for i := 0; i < 2; i++ {
		x.Reports[i], x.Applied[i] = cloneReport(s.Reports[i]), cloneReport(s.Applied[i])
	}
	return x
}
