package pathcoord

// The product protocol is a bilateral configuration barrier. Endpoints and
// reachability belong to each client; the Edge never runs path selection.
import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

const retainedModeRequests = 32

func lightContextMatches(p *fb.WGPathPlanT, s Scope) bool {
	if p == nil || p.Version.NetworkPolicyRevision != s.PolicyRevision || p.RelayMode != s.RelayMode || p.RelayPublicKey != s.RelayPublicKey {
		return false
	}
	for i, prior := range []*fb.WGPathMemberContextT{p.MemberA, p.MemberB} {
		next := s.Members[i]
		if prior == nil || next == nil || prior.MemberId != next.MemberId || prior.DeviceId != next.DeviceId || prior.PublicKey != next.PublicKey || prior.AssignedIp != next.AssignedIp || prior.MembershipGeneration != next.MembershipGeneration {
			return false
		}
	}
	return true
}

// The admission gate ends on failure/timeout even when an issued COMMIT must
// remain replayable. Retained commands and active negotiations are distinct.
func clientInFlight(t *transaction, now time.Time) bool {
	return t.state.LastError == fb.WGPathErrorNONE &&
		(t.state.Plan.Phase == fb.WGPathPhaseWAITING_READY || t.state.Plan.Phase == fb.WGPathPhaseAPPLY) &&
		!t.state.Deadline.IsZero() && now.Before(t.state.Deadline)
}

// Count current barriers rather than messages or retained completed projections.
// Deriving usage under the coordinator lock avoids leaked/double-released slots.
func (c *Coordinator) clientCapacityLocked(pair PairKey, limit int, now time.Time) error {
	for _, member := range []string{pair.MemberAID, pair.MemberBID} {
		used := 0
		for key, t := range c.pairs {
			if key == pair || key.NetworkID != pair.NetworkID ||
				(key.MemberAID != member && key.MemberBID != member) {
				continue
			}
			if clientInFlight(t, now) {
				used++
			}
		}
		if used >= limit {
			return fmt.Errorf("%w: network=%s member=%s active=%d limit=%d", ErrNegotiationCapacity, pair.NetworkID, member, used, limit)
		}
	}
	return nil
}

func (c *Coordinator) clientRequest(s Scope, member string, r *fb.WGPathRequestT, limit int, now time.Time) ([]PairKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateScope(s); err != nil {
		return nil, err
	}
	t := c.pairs[s.Pair]
	old := &fb.WGPathPlanT{} // first proposal has no observed command or path
	var evicted []PairKey
	if t != nil {
		old = t.state.Plan
		if !lightContextMatches(old, s) {
			return nil, fmt.Errorf("WG membership/policy changed; refresh pair")
		}
		// Restoration cannot replace an established mode. First arrival wins:
		// losing requests follow the unchanged operation in their receipt.
		if (r.Kind == fb.WGPathRequestKindSYNC_MODE && old.ModeSetting != nil) || clientInFlight(t, now) {
			return nil, nil
		}
	}
	target := r.RequestedPath
	setting := cloneMode(old.ModeSetting)
	if r.Kind == fb.WGPathRequestKindSWITCH_PATH {
		if (setting != nil && setting.Mode != fb.WGPathTypeUNKNOWN) || r.ObservedCommandId != old.CommandId {
			return nil, fmt.Errorf("stale WG Auto proposal or manual mode selected")
		}
	} else if r.Kind == fb.WGPathRequestKindSYNC_MODE {
		// A one-shot saved preference may initialize an empty authority. It
		// cannot overwrite a user decision or a previously restored setting.
		setting = &fb.WGPathModeSettingT{Mode: r.LocalMode.Mode, DecisionId: uuid.NewString(), Reason: fb.WGPathModeReasonRESTORED}
		target = setting.Mode
	} else {
		setting = &fb.WGPathModeSettingT{Mode: r.RequestedPath, DecisionId: uuid.NewString(), Reason: fb.WGPathModeReasonUSER, RequestedByMemberId: member, RequestId: r.RequestId}
	}
	if target == fb.WGPathTypeUNKNOWN {
		target = old.CommittedPath
		if target == fb.WGPathTypeUNKNOWN {
			target = r.TargetPath
		}
	}
	if target != fb.WGPathTypeDIRECT && target != fb.WGPathTypeRELAY {
		return nil, fmt.Errorf("WG proposal needs initial concrete path")
	}
	if err := c.clientCapacityLocked(s.Pair, limit, now); err != nil {
		return nil, err
	}
	p, err := c.newPlan(s, old.CommittedPath)
	if err != nil {
		return nil, err
	}
	p.ModeSetting, p.TargetPath = setting, target
	if t == nil && len(c.pairs) >= c.maxPairs {
		// Do not evict a retained context for a request that failed validation,
		// capacity admission or authority revision allocation above.
		evicted = c.evictRetainedLocked(now)
		if len(c.pairs) >= c.maxPairs {
			return evicted, fmt.Errorf("WG pair quota reached")
		}
	}
	// Allocate only after admission and complete proposal validation, so a
	// rejected first request cannot leave a phantom pair or spend a revision.
	if t == nil {
		t = &transaction{}
		c.pairs[s.Pair] = t
	}
	t.state = Snapshot{Plan: p}
	t.lastTouched = now
	budget := c.transactionTimeout
	if budget == 0 {
		budget = c.budgets.Prepare + c.budgets.Apply
	}
	t.transactionUntil = now.Add(budget)
	c.enter(t, fb.WGPathPhaseWAITING_READY, now)
	return evicted, nil
}

// evictRetainedLocked removes terminal pair projections only when a new pair
// needs a slot. Active bilateral barriers are never evicted, so maxPairs is a
// memory bound on retained context and not a permanent limit on unique pairs.
// The caller holds c.mu.
func (c *Coordinator) evictRetainedLocked(now time.Time) []PairKey {
	if len(c.pairs) < c.maxPairs {
		return nil
	}
	type candidate struct {
		key PairKey
		at  time.Time
	}
	available := make([]candidate, 0, len(c.pairs))
	for key, t := range c.pairs {
		if t == nil || !clientInFlight(t, now) {
			at := time.Time{}
			if t != nil {
				at = t.lastTouched
			}
			available = append(available, candidate{key: key, at: at})
		}
	}
	if len(available) == 0 {
		return nil
	}
	sort.Slice(available, func(i, j int) bool {
		if available[i].at.Equal(available[j].at) {
			if available[i].key.NetworkID != available[j].key.NetworkID {
				return available[i].key.NetworkID < available[j].key.NetworkID
			}
			if available[i].key.MemberAID != available[j].key.MemberAID {
				return available[i].key.MemberAID < available[j].key.MemberAID
			}
			return available[i].key.MemberBID < available[j].key.MemberBID
		}
		return available[i].at.Before(available[j].at)
	})
	// clientRequest creates one pair at a time, so one terminal context is
	// sufficient. Keeping this loop makes the helper correct if admission is
	// later extended to batch requests.
	evicted := make([]PairKey, 0, 1)
	for _, item := range available {
		if len(c.pairs) < c.maxPairs {
			break
		}
		delete(c.pairs, item.key)
		evicted = append(evicted, item.key)
	}
	return evicted
}

func (o *Owner) handleClientReport(sender types.SessionIdentity, r *fb.WGPathReportT, now time.Time) error {
	pair := PairKey{r.Version.NetworkId, r.Version.MemberAId, r.Version.MemberBId}
	scope, _, err := o.refresh(pair, now)
	if err != nil {
		return err
	}
	member, err := o.registry.AuthenticateMember(pair.NetworkID, sender)
	if err != nil {
		return err
	}
	c := o.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.pairs[pair]
	if t == nil {
		return fmt.Errorf("WG report has no client proposal")
	}
	t.lastTouched = now
	p := t.state.Plan
	index, err := c.sender(scope, member.MemberID, sender.DeviceID, sender.SessionID)
	if err != nil {
		return err
	}
	if r.MemberId != member.MemberID || !reflect.DeepEqual(p.Version, r.Version) || r.CommandId != p.CommandId {
		return fmt.Errorf("stale WG report command/version/member")
	}
	if r.Kind == fb.WGPathReportKindHEALTH {
		return nil
	} // diagnostic only, no decision
	if r.Kind == fb.WGPathReportKindREJECTED {
		if p.Phase == fb.WGPathPhaseCONFIRMED {
			return nil // a delayed earlier failure cannot revoke both APPLIED facts
		}
		t.state.LastError, t.state.LastErrorMessage = r.Error, r.ErrorMessage
		if t.state.LastError == fb.WGPathErrorNONE {
			t.state.LastError = fb.WGPathErrorCONTROL_UNAVAILABLE
		}
		t.state.Deadline = time.Time{}
		t.transactionUntil = time.Time{}
		if p.Phase == fb.WGPathPhaseWAITING_READY {
			p.Phase = fb.WGPathPhaseUNREACHABLE
		}
		return nil // APPLY remains replayable; an error does not undo COMMIT
	}
	if p.Phase == fb.WGPathPhaseCONFIRMED && r.Kind == fb.WGPathReportKindAPPLIED {
		return nil
	}
	if (p.Phase == fb.WGPathPhaseWAITING_READY && r.Kind != fb.WGPathReportKindREADY) || (p.Phase == fb.WGPathPhaseAPPLY && r.Kind != fb.WGPathReportKindAPPLIED) {
		return fmt.Errorf("WG report does not match barrier")
	}
	if p.Phase != fb.WGPathPhaseWAITING_READY && p.Phase != fb.WGPathPhaseAPPLY {
		return fmt.Errorf("WG barrier closed")
	}
	if r.Error != fb.WGPathErrorNONE {
		return fmt.Errorf("WG positive report carries error")
	}
	if p.Phase == fb.WGPathPhaseAPPLY {
		other := scope.Members[1-index]
		owner := other.PublicKey
		if p.TargetPath == fb.WGPathTypeRELAY {
			owner = scope.RelayPublicKey
		}
		if r.ActualPath != p.TargetPath || r.ActualOwnerPublicKey != owner || !ownsHost(r.ActualAllowedIps, other.AssignedIp) || !reflect.DeepEqual(r.AppliedVersion, p.Version) {
			return fmt.Errorf("WG applied report has wrong path/owner/routes/version")
		}
		if p.ModeSetting != nil && !sameMode(p.ModeSetting, r.SavedMode) {
			return fmt.Errorf("WG applied mode not saved")
		}
		t.state.Applied[index] = cloneReport(r)
		t.state.ModeSaved[index] = p.ModeSetting != nil
	}
	t.state.Reports[index] = cloneReport(r)
	if t.state.Reports[0] == nil || t.state.Reports[1] == nil {
		return nil
	}
	if p.Phase == fb.WGPathPhaseWAITING_READY {
		// One common irrevocable decision; no endpoint or probe arbitration here.
		c.enter(t, fb.WGPathPhaseAPPLY, now)
	} else {
		p.CommittedPath = p.TargetPath
		p.Phase = fb.WGPathPhaseCONFIRMED
		p.PhaseTimeoutMs = 0
		t.state.LastError, t.state.LastErrorMessage = fb.WGPathErrorNONE, ""
		t.state.Deadline, t.transactionUntil = time.Time{}, time.Time{}
	}
	return nil
}

func (c *Coordinator) clientTick(t *transaction, now time.Time) {
	if !t.state.Deadline.IsZero() && !now.Before(t.state.Deadline) {
		p := t.state.Plan
		missing := make([]string, 0, 2)
		for i, member := range []string{p.Version.MemberAId, p.Version.MemberBId} {
			if t.state.Reports[i] == nil {
				missing = append(missing, member)
			}
		}
		logger.Warnf("WG path barrier timeout: network=%s pair=%s/%s revision=%d command=%s phase=%s missing_members=%v",
			p.Version.NetworkId, p.Version.MemberAId, p.Version.MemberBId, p.Version.PairRevision, p.CommandId, p.Phase, missing)
		if t.state.Plan.Phase == fb.WGPathPhaseWAITING_READY {
			t.state.Plan.Phase = fb.WGPathPhaseUNREACHABLE
			t.state.LastErrorMessage = "peer not ready; no COMMIT issued"
		} else {
			// Do not undo COMMIT or mint a different command. Late APPLIED may
			// still confirm it until a fresh user/client proposal replaces it.
			t.state.LastErrorMessage = "COMMIT outcome unconfirmed; negotiation gate released"
		}
		t.state.Deadline = time.Time{}
		t.transactionUntil = time.Time{}
		t.state.Plan.PhaseTimeoutMs = 0
		t.state.LastError = fb.WGPathErrorTIMEOUT
	}
}
