package pathcoord

import (
	"fmt"
	"reflect"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

// HandlePathControl dispatches to type-specific handlers.
func (o *Owner) HandlePathControl(sender types.SessionIdentity, message ControlMessage) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return err
	}
	count, network := 0, ""
	if message.Runtime != nil {
		count++
		network = message.Runtime.NetworkId
	}
	if message.Report != nil {
		count++
		if message.Report.Version != nil {
			network = message.Report.Version.NetworkId
		}
	}
	if message.Request != nil {
		count++
		network = message.Request.NetworkId
	}
	if count != 1 {
		return fmt.Errorf("WG control needs exactly one body")
	}
	now := o.config.Now()
	member, err := o.registry.AuthenticateMember(network, sender)
	if err != nil {
		return err
	}
	switch {
	case message.Runtime != nil:
		return o.handleRuntimeLocked(sender, message.Runtime)
	case message.Report != nil:
		return o.handleReportLocked(sender, message.Report, now)
	case message.Request != nil:
		return o.handleRequestLocked(sender, member, message.Request, now)
	default:
		return fmt.Errorf("empty WG control message")
	}
}

// handleRuntimeLocked registers the member's runtime data (candidates, endpoints).
// Pair creation is deferred to REQUEST time.
func (o *Owner) handleRuntimeLocked(sender types.SessionIdentity, runtime *fb.WGPathRuntimeReportT) error {
	binding, err := o.registry.Bootstrap(runtime.NetworkId, sender)
	if err != nil {
		return err
	}
	if runtime.AuthorityEpoch != o.coordinator.epoch ||
		runtime.NetworkPolicyRevision != binding.Network.PolicyRevision {
		return fmt.Errorf("stale WG runtime authority/policy; refresh bootstrap")
	}
	if _, err := o.registry.Register(sender, runtime); err != nil {
		return err
	}
	return nil
}

// handleReportLocked processes plan acknowledgments and health responses under the owner lock.
func (o *Owner) handleReportLocked(sender types.SessionIdentity, report *fb.WGPathReportT, now time.Time) error {
	if report != nil && report.Version != nil {
		pair := PairKey{report.Version.NetworkId, report.Version.MemberAId, report.Version.MemberBId}
		if o.pairs[pair] != nil {
			return o.handleClientReport(sender, report, now)
		}
	}
	return fmt.Errorf("WG report has no current pair")
}

// handleRequestLocked processes mode change requests under the owner lock.
// Pairs are created on-demand when the first REQUEST arrives.
func (o *Owner) handleRequestLocked(sender types.SessionIdentity, member Membership, request *fb.WGPathRequestT, now time.Time) error {
	if err := ValidateRequest(request); err != nil {
		return err
	}
	if request.ObservedAuthorityEpoch != o.coordinator.epoch {
		return fmt.Errorf("stale WG request authority; refresh bootstrap")
	}
	pair, err := NewPairKey(request.NetworkId, member.MemberID, request.PeerMemberId)
	if err != nil {
		return err
	}
	var scope Scope
	state := o.pairs[pair]
	if state == nil {
		scope, err = o.registry.Scope(pair)
	} else {
		scope, _, err = o.refresh(pair, now)
	}
	if err != nil {
		return err
	}
	if scope.RelayMode != fb.WGRelayModeOPTIONAL {
		return fmt.Errorf("WG pair switching requires optional relay mode")
	}
	if state == nil {
		state = &ownedPair{}
	}
	for _, prior := range state.clientRequests {
		if prior.member == member.MemberID && prior.request.RequestId == request.RequestId {
			if !reflect.DeepEqual(prior.request, request) {
				return fmt.Errorf("conflicting WG request replay")
			}
			return nil
		}
	}
	evicted, err := o.coordinator.clientRequest(scope, member.MemberID, request, o.config.ControlBurst, now)
	if err != nil {
		return err
	}
	for _, evictedPair := range evicted {
		delete(o.pairs, evictedPair)
	}
	o.pairs[pair] = state
	copy := *request
	copy.LocalMode = cloneMode(request.LocalMode)
	state.clientRequests = append(state.clientRequests, clientRequest{member.MemberID, &copy})
	if len(state.clientRequests) > retainedModeRequests {
		state.clientRequests = state.clientRequests[1:]
	}
	return nil
}
