package pathcoord

import (
	"sort"
	"time"

	fb "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/types"
)

// RuntimePairs returns detached read models for the authenticated member only.
// Reading never admits a pair, advances a command, or refreshes a deadline.
// The two evidence slots show current reports, falling back to versioned
// native application facts. CONFIRMED keeps the bilateral APPLIED reports.
func (o *Owner) RuntimePairs(networkID string, sender types.SessionIdentity, now time.Time) ([]*fb.WGPathPairRuntimeInfoT, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return nil, err
	}
	binding, err := o.registry.Bootstrap(networkID, sender)
	if err != nil {
		return nil, err
	}
	var pairs []*fb.WGPathPairRuntimeInfoT
	keys := make([]PairKey, 0, len(o.pairs))
	for key := range o.pairs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].MemberAID != keys[j].MemberAID {
			return keys[i].MemberAID < keys[j].MemberAID
		}
		return keys[i].MemberBID < keys[j].MemberBID
	})
	for _, key := range keys {
		if key.NetworkID != networkID || (key.MemberAID != binding.Member.MemberID && key.MemberBID != binding.Member.MemberID) {
			continue
		}
		scope, err := o.registry.Scope(key)
		if err != nil {
			continue
		}
		snapshot, ok := o.coordinator.Snapshot(key)
		if !ok || !lightContextMatches(snapshot.Plan, scope) {
			continue
		}
		reports := snapshot.Reports
		for i := range reports {
			if reports[i] == nil {
				reports[i] = snapshot.Applied[i]
			}
		}
		pairs = append(pairs, &fb.WGPathPairRuntimeInfoT{Plan: snapshot.Plan, ReportA: reports[0], ReportB: reports[1],
			LastError: snapshot.LastError, LastErrorMessage: snapshot.LastErrorMessage,
			ModeSavedA: snapshot.ModeSaved[0], ModeSavedB: snapshot.ModeSaved[1]})
	}
	return pairs, nil
}
