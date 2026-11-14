// Package negotiation contains transport-independent two-party coordination
// primitives. The owning adapter serializes access, authenticates participants,
// validates its full product context, and decides transitions and fallback.
// This package performs no I/O, schedules no work, and owns no goroutines.
package negotiation

import "time"

// Context identifies one execution phase. AttemptID must distinguish replaced
// attempts; CommandID distinguishes commands within an attempt when the wire
// protocol provides one. These opaque IDs do not replace membership, authority,
// candidate or runtime validation in an adapter.
type Context struct {
	AttemptID string
	Phase     string
	CommandID string
}

// Barrier collects successful reports from two fixed participants. A failure
// does not erase a success: deciding whether to abort is adapter policy. The
// adapter must supply validated participant IDs, in its own role order.
type Barrier struct {
	context      Context
	participants [2]string
	succeeded    [2]bool
	initialized  bool
}

func NewBarrier(context Context, participants [2]string) Barrier {
	return Barrier{context: context, participants: participants, initialized: true}
}

type Observation struct {
	Accepted    bool
	Participant int // 0 or 1 when accepted, otherwise -1
	Succeeded   [2]bool
}

func (o Observation) Complete() bool { return o.Accepted && o.Succeeded[0] && o.Succeeded[1] }

// Observe ignores foreign phases/attempts and unknown participants. Duplicate
// successes are idempotent. It does not check the wall clock; the owner decides
// ordering between reports and timeout events using its current phase.
func (b *Barrier) Observe(context Context, participant string, success bool) Observation {
	o := Observation{Participant: -1, Succeeded: b.succeeded}
	if !b.initialized || context != b.context {
		return o
	}
	for index, expected := range b.participants {
		if participant == expected {
			if success {
				b.succeeded[index] = true
			}
			return Observation{Accepted: true, Participant: index, Succeeded: b.succeeded}
		}
	}
	return o
}

// Window is an immutable phase deadline. Retransmission must reuse the same
// Window rather than constructing another and extending the attempt.
type Window struct {
	context     Context
	deadline    time.Time
	initialized bool
}

func NewWindow(context Context, started time.Time, duration time.Duration) Window {
	return Window{context: context, deadline: started.Add(duration), initialized: true}
}

func (w Window) Remaining(now time.Time) time.Duration {
	if !w.initialized || !now.Before(w.deadline) {
		return 0
	}
	return w.deadline.Sub(now)
}

// Due filters a timeout captured by an old execution phase. A timeout event is
// not itself a path failure; the adapter applies its transport/product policy.
func (w Window) Due(current Context, now time.Time) bool {
	return w.initialized && current == w.context && !now.Before(w.deadline)
}
