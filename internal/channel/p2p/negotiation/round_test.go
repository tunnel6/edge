package negotiation

import (
	"testing"
	"time"
)

func TestBarrierNeedsBothParticipantsInEitherOrder(t *testing.T) {
	context := Context{AttemptID: "attempt-1", Phase: "ready", CommandID: "activate-1"}
	for _, order := range [][2]string{{"a", "b"}, {"b", "a"}} {
		b := NewBarrier(context, [2]string{"a", "b"})
		first := b.Observe(context, order[0], true)
		if !first.Accepted || first.Complete() {
			t.Fatalf("one participant completed barrier: %+v", first)
		}
		duplicate := b.Observe(context, order[0], true)
		if duplicate != first {
			t.Fatalf("duplicate changed evidence: %+v -> %+v", first, duplicate)
		}
		failure := b.Observe(context, order[0], false)
		if failure != first {
			t.Fatal("a failure erased collected success")
		}
		if !b.Observe(context, order[1], true).Complete() {
			t.Fatal("both participants did not complete barrier")
		}
	}
}

func TestReplacedRoundCannotInheritForeignEvidence(t *testing.T) {
	current := Context{AttemptID: "new", Phase: "verify", CommandID: "verify-2"}
	b := NewBarrier(current, [2]string{"a", "b"})
	for _, context := range []Context{
		{AttemptID: "old", Phase: current.Phase, CommandID: current.CommandID},
		{AttemptID: current.AttemptID, Phase: "apply", CommandID: current.CommandID},
		{AttemptID: current.AttemptID, Phase: current.Phase, CommandID: "verify-1"},
	} {
		if got := b.Observe(context, "a", true); got.Accepted || got.Succeeded != [2]bool{} {
			t.Fatalf("foreign context accepted: %+v", got)
		}
	}
	if got := b.Observe(current, "outsider", true); got.Accepted || got.Participant != -1 {
		t.Fatalf("unknown participant accepted: %+v", got)
	}
	if b.Observe(current, "b", true).Complete() {
		t.Fatal("rejected reports contributed evidence")
	}
	if !b.Observe(current, "a", true).Complete() {
		t.Fatal("current reports did not complete barrier")
	}
	if b.Observe(current, "outsider", true).Complete() {
		t.Fatal("rejected report inherited a completed barrier action")
	}
	// Replacing a phase, even with the same participants, starts with no evidence.
	current.CommandID = "verify-3"
	b = NewBarrier(current, [2]string{"a", "b"})
	if b.Observe(current, "a", true).Complete() {
		t.Fatal("replacement inherited previous participant success")
	}
}

func TestWindowKeepsDeadlineAndFiltersStaleTimeout(t *testing.T) {
	context := Context{AttemptID: "attempt", Phase: "prepare", CommandID: "prepare-1"}
	started := time.Unix(100, 0)
	w := NewWindow(context, started, 10*time.Second)
	// Model three retransmissions against one accepted phase window.
	for _, elapsed := range []time.Duration{0, 3 * time.Second, 9 * time.Second} {
		if got := w.Remaining(started.Add(elapsed)); got != 10*time.Second-elapsed {
			t.Fatalf("deadline moved on retransmit: remaining=%s", got)
		}
		if w.Due(context, started.Add(elapsed)) {
			t.Fatal("timeout before deadline")
		}
	}
	deadline := started.Add(10 * time.Second)
	if !w.Due(context, deadline) || w.Remaining(deadline.Add(time.Hour)) != 0 {
		t.Fatal("deadline did not expire")
	}
	for _, stale := range []Context{
		{AttemptID: "replacement", Phase: context.Phase, CommandID: context.CommandID},
		{AttemptID: context.AttemptID, Phase: "execute", CommandID: context.CommandID},
		{AttemptID: context.AttemptID, Phase: context.Phase, CommandID: "prepare-2"},
	} {
		if w.Due(stale, deadline.Add(time.Hour)) {
			t.Fatalf("old timeout matched new context: %+v", stale)
		}
	}
	if !NewWindow(context, started, -time.Second).Due(context, started) {
		t.Fatal("nonpositive timeout must already be due")
	}
	var empty Window
	if empty.Due(Context{}, deadline) {
		t.Fatal("uninitialized window produced a timeout")
	}
	var barrier Barrier
	if barrier.Observe(Context{}, "", true).Accepted {
		t.Fatal("uninitialized barrier accepted evidence")
	}
}
