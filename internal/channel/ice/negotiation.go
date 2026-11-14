package ice

import (
	"time"

	"icool.io/yat/edge/internal/channel/p2p/negotiation"
)

// ICE has one random session ID per attempt and no per-command wire ID. WG's
// adapter will use its own authorized command/version context instead.
func (s *Session) negotiationContext(phase State) negotiation.Context {
	return negotiation.Context{AttemptID: s.ID, Phase: string(phase)}
}

type punchObservation struct {
	role      string
	succeeded [2]bool
	startedAt time.Time
}

func (s *Session) recordPunchResult(sender string, result *PunchResult) punchObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PunchResult = result
	// Preserve ICE's legacy diagnostic collection outside StatePunching. The
	// controller still guards transitions and late failures. In particular this
	// extraction does not change its unknown-sender failure/fallback behavior.
	o := s.punchBarrier.Observe(s.negotiationContext(StatePunching), sender, result.Success)
	role := "unknown"
	if o.Accepted {
		if o.Participant == 0 {
			role = "pub"
		} else {
			role = "con"
		}
	}
	return punchObservation{role: role, succeeded: o.Succeeded, startedAt: s.UpdatedAt}
}

func (s *Session) phaseWindow(phase State, duration time.Duration) negotiation.Window {
	return negotiation.NewWindow(s.negotiationContext(phase), time.Now(), duration)
}

func (s *Session) phaseTimeoutDue(window negotiation.Window, now time.Time) bool {
	return window.Due(s.negotiationContext(s.GetState()), now)
}

// Called by existing ICE execution goroutines, after sending the phase's
// messages just as before extraction. It creates no independent scheduler.
func (c *Controller) waitPhaseTimeout(s *Session, phase State, duration time.Duration) bool {
	window := s.phaseWindow(phase, duration)
	timer := time.NewTimer(window.Remaining(time.Now()))
	defer timer.Stop()
	select {
	case <-timer.C:
		return s.phaseTimeoutDue(window, time.Now())
	case <-c.stopCh:
		return false
	}
}
