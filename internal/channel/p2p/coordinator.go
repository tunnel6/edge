package p2p

import (
	"sync"
)

type TransitionEvent struct {
	SessionID string
	OldState  SessionStatus
	NewState  SessionStatus
	Session   *Session
}

type TransitionObserver func(event TransitionEvent)

type Coordinator struct {
	mu              sync.RWMutex
	adapter         Adapter
	tracker         *StatusTracker
	observer        TransitionObserver
	snapMu          sync.RWMutex
	snapshots       map[string]*Session
	retiredNetworks map[string]bool // sticky; protected by snapMu
}

func NewCoordinator(adapter Adapter) *Coordinator {
	return &Coordinator{
		adapter:   adapter,
		tracker:   NewStatusTracker(),
		snapshots: make(map[string]*Session),
	}
}

func (c *Coordinator) SetAdapter(adapter Adapter) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.adapter = adapter
}

func (c *Coordinator) SetTransitionObserver(observer TransitionObserver) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observer = observer
}

func (c *Coordinator) currentAdapter() Adapter {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.adapter
}

func (c *Coordinator) OnSessionCreated(session *Session) error {
	if c == nil || session == nil {
		return nil
	}
	if _, accepted := c.recordSession(session); !accepted {
		return nil
	}
	adapter := c.currentAdapter()
	if adapter == nil {
		return nil
	}
	return adapter.OnSessionCreated(session)
}

func (c *Coordinator) OnSessionStateChange(session *Session) error {
	if c == nil || session == nil {
		return nil
	}
	session = c.mergeSessionPolicyFromTracked(session)
	if session == nil {
		return nil
	}

	newState := session.Status
	oldState, accepted := c.recordSession(session)
	if !accepted {
		return nil
	}

	if adapter := c.currentAdapter(); adapter != nil && adapter.HasSession(session.ID) {
		if err := adapter.OnStateTransition(session.ID, oldState, newState); err != nil {
			return err
		}
	}

	if observer := c.currentObserver(); observer != nil {
		observer(TransitionEvent{
			SessionID: session.ID,
			OldState:  oldState,
			NewState:  newState,
			Session:   cloneSessionSnapshot(session),
		})
	}

	if c.tracker != nil {
		switch session.Status {
		case SessionStatusClosed, SessionStatusFailed:
			c.tracker.Delete(session.ID)
			c.deleteSnapshot(session.ID)
		}
	}

	return nil
}

func (c *Coordinator) mergeSessionPolicyFromTracked(session *Session) *Session {
	if c == nil || session == nil {
		return session
	}
	merged := cloneSessionSnapshot(session)
	if len(merged.PreferredLinks) > 0 {
		return merged
	}
	tracked, ok := c.GetSessionSnapshot(session.ID)
	if !ok || tracked == nil {
		return merged
	}
	merged.PreferredLinks = append([]string(nil), tracked.PreferredLinks...)
	merged.AllowRelayFallback = tracked.AllowRelayFallback
	merged.RequireDirect = tracked.RequireDirect
	return merged
}

func (c *Coordinator) UpdateClientInfo(sessionID, clientID string, info *ClientInfo) error {
	adapter := c.currentAdapter()
	if adapter == nil {
		return nil
	}
	return adapter.UpdateClientInfo(sessionID, clientID, info)
}

func (c *Coordinator) HasAdapter() bool {
	return c.currentAdapter() != nil
}

func (c *Coordinator) currentObserver() TransitionObserver {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.observer
}

func (c *Coordinator) GetSessionStatus(sessionID string) (SessionStatus, bool) {
	if c == nil || c.tracker == nil {
		return SessionStatusNew, false
	}
	return c.tracker.Get(sessionID)
}

func (c *Coordinator) SnapshotSessionStatuses() map[string]SessionStatus {
	if c == nil || c.tracker == nil {
		return nil
	}
	return c.tracker.Snapshot()
}

func cloneSessionSnapshot(src *Session) *Session {
	if src == nil {
		return nil
	}
	copy := *src
	if len(src.PreferredLinks) > 0 {
		copy.PreferredLinks = append([]string(nil), src.PreferredLinks...)
	}
	return &copy
}

// RetireNetwork prevents queued callbacks from republishing obsolete state.
// Adapter and user callbacks are never called while a projection lock is held.
// An adapter that performs side effects must fence/drain those independently.
func (c *Coordinator) RetireNetwork(networkID string) {
	if c == nil || networkID == "" {
		return
	}
	c.snapMu.Lock()
	if c.retiredNetworks == nil {
		c.retiredNetworks = make(map[string]bool)
	}
	c.retiredNetworks[networkID] = true
	for id, session := range c.snapshots {
		if session.NetworkID == networkID {
			delete(c.snapshots, id)
			if c.tracker != nil {
				c.tracker.Delete(id)
			}
		}
	}
	c.snapMu.Unlock()
	if adapter, ok := c.currentAdapter().(interface{ RetireNetwork(string) }); ok {
		adapter.RetireNetwork(networkID)
	}
}

func (c *Coordinator) recordSession(session *Session) (SessionStatus, bool) {
	if c == nil || session == nil || session.ID == "" {
		// Preserve adapter validation of malformed IDs.
		return SessionStatusNew, true
	}
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	if c.retiredNetworks[session.NetworkID] {
		return SessionStatusNew, false
	}
	old := SessionStatusNew
	if c.tracker != nil {
		old, _ = c.tracker.Upsert(session.ID, session.Status)
	}
	c.snapshots[session.ID] = cloneSessionSnapshot(session)
	return old, true
}

func (c *Coordinator) deleteSnapshot(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	delete(c.snapshots, sessionID)
}

func (c *Coordinator) GetSessionSnapshot(sessionID string) (*Session, bool) {
	if c == nil || sessionID == "" {
		return nil, false
	}
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	session, ok := c.snapshots[sessionID]
	if !ok || session == nil {
		return nil, false
	}
	return cloneSessionSnapshot(session), true
}

func (c *Coordinator) SnapshotSessions() map[string]*Session {
	if c == nil {
		return nil
	}
	c.snapMu.RLock()
	defer c.snapMu.RUnlock()
	out := make(map[string]*Session, len(c.snapshots))
	for sessionID, session := range c.snapshots {
		out[sessionID] = cloneSessionSnapshot(session)
	}
	return out
}
