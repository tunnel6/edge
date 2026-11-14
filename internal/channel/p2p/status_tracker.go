package p2p

import "sync"

type StatusTracker struct {
	mu     sync.RWMutex
	states map[string]SessionStatus
}

func NewStatusTracker() *StatusTracker {
	return &StatusTracker{
		states: make(map[string]SessionStatus),
	}
}

func (t *StatusTracker) Upsert(sessionID string, newState SessionStatus) (oldState SessionStatus, changed bool) {
	if t == nil || sessionID == "" {
		return SessionStatusNew, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	old, exists := t.states[sessionID]
	if !exists {
		old = SessionStatusNew
	}
	t.states[sessionID] = newState
	return old, !exists || old != newState
}

func (t *StatusTracker) Delete(sessionID string) {
	if t == nil || sessionID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, sessionID)
}

func (t *StatusTracker) Get(sessionID string) (SessionStatus, bool) {
	if t == nil || sessionID == "" {
		return SessionStatusNew, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	state, ok := t.states[sessionID]
	return state, ok
}

func (t *StatusTracker) Snapshot() map[string]SessionStatus {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]SessionStatus, len(t.states))
	for k, v := range t.states {
		out[k] = v
	}
	return out
}
