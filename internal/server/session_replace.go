package server

import (
	logger "icool.io/yat/edge/pkg/log"
)

// publishClientSession atomically replaces the device-indexed session.
// If an older session exists for the same device, it is locked, closed, and
// superseded.  The caller holds deviceSessionMu on the NEW session via
// addSessionState, so concurrent Add calls serialise safely.
// Physical TLS cleanup of the retired session is returned to the caller and
// runs outside all source/session locks.
func (sm *SessionManager) publishClientSession(session *Session) *Session {
	for {
		value, loaded := sm.clientSessions.LoadOrStore(session.DeviceID, session)
		if !loaded || value == session {
			return nil
		}
		old := value.(*Session)
		old.deviceSessionMu.Lock()
		current, ok := sm.clientSessions.Load(session.DeviceID)
		if !ok || current != old {
			old.deviceSessionMu.Unlock()
			continue
		}
		logger.Infof("[SessionMgr] closing stale session for device %s: old=%s new=%s", session.DeviceID, old.ID, session.ID)
		closed := old.closeState()
		sm.clientSessions.Store(session.DeviceID, session)
		old.deviceSessionMu.Unlock()
		if closed {
			return old
		}
		return nil
	}
}
