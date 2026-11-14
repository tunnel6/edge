package p2p

type Adapter interface {
	OnSessionCreated(session *Session) error
	OnStateTransition(sessionID string, oldState, newState SessionStatus) error
	UpdateClientInfo(sessionID, clientID string, info *ClientInfo) error
	HasSession(sessionID string) bool
}
