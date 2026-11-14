package types

// SessionIdentity is an immutable snapshot of session identity fields.
//
// It is captured once at handler-dispatch time from server.Session and
// embedded (by value) into both channel.HandlerContext and
// server/handler.Context.  This eliminates the field-level duplication
// that previously existed between the two context types while avoiding
// a circular import (channel cannot import server).
//
// Fields are intentionally plain (no mutex): the snapshot is taken
// under the session lock and is read-only afterwards.
type SessionIdentity struct {
	SessionID    string
	UserID       string
	DeviceID     string
	Hostname     string
	Capabilities []string
	// ScopeClaims are certificate-embedded scope restrictions extracted
	// from the yat-scope X.509 extension. nil = no restriction (full access).
	ScopeClaims []string
}

// CurrentClientSessionReader resolves the live authenticated connection for a
// device. A connection supplied by a message must never register itself as
// current. Implementations return owned slices and exclude closed sessions.
type CurrentClientSessionReader interface {
	CurrentClientSession(deviceID string) (SessionIdentity, bool)
}

// ClientSessionMutationSource optionally binds the real control source to one
// authority. Mutations enter this gate before session/index locks and release
// those locks before returning. The callback covers memory facts only: no socket
// close, pushes, manager callbacks or reentry. Detach waits for current mutations
// and must not remove a later binding. Binding itself grants no capability.
// A bound gate must execute each change exactly once, including after its Owner
// stops; source management remains available independently of coordination.
type ClientSessionMutationSource interface {
	BindClientSessionMutations(gate func(change func() error) error) (detach func(), err error)
}
