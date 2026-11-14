package server

import "icool.io/yat/edge/internal/upstream/certmgr"

// Owner decisions are bound to this authenticated session, not a shared user ID.
type sessionOwnerVerifier struct{ session *Session }

func (v sessionOwnerVerifier) IsEdgeOwner(userID string) bool {
	return v.session != nil && v.session.UserID == userID && v.session.Role == certmgr.RoleOwner
}
