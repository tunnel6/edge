package handler

import (
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	logger "icool.io/yat/edge/pkg/log"
)

// HandleEdgeOnline Handle Edge online request
func HandleEdgeOnline(ctx *Context, msg *fbMsg.Message, verifier OwnerVerifier) error {
	logger.Infof("edge online request, session: %s, user: %s", ctx.SessionID, ctx.UserID)

	// Check
	if !verifier.IsEdgeOwner(ctx.UserID) {
		logger.Warnf("edge online denied, user %s is not owner", ctx.UserID)
		return ctx.Protocol.SendEdgeOnlineResponse(ctx.Conn, false, 4001, "permission denied: not edge owner", ctx.SessionID)
	}

	// Execute online operation
	if ctx.Lifecycle == nil {
		logger.Error("controller not available")
		return ctx.Protocol.SendEdgeOnlineResponse(ctx.Conn, false, 5001, "controller not initialized", ctx.SessionID)
	}

	ctx.Lifecycle.MarkOnline()

	logger.Info("edge online success")
	return ctx.Protocol.SendEdgeOnlineResponse(ctx.Conn, true, 0, "", ctx.SessionID)
}

// HandleEdgeOffline Handle Edge offline request
func HandleEdgeOffline(ctx *Context, msg *fbMsg.Message, verifier OwnerVerifier) error {
	logger.Infof("edge offline request, session: %s, user: %s", ctx.SessionID, ctx.UserID)

	// Check
	if !verifier.IsEdgeOwner(ctx.UserID) {
		logger.Warnf("edge offline denied, user %s is not owner", ctx.UserID)
		return ctx.Protocol.SendEdgeOfflineResponse(ctx.Conn, false, 4001, "permission denied: not edge owner", ctx.SessionID)
	}

	// Execute offline operation
	if ctx.Lifecycle == nil {
		logger.Error("controller not available")
		return ctx.Protocol.SendEdgeOfflineResponse(ctx.Conn, false, 5001, "controller not initialized", ctx.SessionID)
	}

	// Mark Edge offline.
	// Server.MarkOffline() handles:
	// 1) Notify and kick all sessions/channels
	// 2) Async notification
	ctx.Lifecycle.MarkOffline()

	logger.Info("edge offline success")
	return ctx.Protocol.SendEdgeOfflineResponse(ctx.Conn, true, 0, "", ctx.SessionID)
}
