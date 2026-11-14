package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	"icool.io/yat/edge/internal/tunnelpolicy"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	tunnelRequestTimeout = 5 * time.Second
	tunnelConflictCode   = 409
)

func (s *Server) handleTunnelSyncRequest(session *Session, msg *fbMsg.Message) error {
	reqStartedAt := time.Now()
	reqSeq := uint32(0)
	if header := msg.Header(nil); header != nil {
		reqSeq = header.Seq()
	}

	if strings.TrimSpace(session.UserID) == "" {
		logger.Warnf(
			"[TunnelSync] reject unauthenticated request: session=%s seq=%d",
			session.ID,
			reqSeq,
		)
		return session.Protocol.SendTunnelSyncResponse(
			session.Conn,
			false,
			true,
			0,
			false,
			nil,
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			"missing session user_id",
			session.ID,
		)
	}

	req := new(fbMsg.TunnelSyncRequest)
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return session.Protocol.SendTunnelSyncResponse(
			session.Conn,
			false,
			true,
			0,
			false,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"invalid tunnel sync request body",
			session.ID,
		)
	}
	req.Init(table.Bytes, table.Pos)
	logger.Infof(
		"[TunnelSync] recv request: session=%s seq=%d user=%s edge=%s since=%d limit=%d includeDeleted=%v",
		session.ID,
		reqSeq,
		strings.TrimSpace(session.UserID),
		strings.TrimSpace(string(req.EdgeId())),
		req.SinceRevision(),
		req.Limit(),
		req.IncludeDeleted(),
	)

	scopeEdgeID, err := s.resolveTunnelScopeEdgeID(string(req.EdgeId()))
	if err != nil {
		logger.Warnf(
			"[TunnelSync] invalid edge scope: session=%s seq=%d edge=%s err=%v",
			session.ID,
			reqSeq,
			strings.TrimSpace(string(req.EdgeId())),
			err,
		)
		return session.Protocol.SendTunnelSyncResponse(
			session.Conn,
			false,
			req.SinceRevision() == 0,
			req.SinceRevision(),
			false,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			err.Error(),
			session.ID,
		)
	}

	store := s.getTunnelDefinitionStore()
	if store == nil {
		logger.Errorf(
			"[TunnelSync] tunnel store unavailable: session=%s seq=%d edge=%s",
			session.ID,
			reqSeq,
			scopeEdgeID,
		)
		return session.Protocol.SendTunnelSyncResponse(
			session.Conn,
			false,
			req.SinceRevision() == 0,
			req.SinceRevision(),
			false,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			"tunnel store unavailable",
			session.ID,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunnelRequestTimeout)
	defer cancel()

	queryStartedAt := time.Now()
	records, nextRevision, hasMore, err := store.ListChanges(
		ctx,
		session.UserID,
		scopeEdgeID,
		req.SinceRevision(),
		req.Limit(),
		req.IncludeDeleted(),
	)
	queryElapsed := time.Since(queryStartedAt)
	if err != nil {
		logger.Errorf(
			"[TunnelSync] list changes failed: session=%s seq=%d edge=%s since=%d limit=%d includeDeleted=%v elapsed=%s err=%v",
			session.ID,
			reqSeq,
			scopeEdgeID,
			req.SinceRevision(),
			req.Limit(),
			req.IncludeDeleted(),
			queryElapsed,
			err,
		)
		return session.Protocol.SendTunnelSyncResponse(
			session.Conn,
			false,
			req.SinceRevision() == 0,
			req.SinceRevision(),
			false,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("sync tunnel definitions failed: %v", err),
			session.ID,
		)
	}

	definitions := make([]*fbMsg.TunnelDefinitionInfoT, 0, len(records))
	for _, rec := range records {
		if s.rewriteTunnelPeerSessionsFromEdgeObservation(rec) {
			if err := store.Upsert(ctx, rec); err != nil {
				logger.Warnf(
					"[TunnelSync] persist rewritten peer sessions failed: session=%s edge=%s tunnel=%s err=%v",
					session.ID,
					scopeEdgeID,
					rec.TunnelID,
					err,
				)
			}
		}
		if rec.Revision > int64(nextRevision) {
			nextRevision = uint64(rec.Revision)
		}
		definitions = append(definitions, tunnelDefinitionInfoFromRecord(rec))
	}

	sendErr := session.Protocol.SendTunnelSyncResponse(
		session.Conn,
		true,
		req.SinceRevision() == 0,
		nextRevision,
		hasMore,
		definitions,
		0,
		"",
		session.ID,
	)
	totalElapsed := time.Since(reqStartedAt)
	if sendErr != nil {
		logger.Errorf(
			"[TunnelSync] send response failed: session=%s seq=%d edge=%s defs=%d next=%d hasMore=%v queryElapsed=%s totalElapsed=%s err=%v",
			session.ID,
			reqSeq,
			scopeEdgeID,
			len(definitions),
			nextRevision,
			hasMore,
			queryElapsed,
			totalElapsed,
			sendErr,
		)
		return sendErr
	}

	logger.Infof(
		"[TunnelSync] response sent: session=%s seq=%d edge=%s defs=%d next=%d hasMore=%v queryElapsed=%s totalElapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		len(definitions),
		nextRevision,
		hasMore,
		queryElapsed,
		totalElapsed,
	)
	return nil
}

func (s *Server) handleTunnelUpsertRequest(session *Session, msg *fbMsg.Message) error {
	reqStartedAt := time.Now()
	reqSeq := uint32(0)
	if header := msg.Header(nil); header != nil {
		reqSeq = header.Seq()
	}
	if strings.TrimSpace(session.UserID) == "" {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			"missing session user_id",
			session.ID,
		)
	}

	req := new(fbMsg.TunnelUpsertRequest)
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"invalid tunnel upsert request body",
			session.ID,
		)
	}
	req.Init(table.Bytes, table.Pos)

	definition := req.Definition(nil)
	if definition == nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"missing tunnel definition",
			session.ID,
		)
	}

	scopeEdgeID, err := s.resolveTunnelScopeEdgeID(
		firstNonEmpty(string(req.EdgeId()), string(definition.EdgeId())),
	)
	if err != nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			err.Error(),
			session.ID,
		)
	}

	store := s.getTunnelDefinitionStore()
	if store == nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			"tunnel store unavailable",
			session.ID,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunnelRequestTimeout)
	defer cancel()

	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(ctx, session.UserID, scopeEdgeID)
	if err != nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			0,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("read current revision failed: %v", err),
			session.ID,
		)
	}

	tunnelID := strings.TrimSpace(string(definition.TunnelId()))
	if tunnelID == "" {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			currentRevision,
			nil,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"tunnel_id is required",
			session.ID,
		)
	}
	logger.Infof(
		"[TunnelUpsertTrace] recv request: session=%s seq=%d user=%s device=%s edge=%s tunnel=%s ifMatch=%d elapsed=%s",
		session.ID,
		reqSeq,
		session.UserID,
		session.DeviceID,
		scopeEdgeID,
		tunnelID,
		req.IfMatchRevision(),
		time.Since(reqStartedAt),
	)

	existing, err := store.Get(ctx, session.UserID, scopeEdgeID, tunnelID)
	if err != nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			currentRevision,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("load tunnel definition failed: %v", err),
			session.ID,
		)
	}
	logger.Debugf(
		"[TunnelUpsertTrace] store get completed: session=%s seq=%d edge=%s tunnel=%s hasExisting=%t elapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		tunnelID,
		existing != nil,
		time.Since(reqStartedAt),
	)

	shouldCheckLimit := existing == nil || existing.DeletedAt != nil
	if shouldCheckLimit {
		maxPerSession := s.config.GetTunnelMaxPerSession()
		if maxPerSession > 0 {
			ownerCount, err := store.CountActiveByEdgeAndOwner(ctx, scopeEdgeID, session.UserID)
			if err != nil {
				return session.Protocol.SendTunnelUpsertResponse(
					session.Conn,
					false,
					false,
					currentRevision,
					nil,
					uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
					fmt.Sprintf("count owner tunnels failed: %v", err),
					session.ID,
				)
			}
			if ownerCount >= maxPerSession {
				return session.Protocol.SendTunnelUpsertResponse(
					session.Conn,
					false,
					false,
					currentRevision,
					nil,
					uint32(fbMsg.ErrorCodeTUNNEL_LIMIT_EXCEEDED),
					fmt.Sprintf("tunnel limit exceeded per session: %d/%d", ownerCount, maxPerSession),
					session.ID,
				)
			}
		}

		maxTotal := s.config.GetTunnelMaxTotal()
		if maxTotal > 0 {
			totalCount, err := store.CountActiveByEdge(ctx, scopeEdgeID)
			if err != nil {
				return session.Protocol.SendTunnelUpsertResponse(
					session.Conn,
					false,
					false,
					currentRevision,
					nil,
					uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
					fmt.Sprintf("count edge tunnels failed: %v", err),
					session.ID,
				)
			}
			if totalCount >= maxTotal {
				return session.Protocol.SendTunnelUpsertResponse(
					session.Conn,
					false,
					false,
					currentRevision,
					nil,
					uint32(fbMsg.ErrorCodeTUNNEL_LIMIT_EXCEEDED),
					fmt.Sprintf("tunnel total limit exceeded: %d/%d", totalCount, maxTotal),
					session.ID,
				)
			}
		}
	}
	if req.IfMatchRevision() > 0 && req.IfMatchRevision() != currentRevision {
		if !shouldSkipTunnelUpsertRevisionGuard(req, existing, session.DeviceID) {
			return session.Protocol.SendTunnelUpsertResponse(
				session.Conn,
				false,
				true,
				currentRevision,
				nil,
				tunnelConflictCode,
				"revision conflict",
				session.ID,
			)
		}
	}

	rec := &channel.TunnelDefinitionRecord{
		EdgeID:      scopeEdgeID,
		OwnerUserID: strings.TrimSpace(session.UserID),
		TunnelID:    tunnelID,
		Name:        strings.TrimSpace(string(definition.Name())),
		AppID:       strings.TrimSpace(string(definition.AppId())),
		Protocol:    strings.TrimSpace(string(definition.Protocol())),
		IntentJSON:  string(definition.IntentJson()),
		ConfigJSON:  string(definition.ConfigJson()),
		RuntimeJSON: string(definition.RuntimeJson()),
		State:       strings.TrimSpace(string(definition.State())),
	}
	requestedRole := normalizeTunnelActorRole(definition.ActorRole())
	requestedActorSessionID := firstNonEmpty(string(definition.ActorSessionId()), session.ID)
	requestedActorDeviceID := firstNonEmpty(string(definition.ActorDeviceId()), session.DeviceID)
	actorResolution := resolveTunnelUpsertActorContext(
		existing,
		rec.ConfigJSON,
		requestedRole,
		requestedActorSessionID,
		requestedActorDeviceID,
		session.ID,
		session.DeviceID,
	)
	if !canSessionMutateTunnelDefinition(existing, rec.ConfigJSON, session.DeviceID, actorResolution.TakeoverApplied) {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			currentRevision,
			nil,
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			"permission denied: only publisher/owner can mutate tunnel definition",
			session.ID,
		)
	}
	rec.ActorRole = uint8(actorResolution.Role)
	rec.ActorSessionID = actorResolution.ActorSessionID
	rec.ActorDeviceID = actorResolution.ActorDeviceID
	logger.Infof(
		"[TunnelUpsertActorAudit] edge=%s tunnel=%s user=%s decision=%s requestedRole=%s effectiveRole=%s requestedActorSession=%s requestedActorDevice=%s effectiveActorSession=%s effectiveActorDevice=%s takeover=%t prevOwnerDevice=%s nextOwnerDevice=%s",
		scopeEdgeID,
		tunnelID,
		session.UserID,
		actorResolution.Decision,
		requestedRole.String(),
		actorResolution.Role.String(),
		requestedActorSessionID,
		requestedActorDeviceID,
		actorResolution.ActorSessionID,
		actorResolution.ActorDeviceID,
		actorResolution.TakeoverApplied,
		actorResolution.PreviousOwnerDeviceID,
		actorResolution.NextOwnerDeviceID,
	)
	rewriteStartedAt := time.Now()
	logger.Infof(
		"[TunnelUpsertTrace] rewrite start: session=%s seq=%d edge=%s tunnel=%s totalElapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		tunnelID,
		time.Since(reqStartedAt),
	)
	s.rewriteTunnelPeerSessionsFromEdgeObservation(rec)
	logger.Infof(
		"[TunnelUpsertTrace] rewrite done: session=%s seq=%d edge=%s tunnel=%s elapsed=%s totalElapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		tunnelID,
		time.Since(rewriteStartedAt),
		time.Since(reqStartedAt),
	)
	upsertStartedAt := time.Now()
	if err := store.Upsert(ctx, rec); err != nil {
		return session.Protocol.SendTunnelUpsertResponse(
			session.Conn,
			false,
			false,
			currentRevision,
			nil,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("upsert tunnel definition failed: %v", err),
			session.ID,
		)
	}
	logger.Infof(
		"[TunnelUpsertTrace] store upsert done: session=%s seq=%d edge=%s tunnel=%s revision=%d elapsed=%s totalElapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		tunnelID,
		rec.Revision,
		time.Since(upsertStartedAt),
		time.Since(reqStartedAt),
	)

	responseDefinition := tunnelDefinitionInfoFromRecord(rec)
	sendStartedAt := time.Now()
	if err := session.Protocol.SendTunnelUpsertResponse(
		session.Conn,
		true,
		false,
		uint64(rec.Revision),
		responseDefinition,
		0,
		"",
		session.ID,
	); err != nil {
		return err
	}
	logger.Infof(
		"[TunnelUpsertTrace] response sent: session=%s seq=%d edge=%s tunnel=%s revision=%d sendElapsed=%s totalElapsed=%s",
		session.ID,
		reqSeq,
		scopeEdgeID,
		tunnelID,
		rec.Revision,
		time.Since(sendStartedAt),
		time.Since(reqStartedAt),
	)

	s.broadcastTunnelEvent(session.ID, session.UserID, fbMsg.TunnelEventActionUPSERT, responseDefinition)
	return nil
}

func (s *Server) handleTunnelDeleteRequest(session *Session, msg *fbMsg.Message) error {
	if strings.TrimSpace(session.UserID) == "" {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			"",
			0,
			uint32(fbMsg.ErrorCodeAUTH_FAILED),
			"missing session user_id",
			session.ID,
		)
	}

	req := new(fbMsg.TunnelDeleteRequest)
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			"",
			0,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"invalid tunnel delete request body",
			session.ID,
		)
	}
	req.Init(table.Bytes, table.Pos)

	scopeEdgeID, err := s.resolveTunnelScopeEdgeID(string(req.EdgeId()))
	if err != nil {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			string(req.TunnelId()),
			0,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			err.Error(),
			session.ID,
		)
	}

	tunnelID := strings.TrimSpace(string(req.TunnelId()))
	if tunnelID == "" {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			"",
			0,
			uint32(fbMsg.ErrorCodeINVALID_MESSAGE),
			"tunnel_id is required",
			session.ID,
		)
	}

	store := s.getTunnelDefinitionStore()
	if store == nil {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			tunnelID,
			0,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			"tunnel store unavailable",
			session.ID,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), tunnelRequestTimeout)
	defer cancel()

	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(ctx, session.UserID, scopeEdgeID)
	if err != nil {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			tunnelID,
			0,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("read current revision failed: %v", err),
			session.ID,
		)
	}
	if req.IfMatchRevision() > 0 && req.IfMatchRevision() != currentRevision {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			true,
			tunnelID,
			currentRevision,
			tunnelConflictCode,
			"revision conflict",
			session.ID,
		)
	}
	changed, err := store.SoftDelete(
		ctx,
		session.UserID,
		scopeEdgeID,
		tunnelID,
		uint8(fbMsg.TunnelActorRoleCONTROLLER),
		session.ID,
		session.DeviceID,
	)
	if err != nil {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			tunnelID,
			currentRevision,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("delete tunnel definition failed: %v", err),
			session.ID,
		)
	}

	nextRevision, err := store.CurrentRevisionByOwnerAndEdge(ctx, session.UserID, scopeEdgeID)
	if err != nil {
		return session.Protocol.SendTunnelDeleteResponse(
			session.Conn,
			false,
			false,
			tunnelID,
			currentRevision,
			uint32(fbMsg.ErrorCodeINTERNAL_ERROR),
			fmt.Sprintf("read next revision failed: %v", err),
			session.ID,
		)
	}

	if err := session.Protocol.SendTunnelDeleteResponse(
		session.Conn,
		true,
		false,
		tunnelID,
		nextRevision,
		0,
		"",
		session.ID,
	); err != nil {
		return err
	}

	if !changed {
		return nil
	}
	if s.channelMgr != nil {
		closedCount, closeErr := s.channelMgr.CloseTunnelChannels(tunnelID)
		if closeErr != nil {
			logger.Warnf(
				"[TunnelDelete] cleanup runtime channels failed, edge=%s tunnel=%s closed=%d err=%v",
				scopeEdgeID,
				tunnelID,
				closedCount,
				closeErr,
			)
		} else if closedCount > 0 {
			logger.Infof(
				"[TunnelDelete] cleaned runtime channels, edge=%s tunnel=%s closed=%d",
				scopeEdgeID,
				tunnelID,
				closedCount,
			)
		}
	}

	deletedRecord, err := store.Get(ctx, session.UserID, scopeEdgeID, tunnelID)
	if err != nil {
		logger.Debugf("load deleted tunnel definition failed, edge=%s tunnel=%s err=%v",
			scopeEdgeID, tunnelID, err)
		return nil
	}
	definition := tunnelDefinitionInfoFromRecord(deletedRecord)
	s.broadcastTunnelEvent(session.ID, session.UserID, fbMsg.TunnelEventActionDELETE, definition)
	return nil
}

func (s *Server) getTunnelDefinitionStore() *channel.TunnelDefinitionStore {
	if s == nil || s.channelMgr == nil {
		return nil
	}
	return s.channelMgr.GetTunnelStore()
}

func (s *Server) resolveTunnelScopeEdgeID(requestEdgeID string) (string, error) {
	currentEdgeID := strings.TrimSpace(s.config.Node.ID)
	scopeEdgeID := strings.TrimSpace(requestEdgeID)
	if scopeEdgeID == "" {
		scopeEdgeID = currentEdgeID
	}

	if scopeEdgeID == "" {
		return "", fmt.Errorf("edge_id is required")
	}
	if currentEdgeID != "" && scopeEdgeID != currentEdgeID {
		return "", fmt.Errorf("edge_id mismatch: current=%s, requested=%s", currentEdgeID, scopeEdgeID)
	}
	return scopeEdgeID, nil
}

func (s *Server) broadcastTunnelEvent(
	excludeSessionID string,
	ownerUserID string,
	action fbMsg.TunnelEventAction,
	definition *fbMsg.TunnelDefinitionInfoT,
) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	if definition == nil || s.sessions == nil || ownerUserID == "" {
		return
	}

	// Publish via async ring-buffer broadcaster.  The delivery goroutine
	// filters by tunnelOwnerUserID and excludeSessionID per session.
	if s.broadcaster != nil {
		s.broadcaster.Publish(broadcastEntry{
			kind:              kindTunnelEvent,
			tunnelAction:      action,
			tunnelRevision:    definition.Revision,
			tunnelDefinition:  definition,
			tunnelOwnerUserID: ownerUserID,
			excludeSessionID:  excludeSessionID,
		})
	}
}

func tunnelDefinitionInfoFromRecord(
	rec *channel.TunnelDefinitionRecord,
) *fbMsg.TunnelDefinitionInfoT {
	if rec == nil {
		return nil
	}

	createdAt := uint64(0)
	if !rec.CreatedAt.IsZero() {
		createdAt = uint64(rec.CreatedAt.UnixMilli())
	}
	updatedAt := uint64(0)
	if !rec.UpdatedAt.IsZero() {
		updatedAt = uint64(rec.UpdatedAt.UnixMilli())
	}

	return &fbMsg.TunnelDefinitionInfoT{
		TunnelId:       rec.TunnelID,
		EdgeId:         rec.EdgeID,
		OwnerUserId:    rec.OwnerUserID,
		Name:           rec.Name,
		AppId:          rec.AppID,
		Protocol:       rec.Protocol,
		IntentJson:     rec.IntentJSON,
		ConfigJson:     rec.ConfigJSON,
		RuntimeJson:    rec.RuntimeJSON,
		State:          rec.State,
		ActorRole:      normalizeTunnelActorRole(fbMsg.TunnelActorRole(rec.ActorRole)),
		ActorSessionId: strings.TrimSpace(rec.ActorSessionID),
		ActorDeviceId:  strings.TrimSpace(rec.ActorDeviceID),
		Version:        uint64(rec.Version),
		Revision:       uint64(rec.Revision),
		Deleted:        rec.DeletedAt != nil,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}
}

func normalizeTunnelActorRole(role fbMsg.TunnelActorRole) fbMsg.TunnelActorRole {
	switch role {
	case fbMsg.TunnelActorRolePUBLISHER, fbMsg.TunnelActorRoleCONSUMER, fbMsg.TunnelActorRoleCONTROLLER:
		return role
	default:
		return fbMsg.TunnelActorRoleCONTROLLER
	}
}

const (
	tunnelActorDecisionFirstCreate      = "first_create_force_publisher"
	tunnelActorDecisionPreserveExisting = "preserve_existing"
	tunnelActorDecisionTakeover         = "takeover_rebind_publisher"
)

type tunnelActorContextResolution struct {
	Role                  fbMsg.TunnelActorRole
	ActorSessionID        string
	ActorDeviceID         string
	TakeoverApplied       bool
	Decision              string
	PreviousOwnerDeviceID string
	NextOwnerDeviceID     string
}

func resolveTunnelUpsertActorContext(
	existing *channel.TunnelDefinitionRecord,
	nextConfigJSON string,
	requestedRole fbMsg.TunnelActorRole,
	requestedActorSessionID string,
	requestedActorDeviceID string,
	sessionID string,
	sessionDeviceID string,
) tunnelActorContextResolution {
	resolvedSessionID := firstNonEmpty(sessionID, requestedActorSessionID)
	resolvedDeviceID := firstNonEmpty(sessionDeviceID, requestedActorDeviceID)
	resolution := tunnelActorContextResolution{
		Role:           requestedRole,
		ActorSessionID: resolvedSessionID,
		ActorDeviceID:  resolvedDeviceID,
		Decision:       tunnelActorDecisionPreserveExisting,
	}

	// Tunnel first create: creator device is publisher.
	if existing == nil || existing.DeletedAt != nil {
		resolution.Role = fbMsg.TunnelActorRolePUBLISHER
		resolution.Decision = tunnelActorDecisionFirstCreate
		return resolution
	}

	// Keep persisted actor context stable by default.
	resolution.Role = normalizeTunnelActorRole(fbMsg.TunnelActorRole(existing.ActorRole))
	resolution.ActorSessionID = firstNonEmpty(existing.ActorSessionID, resolvedSessionID)
	resolution.ActorDeviceID = firstNonEmpty(existing.ActorDeviceID, resolvedDeviceID)
	resolution.PreviousOwnerDeviceID = resolveTunnelOwnershipDeviceID(existing.ConfigJSON)
	resolution.NextOwnerDeviceID = resolveTunnelOwnershipDeviceID(nextConfigJSON)

	// Only takeover is allowed to rebind publisher identity.
	if !isTakeoverConfigTransition(existing.ConfigJSON, nextConfigJSON, sessionDeviceID) {
		return resolution
	}

	resolution.Role = fbMsg.TunnelActorRolePUBLISHER
	resolution.ActorSessionID = resolvedSessionID
	resolution.ActorDeviceID = resolvedDeviceID
	resolution.TakeoverApplied = true
	resolution.Decision = tunnelActorDecisionTakeover
	return resolution
}

func isTakeoverConfigTransition(previousConfigJSON, nextConfigJSON, sessionDeviceID string) bool {
	sessionDeviceID = strings.TrimSpace(sessionDeviceID)
	if sessionDeviceID == "" {
		return false
	}

	prevOwner := resolveTunnelOwnershipDeviceID(previousConfigJSON)
	nextOwner := resolveTunnelOwnershipDeviceID(nextConfigJSON)
	if nextOwner == "" || nextOwner != sessionDeviceID {
		return false
	}
	return prevOwner != nextOwner
}

func resolveTunnelOwnershipDeviceID(configJSON string) string {
	return tunnelpolicy.ResolveOwnershipDeviceID(configJSON)
}

func canSessionMutateTunnelDefinition(
	existing *channel.TunnelDefinitionRecord,
	nextConfigJSON string,
	sessionDeviceID string,
	takeoverApplied bool,
) bool {
	sessionDeviceID = strings.TrimSpace(sessionDeviceID)
	if sessionDeviceID == "" {
		return false
	}
	if existing == nil || existing.DeletedAt != nil {
		return true
	}
	if takeoverApplied {
		return true
	}

	ownerDeviceID := firstNonEmpty(
		resolveTunnelOwnershipDeviceID(existing.ConfigJSON),
		strings.TrimSpace(existing.ActorDeviceID),
		resolveTunnelOwnershipDeviceID(nextConfigJSON),
	)
	if ownerDeviceID == "" {
		// Backward compatibility: historical records may miss ownership fields.
		return true
	}
	return ownerDeviceID == sessionDeviceID
}

func shouldSkipTunnelUpsertRevisionGuard(
	req *fbMsg.TunnelUpsertRequest,
	existing *channel.TunnelDefinitionRecord,
	sessionDeviceID string,
) bool {
	if req == nil {
		return false
	}
	sessionDeviceID = strings.TrimSpace(sessionDeviceID)
	if sessionDeviceID == "" {
		return false
	}
	definition := req.Definition(nil)
	if definition == nil {
		return false
	}
	if normalizeTunnelActorRole(definition.ActorRole()) == fbMsg.TunnelActorRoleCONSUMER {
		return false
	}

	nextConfigJSON := strings.TrimSpace(string(definition.ConfigJson()))
	knownNext, nextExclusive := resolveTunnelSharedModeFromConfigJSON(nextConfigJSON)
	if !knownNext || !nextExclusive {
		return false
	}

	currentConfigJSON := ""
	if existing != nil {
		currentConfigJSON = strings.TrimSpace(existing.ConfigJSON)
	}
	if currentConfigJSON != "" {
		knownCurrent, currentExclusive := resolveTunnelSharedModeFromConfigJSON(currentConfigJSON)
		if !knownCurrent || !currentExclusive {
			return false
		}
	}

	managerDeviceID := firstNonEmpty(
		resolveTunnelOwnershipDeviceID(nextConfigJSON),
		resolveTunnelOwnershipDeviceID(currentConfigJSON),
	)
	if managerDeviceID == "" {
		return false
	}
	return managerDeviceID == sessionDeviceID
}

func resolveTunnelOwnershipFieldsFromConfig(configJSON string) (managerDeviceID, creatorDeviceID, publisherDeviceID string) {
	return tunnelpolicy.ResolveOwnershipFieldsFromConfig(configJSON)
}

func resolveTunnelSharedModeFromConfigJSON(configJSON string) (known bool, exclusive bool) {
	return tunnelpolicy.ResolveSharedModeFromConfig(configJSON)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (s *Server) rewriteTunnelPeerSessionsFromEdgeObservation(rec *channel.TunnelDefinitionRecord) bool {
	rewriteStartedAt := time.Now()
	if rec == nil || s == nil || s.channelMgr == nil {
		return false
	}
	tunnelID := strings.TrimSpace(rec.TunnelID)
	if tunnelID == "" {
		return false
	}
	observed := s.channelMgr.ListTunnelObservedChannels(tunnelID)
	endpointResolveStartedAt := time.Now()
	directEndpointBySession := s.buildQUICDirectEndpointBySession(observed)
	logger.Debugf(
		"[TunnelUpsertTrace] rewrite endpoint resolved: tunnel=%s observed=%d endpointSessions=%d resolveElapsed=%s totalElapsed=%s",
		tunnelID,
		len(observed),
		len(directEndpointBySession),
		time.Since(endpointResolveStartedAt),
		time.Since(rewriteStartedAt),
	)

	changed := false
	normalizedRuntime, runtimeChanged := rewritePeerSessionsInJSONPath(rec.RuntimeJSON, observed, directEndpointBySession)
	if runtimeChanged {
		rec.RuntimeJSON = normalizedRuntime
		changed = true
	}
	normalizedConfig, configChanged := rewritePeerSessionsInJSONPath(rec.ConfigJSON, observed, directEndpointBySession, "runtime")
	if configChanged {
		rec.ConfigJSON = normalizedConfig
		changed = true
	}
	logger.Debugf(
		"[TunnelUpsertTrace] rewrite completed: tunnel=%s changed=%t runtimeChanged=%t configChanged=%t observed=%d endpointSessions=%d totalElapsed=%s",
		tunnelID,
		changed,
		runtimeChanged,
		configChanged,
		len(observed),
		len(directEndpointBySession),
		time.Since(rewriteStartedAt),
	)
	return changed
}

func (s *Server) buildQUICDirectEndpointBySession(observed []channel.TunnelObservedChannel) map[string]string {
	if s == nil || s.channelMgr == nil || len(observed) == 0 {
		return nil
	}
	quicSessions := s.channelMgr.GetP2PNamespaceSessionSnapshot(p2p.NamespaceQUIC)
	if len(quicSessions) == 0 {
		return nil
	}
	iceCtrl := s.channelMgr.GetICEController()
	if iceCtrl == nil {
		return nil
	}

	tunnelIDs := collectObservedTunnelIDs(observed)
	deviceEndpoint := make(map[string]string)
	deviceUpdatedAt := make(map[string]time.Time)
	seenSessionIDs := make(map[string]struct{}, len(observed)*3)
	processSession := func(sessionID string, session *p2p.Session) {
		if session == nil {
			return
		}
		if len(tunnelIDs) > 0 {
			networkID := strings.TrimSpace(session.NetworkID)
			if networkID == "" {
				return
			}
			if _, matched := tunnelIDs[networkID]; !matched {
				return
			}
		}
		if session.PathType != p2p.PathDirect {
			return
		}
		if session.Status != p2p.SessionStatusConnected && session.Status != p2p.SessionStatusEstablishing {
			return
		}

		iceSession, iceOK := iceCtrl.GetSession(strings.TrimSpace(sessionID))
		if !iceOK || iceSession == nil {
			return
		}
		publisherEndpoint, consumerEndpoint := iceSession.EndpointAddrs()
		publisherDeviceID := extractDeviceIDFromClientID(session.PeerA)
		consumerDeviceID := extractDeviceIDFromClientID(session.PeerB)
		upsertDeviceEndpoint(deviceEndpoint, deviceUpdatedAt, publisherDeviceID, publisherEndpoint, session.UpdatedAt)
		upsertDeviceEndpoint(deviceEndpoint, deviceUpdatedAt, consumerDeviceID, consumerEndpoint, session.UpdatedAt)
	}

	// Candidate-first lookup keeps actor/session matching precise.
	// Snapshot-based reads avoid repeatedly contending ChannelManager/runtime locks.
	for _, sessionID := range collectObservedQUICSessionIDs(observed) {
		seenSessionIDs[sessionID] = struct{}{}
		processSession(sessionID, quicSessions[sessionID])
	}

	// Fallback to legacy snapshot scan when candidate mapping cannot resolve any
	// endpoint (e.g. historical session IDs that do not match observed aliases).
	if len(deviceEndpoint) == 0 {
		for sessionID, session := range quicSessions {
			if _, seen := seenSessionIDs[sessionID]; seen {
				continue
			}
			processSession(sessionID, session)
		}
	}
	if len(deviceEndpoint) == 0 {
		return nil
	}

	out := mapObservedSessionIDToDirectEndpoint(observed, deviceEndpoint)
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectObservedQUICSessionIDs(observed []channel.TunnelObservedChannel) []string {
	if len(observed) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(observed)*3)
	for _, item := range observed {
		for _, candidate := range quicSessionIDCandidatesFromObserved(item) {
			sessionID := strings.TrimSpace(candidate)
			if sessionID == "" {
				continue
			}
			seen[sessionID] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for sessionID := range seen {
		out = append(out, sessionID)
	}
	sort.Strings(out)
	return out
}

func collectObservedTunnelIDs(observed []channel.TunnelObservedChannel) map[string]struct{} {
	if len(observed) == 0 {
		return nil
	}
	out := make(map[string]struct{})
	for _, item := range observed {
		channelID := strings.TrimSpace(item.ChannelID)
		if channelID == "" {
			continue
		}
		parts := strings.SplitN(channelID, ":", 2)
		tunnelID := strings.TrimSpace(parts[0])
		if tunnelID == "" {
			continue
		}
		out[tunnelID] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractDeviceIDFromClientID(clientID string) string {
	normalized := strings.ToLower(strings.TrimSpace(clientID))
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "device-") {
		return normalized
	}
	const marker = "-device-"
	idx := strings.Index(normalized, marker)
	if idx < 0 {
		return ""
	}
	core := strings.TrimSpace(normalized[idx+len(marker):])
	if core == "" {
		return ""
	}
	return "device-" + core
}

func upsertDeviceEndpoint(
	deviceEndpoint map[string]string,
	deviceUpdatedAt map[string]time.Time,
	deviceID string,
	endpoint string,
	updatedAt time.Time,
) {
	deviceID = strings.TrimSpace(deviceID)
	endpoint = strings.TrimSpace(endpoint)
	if deviceID == "" || !hasEndpointPort(endpoint) {
		return
	}
	if lastUpdated, exists := deviceUpdatedAt[deviceID]; exists {
		if updatedAt.Before(lastUpdated) {
			return
		}
	}
	deviceUpdatedAt[deviceID] = updatedAt
	deviceEndpoint[deviceID] = endpoint
}

func mapObservedSessionIDToDirectEndpoint(
	observed []channel.TunnelObservedChannel,
	deviceEndpoint map[string]string,
) map[string]string {
	if len(observed) == 0 || len(deviceEndpoint) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, item := range observed {
		deviceID := strings.TrimSpace(item.ActorDeviceID)
		if deviceID == "" {
			deviceID = strings.TrimSpace(item.DeviceID)
		}
		if deviceID == "" {
			continue
		}
		endpoint := strings.TrimSpace(deviceEndpoint[deviceID])
		if !hasEndpointPort(endpoint) {
			continue
		}
		for _, candidate := range quicSessionIDCandidatesFromObserved(item) {
			if candidate == "" {
				continue
			}
			out[candidate] = endpoint
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func quicSessionIDCandidatesFromObserved(item channel.TunnelObservedChannel) []string {
	seen := make(map[string]struct{}, 3)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
	}

	add(item.ActorSessionID)
	add(item.SessionID)

	scope := ""
	channelID := strings.TrimSpace(item.ChannelID)
	if channelID != "" {
		parts := strings.SplitN(channelID, ":", 2)
		scope = strings.TrimSpace(parts[0])
	}
	owner := strings.TrimSpace(item.ActorSessionID)
	if owner == "" {
		owner = strings.TrimSpace(item.SessionID)
	}
	if scope != "" && owner != "" {
		add(fmt.Sprintf("quic:%s:%s", owner, scope))
	}

	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func rewritePeerSessionsInJSONPath(
	raw string,
	observed []channel.TunnelObservedChannel,
	directEndpointBySession map[string]string,
	path ...string,
) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw, false
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return raw, false
	}

	target := payload
	for _, segment := range path {
		nextRaw, ok := target[strings.TrimSpace(segment)]
		if !ok {
			return raw, false
		}
		next, ok := nextRaw.(map[string]any)
		if !ok || next == nil {
			return raw, false
		}
		target = next
	}

	changed := rewritePeerSessionsInObject(target, observed, directEndpointBySession)
	if !changed {
		return raw, false
	}
	next, err := json.Marshal(payload)
	if err != nil {
		return raw, false
	}
	return string(next), true
}

func rewritePeerSessionsInObject(
	obj map[string]any,
	observed []channel.TunnelObservedChannel,
	directEndpointBySession map[string]string,
) bool {
	if obj == nil {
		return false
	}
	const peerSessionsVersion = 2
	nextSessionItems := buildObservedPeerSessionsV2(observed, directEndpointBySession)
	if nextSessionItems == nil {
		nextSessionItems = make([]any, 0)
	}

	changed := false
	if !jsonFieldDeepEqual(obj["peerSessions"], nextSessionItems) {
		obj["peerSessions"] = nextSessionItems
		changed = true
	}
	if !jsonFieldDeepEqual(obj["peerSessionsVersion"], peerSessionsVersion) {
		obj["peerSessionsVersion"] = peerSessionsVersion
		changed = true
	}
	return changed
}

type observedPublisherSessionV2 struct {
	sessionID   string
	deviceID    string
	tunnelID    string
	channelKeys map[string]struct{}
	consumers   map[string]*observedConsumerSessionV2
}

type observedConsumerSessionV2 struct {
	sessionID           string
	deviceID            string
	role                string
	channelKeys         map[string]struct{}
	transportSessionIDs map[string]struct{}
	items               []channel.TunnelObservedChannel
}

type observedSessionDataPath struct {
	linkType         string
	pathKind         string
	state            string
	endpoint         string
	channelEndpoints map[string]string
	linkTypes        []string
	hasDirectLike    bool
}

func buildObservedPeerSessionsV2(
	observed []channel.TunnelObservedChannel,
	directEndpointBySession map[string]string,
) []any {
	if len(observed) == 0 {
		return nil
	}
	publishers := buildObservedPeerSessionAggregates(observed)
	if len(publishers) == 0 {
		return nil
	}

	out := make([]any, 0, len(publishers))
	for _, publisher := range publishers {
		if publisher == nil || publisher.sessionID == "" {
			continue
		}
		channelKeys := sortedStringSetKeys(publisher.channelKeys)
		consumerIDs := make([]string, 0, len(publisher.consumers))
		for consumerID := range publisher.consumers {
			consumerIDs = append(consumerIDs, consumerID)
		}
		sort.Strings(consumerIDs)

		connectedCount := 0
		negotiatingCount := 0
		failedCount := 0
		inactiveCount := 0
		activeCount := 0
		consumerItems := make([]any, 0, len(consumerIDs))
		for _, consumerID := range consumerIDs {
			consumer := publisher.consumers[consumerID]
			if consumer == nil {
				continue
			}
			path := deriveObservedSessionDataPath(consumer.items)
			if path.linkType == "" {
				path.linkType = "relay"
			}
			if path.hasDirectLike && consumer.sessionID != "" {
				if directEndpoint, ok := resolveObservedDirectEndpointForSession(consumer, directEndpointBySession); ok {
					path.endpoint = directEndpoint
				} else {
					path.endpoint = ""
					if path.pathKind == "direct" && path.state == "connected" {
						path.state = "negotiating"
					}
				}
			}
			runtimeState := mapDataPathStateToRuntimeSessionState(path.state)
			switch path.state {
			case "connected":
				connectedCount++
			case "negotiating":
				negotiatingCount++
			case "failed":
				failedCount++
			default:
				inactiveCount++
			}
			if runtimeState == "active" {
				activeCount++
			}

			dataPath := map[string]any{
				"type":  path.linkType,
				"state": path.state,
			}
			if path.pathKind != "" {
				dataPath["pathKind"] = path.pathKind
			}
			if len(path.linkTypes) > 0 {
				dataPath["linkTypes"] = stringSliceToAny(path.linkTypes)
			}
			if len(path.channelEndpoints) > 0 {
				dataPath["channelEndpoints"] = stringMapToAny(path.channelEndpoints)
			}
			if path.endpoint != "" {
				dataPath["endpoint"] = path.endpoint
			}

			consumerObj := map[string]any{
				"id":          consumer.sessionID,
				"sessionId":   consumer.sessionID,
				"role":        consumer.role,
				"deviceId":    consumer.deviceID,
				"state":       runtimeState,
				"channelKeys": stringSliceToAny(sortedStringSetKeys(consumer.channelKeys)),
				"dataPath":    dataPath,
			}
			transportSessionIDs := sortedStringSetKeys(consumer.transportSessionIDs)
			if len(transportSessionIDs) > 0 {
				consumerObj["transportSessionIds"] = stringSliceToAny(transportSessionIDs)
				consumerObj["transportSessionId"] = transportSessionIDs[0]
			}
			consumerItems = append(consumerItems, consumerObj)
		}

		summaryState := "inactive"
		if activeCount > 0 {
			summaryState = "active"
		} else if negotiatingCount > 0 {
			summaryState = "negotiating"
		} else if failedCount > 0 {
			summaryState = "failed"
		}

		sessionObj := map[string]any{
			"id":          publisher.sessionID,
			"channelKeys": stringSliceToAny(channelKeys),
			"publisher": map[string]any{
				"sessionId": publisher.sessionID,
				"deviceId":  publisher.deviceID,
			},
			"consumers": consumerItems,
			"summary": map[string]any{
				"state":            summaryState,
				"consumerCount":    len(consumerItems),
				"activeCount":      activeCount,
				"connectedCount":   connectedCount,
				"negotiatingCount": negotiatingCount,
				"failedCount":      failedCount,
				"inactiveCount":    inactiveCount,
			},
			"metadata": map[string]any{
				"source": "edge-observed",
			},
		}
		out = append(out, sessionObj)
	}
	return out
}

func buildObservedPeerSessionAggregates(observed []channel.TunnelObservedChannel) []*observedPublisherSessionV2 {
	if len(observed) == 0 {
		return nil
	}
	items := make([]channel.TunnelObservedChannel, 0, len(observed))
	items = append(items, observed...)
	sort.Slice(items, func(i, j int) bool {
		left := strings.TrimSpace(items[i].ChannelID)
		right := strings.TrimSpace(items[j].ChannelID)
		if left == right {
			leftSession := strings.TrimSpace(items[i].ActorSessionID)
			rightSession := strings.TrimSpace(items[j].ActorSessionID)
			return leftSession < rightSession
		}
		return left < right
	})

	publisherBySessionID := make(map[string]*observedPublisherSessionV2)
	publisherByChannelKey := make(map[string]*observedPublisherSessionV2)
	publisherOrder := make([]string, 0, len(items))
	var defaultPublisher *observedPublisherSessionV2

	ensurePublisher := func(sessionID, deviceID, tunnelID string) *observedPublisherSessionV2 {
		sessionID = strings.TrimSpace(sessionID)
		if sessionID == "" {
			sessionID = "publisher:unknown:" + strings.TrimSpace(tunnelID)
		}
		if existing, ok := publisherBySessionID[sessionID]; ok && existing != nil {
			if existing.deviceID == "" && strings.TrimSpace(deviceID) != "" {
				existing.deviceID = strings.TrimSpace(deviceID)
			}
			return existing
		}
		next := &observedPublisherSessionV2{
			sessionID:   sessionID,
			deviceID:    strings.TrimSpace(deviceID),
			tunnelID:    strings.TrimSpace(tunnelID),
			channelKeys: make(map[string]struct{}),
			consumers:   make(map[string]*observedConsumerSessionV2),
		}
		publisherBySessionID[sessionID] = next
		publisherOrder = append(publisherOrder, sessionID)
		return next
	}

	for _, item := range items {
		role := resolveObservedActorRole(item)
		if role != uint8(fbMsg.TunnelActorRolePUBLISHER) {
			continue
		}
		publisherSessionID := resolveObservedSessionID(item)
		publisherDeviceID := resolveObservedDeviceID(item)
		tunnelID := resolveObservedTunnelID(item)
		publisher := ensurePublisher(publisherSessionID, publisherDeviceID, tunnelID)
		if defaultPublisher == nil {
			defaultPublisher = publisher
		}
		channelKey := strings.TrimSpace(item.ChannelKey)
		if channelKey != "" {
			publisher.channelKeys[channelKey] = struct{}{}
			if _, exists := publisherByChannelKey[channelKey]; !exists {
				publisherByChannelKey[channelKey] = publisher
			}
		}
	}

	for _, item := range items {
		role := resolveObservedActorRole(item)
		if role == uint8(fbMsg.TunnelActorRolePUBLISHER) {
			continue
		}
		sessionID := resolveObservedSessionID(item)
		if sessionID == "" {
			continue
		}
		channelKey := strings.TrimSpace(item.ChannelKey)
		publisher := publisherByChannelKey[channelKey]
		if publisher == nil {
			publisher = defaultPublisher
		}
		if publisher == nil {
			publisher = ensurePublisher("", "", resolveObservedTunnelID(item))
			if defaultPublisher == nil {
				defaultPublisher = publisher
			}
		}
		if channelKey != "" {
			publisher.channelKeys[channelKey] = struct{}{}
		}
		consumer := publisher.consumers[sessionID]
		if consumer == nil {
			consumer = &observedConsumerSessionV2{
				sessionID:           sessionID,
				deviceID:            resolveObservedDeviceID(item),
				role:                observedActorRoleToString(role),
				channelKeys:         make(map[string]struct{}),
				transportSessionIDs: make(map[string]struct{}),
			}
			publisher.consumers[sessionID] = consumer
		}
		if consumer.deviceID == "" {
			consumer.deviceID = resolveObservedDeviceID(item)
		}
		if consumer.role != "consumer" && role == uint8(fbMsg.TunnelActorRoleCONSUMER) {
			consumer.role = "consumer"
		}
		if channelKey != "" {
			consumer.channelKeys[channelKey] = struct{}{}
		}
		transportSessionID := strings.TrimSpace(item.SessionID)
		if transportSessionID != "" {
			consumer.transportSessionIDs[transportSessionID] = struct{}{}
		}
		consumer.items = append(consumer.items, item)
	}

	if len(publisherOrder) == 0 {
		return nil
	}
	out := make([]*observedPublisherSessionV2, 0, len(publisherOrder))
	for _, sessionID := range publisherOrder {
		publisher := publisherBySessionID[sessionID]
		if publisher == nil {
			continue
		}
		out = append(out, publisher)
	}
	return out
}

func resolveObservedDirectEndpointForSession(
	consumer *observedConsumerSessionV2,
	directEndpointBySession map[string]string,
) (string, bool) {
	if consumer == nil || len(directEndpointBySession) == 0 {
		return "", false
	}
	candidates := make([]string, 0, 1+len(consumer.items)*2)
	seen := make(map[string]struct{}, 1+len(consumer.items)*2)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}
	add(consumer.sessionID)
	for _, item := range consumer.items {
		add(item.ActorSessionID)
		add(item.SessionID)
	}
	for _, candidate := range candidates {
		directEndpoint := strings.TrimSpace(directEndpointBySession[candidate])
		if hasEndpointPort(directEndpoint) {
			return directEndpoint, true
		}
	}
	return "", false
}

func sortedStringSetKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stringSliceToAny(values []string) []any {
	if len(values) == 0 {
		return nil
	}
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func stringMapToAny(values map[string]string) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resolveObservedSessionID(item channel.TunnelObservedChannel) string {
	if actorSessionID := strings.TrimSpace(item.ActorSessionID); actorSessionID != "" {
		return actorSessionID
	}
	if sessionID := strings.TrimSpace(item.SessionID); sessionID != "" {
		return sessionID
	}
	return ""
}

func resolveObservedDeviceID(item channel.TunnelObservedChannel) string {
	if actorDeviceID := strings.TrimSpace(item.ActorDeviceID); actorDeviceID != "" {
		return actorDeviceID
	}
	return strings.TrimSpace(item.DeviceID)
}

func resolveObservedTunnelID(item channel.TunnelObservedChannel) string {
	channelID := strings.TrimSpace(item.ChannelID)
	if channelID == "" {
		return ""
	}
	parts := strings.SplitN(channelID, ":", 2)
	return strings.TrimSpace(parts[0])
}

func observedActorRoleToString(role uint8) string {
	switch role {
	case uint8(fbMsg.TunnelActorRoleCONSUMER):
		return "consumer"
	case uint8(fbMsg.TunnelActorRoleCONTROLLER):
		return "controller"
	default:
		return "consumer"
	}
}

func mapDataPathStateToRuntimeSessionState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "connected":
		return "active"
	case "negotiating":
		return "negotiating"
	case "failed":
		return "failed"
	default:
		return "inactive"
	}
}

func resolveObservedActorRole(item channel.TunnelObservedChannel) uint8 {
	if item.ActorRole != 0 {
		return item.ActorRole
	}
	channelID := strings.ToLower(strings.TrimSpace(item.ChannelID))
	if channelID == "" {
		return uint8(fbMsg.TunnelActorRolePUBLISHER)
	}
	if strings.Contains(channelID, ":consumer:") || strings.HasSuffix(channelID, ":consumer") {
		return uint8(fbMsg.TunnelActorRoleCONSUMER)
	}
	if strings.Contains(channelID, ":controller:") || strings.HasSuffix(channelID, ":controller") {
		return uint8(fbMsg.TunnelActorRoleCONTROLLER)
	}
	if strings.Contains(channelID, ":publisher:") || strings.HasSuffix(channelID, ":publisher") {
		return uint8(fbMsg.TunnelActorRolePUBLISHER)
	}
	return uint8(fbMsg.TunnelActorRolePUBLISHER)
}

func deriveObservedSessionDataPath(
	selected []channel.TunnelObservedChannel,
) observedSessionDataPath {
	result := observedSessionDataPath{
		linkType:  "relay",
		pathKind:  "unknown",
		state:     "inactive",
		linkTypes: nil,
	}
	if len(selected) == 0 {
		return result
	}

	linkTypeSeen := make(map[string]struct{}, len(selected))
	hasRelay := false
	hasDirectLike := false
	firstDirectType := ""
	for _, item := range selected {
		normalized := normalizeLinkType(item.LinkType)
		if _, exists := linkTypeSeen[normalized]; !exists {
			linkTypeSeen[normalized] = struct{}{}
			result.linkTypes = append(result.linkTypes, normalized)
		}
		if normalized == "relay" {
			hasRelay = true
			continue
		}
		if normalized == "p2p" || normalized == "wireguard" {
			hasDirectLike = true
			if firstDirectType == "" {
				firstDirectType = normalized
			}
		}
	}
	result.hasDirectLike = hasDirectLike

	switch {
	case hasRelay && hasDirectLike:
		result.pathKind = "mixed"
		result.linkType = "relay"
	case hasDirectLike:
		result.pathKind = "direct"
		if firstDirectType != "" {
			result.linkType = firstDirectType
		} else {
			result.linkType = "p2p"
		}
	case hasRelay:
		result.pathKind = "relay"
		result.linkType = "relay"
	}

	activeDetected := false
	negotiatingDetected := false
	failedDetected := false
	channelEndpoints := make(map[string]string, len(selected))
	for _, item := range selected {
		normalizedLinkType := normalizeLinkType(item.LinkType)
		normalizedState := strings.ToLower(strings.TrimSpace(item.State))
		if normalizedState == "active" {
			activeDetected = true
		} else if normalizedState == "negotiating" {
			negotiatingDetected = true
		} else if normalizedState == "failed" {
			failedDetected = true
		}
		key := strings.TrimSpace(item.ChannelKey)
		remote := strings.TrimSpace(item.RemoteEndpoint)
		if normalizedLinkType == "relay" && key != "" && hasEndpointPort(remote) {
			channelEndpoints[key] = remote
		}
	}

	if activeDetected {
		result.state = "connected"
	} else if negotiatingDetected {
		result.state = "negotiating"
	} else if failedDetected {
		result.state = "failed"
	}

	if len(channelEndpoints) > 0 && (result.pathKind == "relay" || result.pathKind == "mixed") {
		result.channelEndpoints = channelEndpoints
	}

	for _, item := range selected {
		if normalized := normalizeLinkType(item.LinkType); normalized != "p2p" && normalized != "wireguard" {
			continue
		}
		remote := strings.TrimSpace(item.RemoteEndpoint)
		if hasEndpointPort(remote) {
			result.endpoint = remote
			break
		}
	}
	return result
}

func normalizeLinkType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "p2p":
		return "p2p"
	case "wireguard":
		return "wireguard"
	case "relay":
		return "relay"
	default:
		return "relay"
	}
}

func jsonFieldDeepEqual(left, right any) bool {
	lb, lerr := json.Marshal(left)
	rb, rerr := json.Marshal(right)
	if lerr != nil || rerr != nil {
		return false
	}
	return string(lb) == string(rb)
}

func hasEndpointPort(endpoint string) bool {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return false
	}
	if host, port, err := net.SplitHostPort(trimmed); err == nil {
		if strings.TrimSpace(host) == "" {
			return false
		}
		_, perr := strconv.Atoi(strings.TrimSpace(port))
		return perr == nil
	}
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon <= 0 || lastColon+1 >= len(trimmed) {
		return false
	}
	_, err := strconv.Atoi(strings.TrimSpace(trimmed[lastColon+1:]))
	return err == nil
}
