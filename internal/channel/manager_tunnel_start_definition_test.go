package channel

import (
	"context"
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	chtype "icool.io/yat/edge/internal/channel/types"
)

func newTunnelStartDefinitionManagerForTest(t *testing.T) *ChannelManager {
	t.Helper()

	manager, err := NewChannelManager(&Config{
		DomainProvider: &staticDomainProvider{assigned: "edge.example.com"},
		StatusDir:      t.TempDir(),
		EdgeID:         "edge-test-1",
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewChannelManager failed: %v", err)
	}
	return manager
}

func buildTunnelStartRequestForDefinitionTest(
	t *testing.T,
	ctx *HandlerContext,
	tunnelID string,
	edgeID string,
	ifMatchRevision uint64,
	definition *fbMsg.TunnelDefinitionInfoT,
) *fbMsg.TunnelStartRequest {
	t.Helper()
	if ctx == nil {
		t.Fatalf("handler context is required")
	}

	if definition != nil {
		if definition.ActorRole == fbMsg.TunnelActorRoleUNKNOWN {
			definition.ActorRole = fbMsg.TunnelActorRolePUBLISHER
		}
		if definition.ActorSessionId == "" {
			definition.ActorSessionId = ctx.SessionID
		}
		if definition.ActorDeviceId == "" {
			definition.ActorDeviceId = ctx.DeviceID
		}
	}

	builder := flatbuffers.NewBuilder(512)
	req := &fbMsg.TunnelStartRequestT{
		TunnelId: tunnelID,
		EdgeId:   edgeID,
		Mode:     fbMsg.TunnelStartModeALL_OR_NOTHING,
		Actor: &fbMsg.TunnelActorContextT{
			Role:      fbMsg.TunnelActorRolePUBLISHER,
			SessionId: ctx.SessionID,
			DeviceId:  ctx.DeviceID,
		},
		Channels:                  []*fbMsg.TunnelChannelStartSpecT{},
		Reconnect:                 false,
		DefinitionIfMatchRevision: ifMatchRevision,
		Definition:                definition,
	}
	offset := req.Pack(builder)
	builder.Finish(offset)
	return fbMsg.GetRootAsTunnelStartRequest(builder.FinishedBytes(), 0)
}

func TestUpsertTunnelDefinitionBeforeStart_UnblocksFirstOwnershipCheck(t *testing.T) {
	manager := newTunnelStartDefinitionManagerForTest(t)
	ctx := &HandlerContext{
		SessionIdentity: chtype.SessionIdentity{
			UserID:    "user-start-1",
			SessionID: "session-start-1",
			DeviceID:  "device-start-1",
		},
	}
	const (
		tunnelID = "tunnel-start-1"
		edgeID   = "edge-test-1"
	)

	if _, code, _ := manager.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID); code == 0 {
		t.Fatalf("expected ownership check to fail before definition upsert")
	}

	req := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, 0, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:       tunnelID,
		EdgeId:         edgeID,
		Name:           "First Start",
		AppId:          "app.ard",
		Protocol:       "tcp",
		IntentJson:     `{"purpose":"test"}`,
		ConfigJson:     `{"managerDeviceId":"device-start-1"}`,
		RuntimeJson:    `{"status":"inactive"}`,
		State:          "inactive",
		ActorRole:      fbMsg.TunnelActorRolePUBLISHER,
		ActorSessionId: ctx.SessionID,
		ActorDeviceId:  ctx.DeviceID,
	})

	resolvedEdgeID, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, req, tunnelID, edgeID)
	if code != 0 {
		t.Fatalf("upsertTunnelDefinitionBeforeStart failed: code=%d message=%s", code, message)
	}
	if resolvedEdgeID != edgeID {
		t.Fatalf("expected resolved edge %s, got %s", edgeID, resolvedEdgeID)
	}

	if _, code, message := manager.verifyTunnelRuntimeOwnership(ctx.UserID, edgeID, tunnelID); code != 0 {
		t.Fatalf("ownership check should pass after prestart upsert: code=%d message=%s", code, message)
	}

	store := manager.GetTunnelStore()
	if store == nil {
		t.Fatalf("tunnel store is nil")
	}
	rec, err := store.Get(context.Background(), ctx.UserID, edgeID, tunnelID)
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if rec == nil {
		t.Fatalf("expected tunnel definition record to exist")
	}
	if got := fbMsg.TunnelActorRole(rec.ActorRole); got != fbMsg.TunnelActorRolePUBLISHER {
		t.Fatalf("expected first write actor role publisher, got %s", got.String())
	}
	if rec.ActorSessionID != ctx.SessionID {
		t.Fatalf("expected actor session %s, got %s", ctx.SessionID, rec.ActorSessionID)
	}
	if rec.ActorDeviceID != ctx.DeviceID {
		t.Fatalf("expected actor device %s, got %s", ctx.DeviceID, rec.ActorDeviceID)
	}
}

func TestUpsertTunnelDefinitionBeforeStart_RejectsRevisionConflict(t *testing.T) {
	manager := newTunnelStartDefinitionManagerForTest(t)
	ctx := &HandlerContext{
		SessionIdentity: chtype.SessionIdentity{
			UserID:    "user-start-2",
			SessionID: "session-start-2",
			DeviceID:  "device-start-2",
		},
	}
	const (
		tunnelID = "tunnel-start-2"
		edgeID   = "edge-test-1"
	)

	initialReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, 0, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v1",
		AppId:       "app.ard",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-2"}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	if _, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, initialReq, tunnelID, edgeID); code != 0 {
		t.Fatalf("initial upsert failed: code=%d message=%s", code, message)
	}

	store := manager.GetTunnelStore()
	if store == nil {
		t.Fatalf("tunnel store is nil")
	}
	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(context.Background(), ctx.UserID, edgeID)
	if err != nil {
		t.Fatalf("CurrentRevisionByOwnerAndEdge failed: %v", err)
	}

	conflictReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, currentRevision+1, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v2-conflict",
		AppId:       "app.ard",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-2"}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	_, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, conflictReq, tunnelID, edgeID)
	if code != tunnelStartRevisionConflictCode {
		t.Fatalf("expected revision conflict code %d, got %d (message=%s)", tunnelStartRevisionConflictCode, code, message)
	}
	if message != "revision conflict" {
		t.Fatalf("unexpected conflict message: %s", message)
	}

	rec, err := store.Get(context.Background(), ctx.UserID, edgeID, tunnelID)
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if rec == nil {
		t.Fatalf("expected existing record")
	}
	if rec.Name != "v1" {
		t.Fatalf("expected record unchanged on conflict, got name=%s", rec.Name)
	}
}

func TestUpsertTunnelDefinitionBeforeStart_ExclusiveOwnerAllowsStaleRevision(t *testing.T) {
	manager := newTunnelStartDefinitionManagerForTest(t)
	ctx := &HandlerContext{
		SessionIdentity: chtype.SessionIdentity{
			UserID:    "user-start-3",
			SessionID: "session-start-3",
			DeviceID:  "device-start-3",
		},
	}
	const (
		tunnelID = "tunnel-start-3"
		edgeID   = "edge-test-1"
	)

	initialReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, 0, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v1",
		AppId:       "app.tcp",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-3","sharedState":"exclusive","shared":false}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	if _, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, initialReq, tunnelID, edgeID); code != 0 {
		t.Fatalf("initial upsert failed: code=%d message=%s", code, message)
	}

	store := manager.GetTunnelStore()
	if store == nil {
		t.Fatalf("tunnel store is nil")
	}
	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(context.Background(), ctx.UserID, edgeID)
	if err != nil {
		t.Fatalf("CurrentRevisionByOwnerAndEdge failed: %v", err)
	}

	staleReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, currentRevision+1, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v2-exclusive-stale",
		AppId:       "app.tcp",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-3","sharedState":"exclusive","shared":false}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	_, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, staleReq, tunnelID, edgeID)
	if code != 0 {
		t.Fatalf("expected exclusive stale revision to pass, got code=%d message=%s", code, message)
	}

	rec, err := store.Get(context.Background(), ctx.UserID, edgeID, tunnelID)
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if rec == nil {
		t.Fatalf("expected existing record")
	}
	if rec.Name != "v2-exclusive-stale" {
		t.Fatalf("expected record updated, got name=%s", rec.Name)
	}
}

func TestUpsertTunnelDefinitionBeforeStart_SharedKeepsRevisionConflict(t *testing.T) {
	manager := newTunnelStartDefinitionManagerForTest(t)
	ctx := &HandlerContext{
		SessionIdentity: chtype.SessionIdentity{
			UserID:    "user-start-4",
			SessionID: "session-start-4",
			DeviceID:  "device-start-4",
		},
	}
	const (
		tunnelID = "tunnel-start-4"
		edgeID   = "edge-test-1"
	)

	initialReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, 0, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v1",
		AppId:       "app.tcp",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-4","sharedState":"shared","shared":true}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	if _, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, initialReq, tunnelID, edgeID); code != 0 {
		t.Fatalf("initial upsert failed: code=%d message=%s", code, message)
	}

	store := manager.GetTunnelStore()
	if store == nil {
		t.Fatalf("tunnel store is nil")
	}
	currentRevision, err := store.CurrentRevisionByOwnerAndEdge(context.Background(), ctx.UserID, edgeID)
	if err != nil {
		t.Fatalf("CurrentRevisionByOwnerAndEdge failed: %v", err)
	}

	staleReq := buildTunnelStartRequestForDefinitionTest(t, ctx, tunnelID, edgeID, currentRevision+1, &fbMsg.TunnelDefinitionInfoT{
		TunnelId:    tunnelID,
		EdgeId:      edgeID,
		Name:        "v2-shared-stale",
		AppId:       "app.tcp",
		Protocol:    "tcp",
		IntentJson:  `{"purpose":"test"}`,
		ConfigJson:  `{"managerDeviceId":"device-start-4","sharedState":"shared","shared":true}`,
		RuntimeJson: `{"status":"inactive"}`,
		State:       "inactive",
		ActorRole:   fbMsg.TunnelActorRolePUBLISHER,
	})
	_, code, message := manager.upsertTunnelDefinitionBeforeStart(ctx, staleReq, tunnelID, edgeID)
	if code != tunnelStartRevisionConflictCode {
		t.Fatalf("expected revision conflict for shared, got code=%d message=%s", code, message)
	}
}
