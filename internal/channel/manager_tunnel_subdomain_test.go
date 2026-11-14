package channel

import (
	"context"
	"net"
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	chtype "icool.io/yat/edge/internal/channel/types"
)

func buildTunnelStartSpecForSubdomainTest(
	t *testing.T,
	metadataJSON string,
	subdomain string,
) *fbMsg.TunnelChannelStartSpec {
	t.Helper()
	builder := flatbuffers.NewBuilder(256)
	spec := (&fbMsg.TunnelChannelStartSpecT{
		Key:                "tcp-main",
		Protocol:           "tcp",
		LocalHost:          "127.0.0.1",
		LocalPort:          8080,
		RemotePort:         0,
		AliasDomain:        "",
		BufferSize:         0,
		Transport:          "relay",
		EagerConnectRemote: false,
		MetadataJson:       metadataJSON,
		Subdomain:          subdomain,
	}).Pack(builder)
	builder.Finish(spec)
	return fbMsg.GetRootAsTunnelChannelStartSpec(builder.FinishedBytes(), 0)
}

func TestResolveTunnelStartSubdomain_FromMetadata(t *testing.T) {
	spec := buildTunnelStartSpecForSubdomainTest(t, `{"subdomain":"Video-Node-01"}`, "")
	got := resolveTunnelStartSubdomain(spec)
	if got != "video-node-01" {
		t.Fatalf("expected normalized subdomain from metadata, got %q", got)
	}
}

func TestResolveTunnelStartSubdomain_EmptyOnInvalidMetadata(t *testing.T) {
	spec := buildTunnelStartSpecForSubdomainTest(t, `{"subdomain":`, "")
	got := resolveTunnelStartSubdomain(spec)
	if got != "" {
		t.Fatalf("expected empty subdomain on invalid metadata, got %q", got)
	}
}

func TestResolveTunnelStartSubdomain_FieldPrecedence(t *testing.T) {
	spec := buildTunnelStartSpecForSubdomainTest(t, `{"subdomain":"from-metadata"}`, "From-Field")
	got := resolveTunnelStartSubdomain(spec)
	if got != "from-field" {
		t.Fatalf("expected explicit field subdomain precedence, got %q", got)
	}
}

func TestResolveTunnelStartSubdomainWithSource(t *testing.T) {
	tests := []struct {
		name       string
		metadata   string
		subdomain  string
		wantValue  string
		wantSource tunnelSubdomainResolveSource
	}{
		{
			name:       "from field",
			metadata:   `{"subdomain":"from-metadata"}`,
			subdomain:  "From-Field",
			wantValue:  "from-field",
			wantSource: tunnelSubdomainResolveSourceField,
		},
		{
			name:       "from metadata",
			metadata:   `{"subdomain":"From-Metadata"}`,
			subdomain:  "",
			wantValue:  "from-metadata",
			wantSource: tunnelSubdomainResolveSourceMetadata,
		},
		{
			name:       "empty on invalid metadata",
			metadata:   `{"subdomain":`,
			subdomain:  "",
			wantValue:  "",
			wantSource: tunnelSubdomainResolveSourceNone,
		},
		{
			name:       "empty on missing data",
			metadata:   "",
			subdomain:  "",
			wantValue:  "",
			wantSource: tunnelSubdomainResolveSourceNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := buildTunnelStartSpecForSubdomainTest(t, tc.metadata, tc.subdomain)
			gotValue, gotSource := resolveTunnelStartSubdomainWithSource(spec)
			if gotValue != tc.wantValue || gotSource != tc.wantSource {
				t.Fatalf(
					"unexpected result: value=%q source=%s, want value=%q source=%s",
					gotValue,
					gotSource,
					tc.wantValue,
					tc.wantSource,
				)
			}
		})
	}
}

func buildTunnelJoinRequestForSubdomainTest(
	t *testing.T,
	channels []*fbMsg.TunnelChannelStartSpecT,
) *fbMsg.TunnelJoinRequest {
	t.Helper()
	builder := flatbuffers.NewBuilder(512)
	req := (&fbMsg.TunnelJoinRequestT{
		TunnelId: "tunnel-subdomain-test",
		EdgeId:   "edge-subdomain-test",
		Mode:     fbMsg.TunnelStartModeALL_OR_NOTHING,
		Actor: &fbMsg.TunnelActorContextT{
			Role:      fbMsg.TunnelActorRoleCONSUMER,
			SessionId: "session-subdomain-test",
			DeviceId:  "device-subdomain-test",
		},
		Channels: channels,
	}).Pack(builder)
	builder.Finish(req)
	return fbMsg.GetRootAsTunnelJoinRequest(builder.FinishedBytes(), 0)
}

func TestReadTunnelJoinSubdomainHints(t *testing.T) {
	req := buildTunnelJoinRequestForSubdomainTest(t, []*fbMsg.TunnelChannelStartSpecT{
		{
			Key:          "alpha",
			Protocol:     "tcp",
			LocalHost:    "127.0.0.1",
			LocalPort:    8080,
			MetadataJson: `{"subdomain":"ignore-me"}`,
			Subdomain:    "From-Field",
		},
		{
			Key:          "beta",
			Protocol:     "udp",
			LocalHost:    "127.0.0.1",
			LocalPort:    5353,
			MetadataJson: `{"subdomain":"From-Metadata"}`,
		},
		{
			Key:       "alpha",
			Protocol:  "tcp",
			LocalHost: "127.0.0.1",
			LocalPort: 9090,
			Subdomain: "second-wins-should-not-happen",
		},
		{
			Key:       "",
			Protocol:  "tcp",
			LocalHost: "127.0.0.1",
			LocalPort: 10000,
			Subdomain: "blank-key",
		},
		{
			Key:          "gamma",
			Protocol:     "tcp",
			LocalHost:    "127.0.0.1",
			LocalPort:    10001,
			MetadataJson: `{"subdomain":`,
		},
	})

	hints, sourceCounts := readTunnelJoinSubdomainHints(req)
	if len(hints) != 2 {
		t.Fatalf("expected 2 subdomain hints, got %d (%v)", len(hints), hints)
	}
	if sourceCounts.field != 2 || sourceCounts.metadata != 1 || sourceCounts.none != 1 {
		t.Fatalf("unexpected source counts: field=%d metadata=%d none=%d", sourceCounts.field, sourceCounts.metadata, sourceCounts.none)
	}
	if got := hints["alpha"]; got != "from-field" {
		t.Fatalf("expected alpha subdomain from explicit field, got %q", got)
	}
	if got := hints["beta"]; got != "from-metadata" {
		t.Fatalf("expected beta subdomain from metadata fallback, got %q", got)
	}
	if _, exists := hints["gamma"]; exists {
		t.Fatalf("expected gamma hint to be skipped on invalid metadata, got %q", hints["gamma"])
	}
}

func TestReadTunnelJoinSubdomainHints_NilRequest(t *testing.T) {
	if got, sourceCounts := readTunnelJoinSubdomainHints(nil); got != nil {
		t.Fatalf("expected nil hints on nil request, got %v", got)
	} else if sourceCounts.field != 0 || sourceCounts.metadata != 0 || sourceCounts.none != 0 {
		t.Fatalf("expected zero source counts on nil request, got %+v", sourceCounts)
	}
}

func TestResolveTunnelJoinSubdomainMismatch(t *testing.T) {
	tests := []struct {
		name            string
		hints           map[string]string
		channelKey      string
		targetSubdomain string
		wantRequested   string
		wantTarget      string
		wantMismatch    bool
	}{
		{
			name:            "match",
			hints:           map[string]string{"alpha": "Video-Node-01"},
			channelKey:      "alpha",
			targetSubdomain: "video-node-01",
			wantRequested:   "video-node-01",
			wantTarget:      "video-node-01",
			wantMismatch:    false,
		},
		{
			name:            "mismatch",
			hints:           map[string]string{"alpha": "Video-Node-01"},
			channelKey:      "alpha",
			targetSubdomain: "other-node",
			wantRequested:   "video-node-01",
			wantTarget:      "other-node",
			wantMismatch:    true,
		},
		{
			name:            "missing hint",
			hints:           map[string]string{"beta": "node-b"},
			channelKey:      "alpha",
			targetSubdomain: "node-a",
			wantRequested:   "",
			wantTarget:      "",
			wantMismatch:    false,
		},
		{
			name:            "empty target ignored for compatibility",
			hints:           map[string]string{"alpha": "node-a"},
			channelKey:      "alpha",
			targetSubdomain: "",
			wantRequested:   "node-a",
			wantTarget:      "",
			wantMismatch:    false,
		},
		{
			name:            "nil hints",
			hints:           nil,
			channelKey:      "alpha",
			targetSubdomain: "node-a",
			wantRequested:   "",
			wantTarget:      "",
			wantMismatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requested, target, mismatch := resolveTunnelJoinSubdomainMismatch(tc.hints, tc.channelKey, tc.targetSubdomain)
			if requested != tc.wantRequested || target != tc.wantTarget || mismatch != tc.wantMismatch {
				t.Fatalf(
					"unexpected result: requested=%q target=%q mismatch=%v, want requested=%q target=%q mismatch=%v",
					requested,
					target,
					mismatch,
					tc.wantRequested,
					tc.wantTarget,
					tc.wantMismatch,
				)
			}
		})
	}
}

func TestChannelManagerSubdomainResolutionStats(t *testing.T) {
	mgr := &ChannelManager{}
	mgr.recordTunnelStartSubdomainResolution(tunnelSubdomainResolveSourceField)
	mgr.recordTunnelStartSubdomainResolution(tunnelSubdomainResolveSourceMetadata)
	mgr.recordTunnelStartSubdomainResolution(tunnelSubdomainResolveSourceNone)

	mgr.recordTunnelJoinSubdomainHintSources(tunnelJoinSubdomainHintSourceCounts{
		field:    2,
		metadata: 1,
		none:     3,
	})
	mgr.recordTunnelJoinSubdomainMismatch()
	mgr.recordTunnelJoinSubdomainMismatch()

	stats := mgr.GetSubdomainResolutionStats()
	if stats == nil {
		t.Fatalf("expected non-nil stats")
	}
	if stats.StartTotal != 3 || stats.StartFieldTotal != 1 || stats.StartMetadataFallbackTotal != 1 || stats.StartNoneTotal != 1 {
		t.Fatalf("unexpected start stats: %+v", stats)
	}
	if stats.JoinHintTotal != 6 || stats.JoinHintFieldTotal != 2 || stats.JoinHintMetadataFallbackTotal != 1 || stats.JoinHintNoneTotal != 3 {
		t.Fatalf("unexpected join hint stats: %+v", stats)
	}
	if stats.JoinHintMismatchTotal != 2 {
		t.Fatalf("unexpected mismatch count: %+v", stats)
	}
	if stats.UpdatedAtUnix <= 0 {
		t.Fatalf("expected updated timestamp in stats, got %+v", stats)
	}
}

func TestChannelManagerSubdomainResolutionStats_ZeroValue(t *testing.T) {
	mgr := &ChannelManager{}
	stats := mgr.GetSubdomainResolutionStats()
	if stats == nil {
		t.Fatalf("expected zero-value stats, got nil")
	}
	if stats.StartTotal != 0 ||
		stats.StartFieldTotal != 0 ||
		stats.StartMetadataFallbackTotal != 0 ||
		stats.StartNoneTotal != 0 ||
		stats.JoinHintTotal != 0 ||
		stats.JoinHintFieldTotal != 0 ||
		stats.JoinHintMetadataFallbackTotal != 0 ||
		stats.JoinHintNoneTotal != 0 ||
		stats.JoinHintMismatchTotal != 0 ||
		stats.UpdatedAtUnix != 0 {
		t.Fatalf("expected zero-value stats, got %+v", stats)
	}
}

type tunnelSubdomainTestProtocol struct {
	joinResponses []*fbMsg.TunnelJoinResponseT
}

func (p *tunnelSubdomainTestProtocol) SendError(conn net.Conn, errCode fbMsg.ErrorCode, errMsg, sessionID string) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendTunnelStartResponse(conn net.Conn, resp *fbMsg.TunnelStartResponseT, sessionID string) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendTunnelStopResponse(conn net.Conn, resp *fbMsg.TunnelStopResponseT, sessionID string) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendTunnelJoinResponse(conn net.Conn, resp *fbMsg.TunnelJoinResponseT, sessionID string) error {
	p.joinResponses = append(p.joinResponses, cloneTunnelJoinResponse(resp))
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendTunnelLeaveResponse(conn net.Conn, resp *fbMsg.TunnelLeaveResponseT, sessionID string) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendDataAck(conn net.Conn, channelID, connectionID string, seq uint32, sessionID string) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) WriteMessage(conn net.Conn, data []byte) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendPushRequest(
	conn net.Conn,
	requestID,
	channelID,
	method,
	path,
	query string,
	headers []HTTPHeader,
	body []byte,
	remoteAddr,
	sessionID string,
) error {
	return nil
}

func (p *tunnelSubdomainTestProtocol) SendDataPacket(
	conn net.Conn,
	channelID,
	connectionID string,
	seq uint32,
	data []byte,
	flags uint8,
	sessionID string,
) error {
	return nil
}

func cloneTunnelJoinResponse(resp *fbMsg.TunnelJoinResponseT) *fbMsg.TunnelJoinResponseT {
	if resp == nil {
		return nil
	}
	copied := *resp
	if resp.Summary != nil {
		summary := *resp.Summary
		copied.Summary = &summary
	}
	if len(resp.Channels) > 0 {
		copied.Channels = make([]*fbMsg.TunnelChannelStartResultT, len(resp.Channels))
		for i, item := range resp.Channels {
			if item == nil {
				continue
			}
			channel := *item
			copied.Channels[i] = &channel
		}
	}
	return &copied
}

func buildTunnelJoinMessageForSubdomainTest(t *testing.T, req *fbMsg.TunnelJoinRequestT, sessionID string) *fbMsg.Message {
	t.Helper()
	if req == nil {
		t.Fatalf("tunnel join request is required")
	}
	builder := flatbuffers.NewBuilder(1024)
	msg := (&fbMsg.MessageT{
		Header: &fbMsg.MessageHeaderT{
			Type:      fbMsg.MessageTypeTUNNEL_JOIN_REQUEST,
			Seq:       1,
			Timestamp: 1,
			SessionId: sessionID,
		},
		Body: &fbMsg.MessageBodyT{
			Type:  fbMsg.MessageBodyTunnelJoinRequest,
			Value: req,
		},
	}).Pack(builder)
	fbMsg.FinishMessageBuffer(builder, msg)
	return fbMsg.GetRootAsMessage(builder.FinishedBytes(), 0)
}

func TestHandleTunnelJoin_SubdomainMismatch_RecordsStatsAndStatus(t *testing.T) {
	const (
		ownerUserID     = "user-subdomain-join"
		publisherDevice = "device-publisher-join"
		consumerDevice  = "device-consumer-join"
		tunnelID        = "tunnel-subdomain-join"
		edgeID          = "edge-test-1"
		channelKey      = "alpha"
	)

	manager, err := NewChannelManager(&Config{
		DomainProvider:       &staticDomainProvider{assigned: "edge.example.com"},
		StatusDir:            t.TempDir(),
		EdgeID:               edgeID,
		MaxTargets:           128,
		MaxTargetsPerSession: 64,
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewChannelManager failed: %v", err)
	}

	store := manager.GetTunnelStore()
	if store == nil {
		t.Fatalf("tunnel store is nil")
	}

	if err := store.Upsert(context.Background(), &TunnelDefinitionRecord{
		EdgeID:         edgeID,
		OwnerUserID:    ownerUserID,
		TunnelID:       tunnelID,
		Name:           "subdomain join test",
		AppID:          "app.tcp",
		Protocol:       "tcp",
		IntentJSON:     `{"purpose":"test"}`,
		ConfigJSON:     `{}`,
		RuntimeJSON:    `{"status":"active"}`,
		State:          "active",
		ActorRole:      uint8(fbMsg.TunnelActorRolePUBLISHER),
		ActorSessionID: "session-publisher-join",
		ActorDeviceID:  publisherDevice,
	}); err != nil {
		t.Fatalf("failed to seed tunnel definition: %v", err)
	}

	channelID := composeTunnelChannelID(tunnelID, channelKey)
	target := NewChannel(
		channelID,
		fbMsg.ChannelTypeTCP,
		"transport-session-publisher-join",
		ownerUserID,
		publisherDevice,
		"publisher-host",
		"127.0.0.1:5900",
	)
	target.ActorRole = fbMsg.TunnelActorRolePUBLISHER
	target.ActorSessionID = "session-publisher-join"
	target.ActorDeviceID = publisherDevice
	target.ChannelKey = channelKey
	target.Protocol = "tcp"
	target.LinkType = "p2p"
	target.AllowRelayFallback = true
	target.Subdomain = "target-node"
	target.SetState(StateActive)
	manager.registry.targets[channelID] = target
	manager.registry.sessionTargets[target.SessionID] = append(manager.registry.sessionTargets[target.SessionID], channelID)

	protocol := &tunnelSubdomainTestProtocol{}
	ctx := &HandlerContext{
		SessionIdentity: chtype.SessionIdentity{
			SessionID: "transport-session-consumer-join",
			UserID:    ownerUserID,
			DeviceID:  consumerDevice,
			Hostname:  "consumer-host",
		},
		Protocol: protocol,
	}

	joinMsg := buildTunnelJoinMessageForSubdomainTest(t, &fbMsg.TunnelJoinRequestT{
		TunnelId: tunnelID,
		EdgeId:   edgeID,
		Mode:     fbMsg.TunnelStartModeALL_OR_NOTHING,
		Actor: &fbMsg.TunnelActorContextT{
			Role:      fbMsg.TunnelActorRoleCONSUMER,
			SessionId: "session-consumer-join",
			DeviceId:  consumerDevice,
		},
		Channels: []*fbMsg.TunnelChannelStartSpecT{
			{
				Key:       channelKey,
				Protocol:  "tcp",
				LocalHost: "127.0.0.1",
				LocalPort: 5900,
				Subdomain: "requested-node",
			},
		},
	}, ctx.SessionID)

	if err := manager.HandleTunnelJoin(ctx, joinMsg); err != nil {
		t.Fatalf("HandleTunnelJoin returned error: %v", err)
	}

	if len(protocol.joinResponses) != 1 {
		t.Fatalf("expected one join response, got %d", len(protocol.joinResponses))
	}
	resp := protocol.joinResponses[0]
	if resp == nil {
		t.Fatalf("expected non-nil join response")
	}
	if resp.Success {
		t.Fatalf("expected join response failure on subdomain mismatch, got success")
	}
	if resp.ErrorCode != uint32(fbMsg.ErrorCodeINVALID_MESSAGE) {
		t.Fatalf("unexpected error code: got=%d want=%d", resp.ErrorCode, uint32(fbMsg.ErrorCodeINVALID_MESSAGE))
	}
	if resp.ErrorMessage != "channel subdomain mismatch" {
		t.Fatalf("unexpected error message: %q", resp.ErrorMessage)
	}
	if resp.Summary == nil || resp.Summary.Requested != 1 || resp.Summary.Succeeded != 0 || resp.Summary.Failed != 1 {
		t.Fatalf("unexpected join summary: %+v", resp.Summary)
	}
	if len(resp.Channels) != 1 {
		t.Fatalf("expected one channel result, got %d", len(resp.Channels))
	}
	if result := resp.Channels[0]; result == nil {
		t.Fatalf("expected non-nil channel result")
	} else if result.Success || result.ErrorMessage != "channel subdomain mismatch" {
		t.Fatalf("unexpected channel result: %+v", result)
	}

	stats := manager.GetSubdomainResolutionStats()
	if stats == nil {
		t.Fatalf("expected non-nil subdomain stats")
	}
	if stats.JoinHintTotal != 1 || stats.JoinHintFieldTotal != 1 || stats.JoinHintMismatchTotal != 1 {
		t.Fatalf("unexpected subdomain stats after mismatch: %+v", stats)
	}

	status := manager.GetStatus()
	if status == nil || status.SubdomainResolution == nil {
		t.Fatalf("expected status subdomain resolution stats, got status=%+v", status)
	}
	if status.SubdomainResolution.JoinHintTotal != 1 ||
		status.SubdomainResolution.JoinHintFieldTotal != 1 ||
		status.SubdomainResolution.JoinHintMismatchTotal != 1 {
		t.Fatalf("unexpected status subdomain stats: %+v", status.SubdomainResolution)
	}
}
