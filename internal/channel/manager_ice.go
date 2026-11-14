package channel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel/ice"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	logger "icool.io/yat/edge/pkg/log"
)

type iceManagerBridge struct {
	manager *ChannelManager
}

// composeClientID returns the canonical client identifier used for push
// and ICE session tracking.  The canonical format is the bare deviceID,
// matching member.ClientID in the WireGuard layer and the key format of
// SessionManager.clientSessions.
func composeClientID(userID, deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return ""
	}
	return deviceID
}

func targetClientID(target *Channel) string {
	if target == nil {
		return ""
	}
	return composeClientID(target.UserID, target.DeviceID)
}

func (b *iceManagerBridge) SendToClient(clientID string, msgType int, payload []byte) error {
	if b.manager == nil || b.manager.clientPusher == nil {
		return nil
	}
	return b.manager.clientPusher.PushToClient(clientID, payload)
}

func (b *iceManagerBridge) GetTunnelLinkPolicy(tunnelID string) *ice.LinkPolicy {
	if b.manager == nil {
		return &ice.LinkPolicy{P2PMode: "preferred", AllowRelayFallback: true}
	}
	targets := b.manager.listTunnelTargets(tunnelID)
	for _, ch := range targets {
		if ch == nil {
			continue
		}
		return &ice.LinkPolicy{
			P2PMode:            linkTypeToP2PMode(ch.LinkType),
			AllowRelayFallback: ch.AllowRelayFallback,
			RequireDirect:      ch.RequireDirect,
		}
	}
	return &ice.LinkPolicy{P2PMode: "preferred", AllowRelayFallback: true}
}

func linkTypeToP2PMode(linkType string) string {
	switch linkType {
	case "p2p":
		return "required"
	case "relay":
		return "off"
	default:
		return "preferred"
	}
}

func (b *iceManagerBridge) ReportICEStateChange(
	iceSessionID string,
	tunnelID string,
	publisherSessionID string,
	consumerSessionID string,
	state ice.State,
	detail *ice.StateDetail,
) {
	if b.manager == nil {
		return
	}
	logger.Infof("[ICE] state change: session=%s state=%s", iceSessionID, state)
	b.syncRuntimeFromICEStateChange(
		iceSessionID,
		tunnelID,
		publisherSessionID,
		consumerSessionID,
		state,
		detail,
	)
	b.manager.NotifyStatusChange()
}

func (b *iceManagerBridge) syncRuntimeFromICEStateChange(
	iceSessionID string,
	tunnelID string,
	publisherSessionID string,
	consumerSessionID string,
	state ice.State,
	detail *ice.StateDetail,
) {
	if b == nil || b.manager == nil {
		return
	}

	m := b.manager
	m.mu.RLock()
	runtime := m.p2pRuntime
	m.mu.RUnlock()
	if runtime == nil {
		return
	}

	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return
	}
	iceSession := &ice.Session{
		ID:                 strings.TrimSpace(iceSessionID),
		TunnelID:           tunnelID,
		PublisherSessionID: strings.TrimSpace(publisherSessionID),
		ConsumerSessionID:  strings.TrimSpace(consumerSessionID),
	}
	if iceSession.ID == "" {
		return
	}

	policy := b.GetTunnelLinkPolicy(tunnelID)
	p2pSession := buildP2PSessionFromICE(iceSession, state, detail, policy)
	if p2pSession == nil {
		return
	}

	coord := runtime.Ensure(p2p.NamespaceQUIC)
	if coord == nil {
		return
	}
	if existing, exists := coord.GetSessionSnapshot(p2pSession.ID); exists && existing != nil {
		if !existing.CreatedAt.IsZero() {
			p2pSession.CreatedAt = existing.CreatedAt
		}
		if existing.PathType != p2p.PathUnknown && p2pSession.PathType == p2p.PathUnknown {
			p2pSession.PathType = existing.PathType
		}
		if strings.TrimSpace(p2pSession.LastError) == "" {
			p2pSession.LastError = strings.TrimSpace(existing.LastError)
		}
	} else {
		if err := coord.OnSessionCreated(p2pSession); err != nil {
			logger.Warnf("[ICE] on session created failed: session=%s err=%v", p2pSession.ID, err)
		}
	}
	if err := coord.OnSessionStateChange(p2pSession); err != nil {
		logger.Warnf("[ICE] on session state change failed: session=%s state=%s err=%v", p2pSession.ID, state, err)
	}

	if err := m.persistTunnelRuntimeSnapshot(tunnelID); err != nil {
		logger.Warnf("[ICE] persist tunnel runtime snapshot failed: tunnel=%s state=%s err=%v", tunnelID, state, err)
	}
}

func buildP2PSessionFromICE(
	session *ice.Session,
	state ice.State,
	detail *ice.StateDetail,
	policy *ice.LinkPolicy,
) *p2p.Session {
	if session == nil {
		return nil
	}

	status, pathType := mapICEStateToP2PSession(state)
	preferredLinks, allowRelayFallback, requireDirect := deriveP2PPolicyFromICELinkPolicy(policy)
	now := time.Now()
	lastError := ""
	if detail != nil {
		lastError = strings.TrimSpace(detail.Error)
	}

	return &p2p.Session{
		ID:                 strings.TrimSpace(session.ID),
		NetworkID:          strings.TrimSpace(session.TunnelID),
		InitiatorID:        strings.TrimSpace(session.PublisherSessionID),
		PeerA:              strings.TrimSpace(session.PublisherSessionID),
		PeerB:              strings.TrimSpace(session.ConsumerSessionID),
		Status:             status,
		PathType:           pathType,
		PreferredLinks:     preferredLinks,
		AllowRelayFallback: allowRelayFallback,
		RequireDirect:      requireDirect,
		CreatedAt:          now,
		UpdatedAt:          now,
		LastError:          lastError,
	}
}

func mapICEStateToP2PSession(state ice.State) (p2p.SessionStatus, p2p.PathType) {
	switch state {
	case ice.StateIdle:
		return p2p.SessionStatusNew, p2p.PathUnknown
	case ice.StateGathering, ice.StateChecking:
		return p2p.SessionStatusGathering, p2p.PathUnknown
	case ice.StatePunching:
		return p2p.SessionStatusPunching, p2p.PathUnknown
	case ice.StateConnecting:
		return p2p.SessionStatusEstablishing, p2p.PathUnknown
	case ice.StateConnected:
		return p2p.SessionStatusConnected, p2p.PathDirect
	case ice.StateFallback:
		return p2p.SessionStatusConnected, p2p.PathRelay
	case ice.StateFailed:
		return p2p.SessionStatusFailed, p2p.PathUnknown
	case ice.StateClosed:
		return p2p.SessionStatusClosed, p2p.PathUnknown
	default:
		return p2p.SessionStatusNew, p2p.PathUnknown
	}
}

func deriveP2PPolicyFromICELinkPolicy(policy *ice.LinkPolicy) ([]string, bool, bool) {
	allowRelayFallback := true
	requireDirect := false
	mode := "preferred"
	if policy != nil {
		allowRelayFallback = policy.AllowRelayFallback
		requireDirect = policy.RequireDirect
		if trimmed := strings.TrimSpace(policy.P2PMode); trimmed != "" {
			mode = trimmed
		}
	}

	preferredLinks := []string{"p2p", "relay"}
	switch mode {
	case "off":
		preferredLinks = []string{"relay"}
		allowRelayFallback = false
	case "required":
		preferredLinks = []string{"p2p"}
	}
	if !allowRelayFallback {
		preferredLinks = []string{"p2p"}
		if mode == "off" {
			preferredLinks = []string{"relay"}
		}
	}
	return preferredLinks, allowRelayFallback, requireDirect
}

func (m *ChannelManager) persistTunnelRuntimeSnapshot(tunnelID string) error {
	if m == nil {
		return nil
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return nil
	}

	snapshot := m.buildTunnelRuntimeSnapshot(tunnelID)
	if snapshot == nil {
		return nil
	}

	m.mu.RLock()
	store := m.tunnelStore
	edgeID := ""
	if m.config != nil {
		edgeID = strings.TrimSpace(m.config.EdgeID)
	}
	m.mu.RUnlock()
	if store == nil || edgeID == "" {
		return nil
	}

	updated, err := store.UpdateRuntimeSnapshotByEdgeAndTunnel(
		context.Background(),
		edgeID,
		tunnelID,
		snapshot.RuntimeJson,
		snapshot.State,
	)
	if err != nil {
		return err
	}
	if updated > 0 {
		logger.Debugf("[ICE] persisted tunnel runtime snapshot: tunnel=%s rows=%d", tunnelID, updated)
	}
	return nil
}

func (m *ChannelManager) setupICE(cfg *Config) error {
	if cfg.ICEConfig == nil {
		return nil
	}

	bridge := &iceManagerBridge{manager: m}
	m.iceController = ice.NewController(*cfg.ICEConfig, bridge)
	return nil
}

func (m *ChannelManager) GetICEController() *ice.Controller {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.iceController
}

func (m *ChannelManager) GetICEStats() *ice.ICEStats {
	ctrl := m.GetICEController()
	if ctrl == nil {
		return nil
	}
	stats := ctrl.Stats()
	return &stats
}

func (m *ChannelManager) OnPeerSessionPairReady(tunnelID, publisherClientID, consumerClientID string) {
	if m == nil {
		return
	}
	logger.Debugf("[ICE] peer session pair ready: tunnel=%s pubClient=%s conClient=%s", tunnelID, publisherClientID, consumerClientID)
	m.mu.RLock()
	ctrl := m.iceController
	m.mu.RUnlock()
	if ctrl == nil {
		logger.Debugf("[ICE] peer session pair ready but iceController is nil, skipping")
		return
	}
	ctrl.OnPeerSessionEstablished(tunnelID, publisherClientID, consumerClientID)
}

func (m *ChannelManager) maybeStartICE(tunnelID string) {
	if m.iceController == nil {
		logger.Debugf("[ICE] maybeStartICE: tunnel=%s skipped, iceController is nil", tunnelID)
		return
	}

	targets := m.listTunnelTargets(tunnelID)
	logger.Debugf("[ICE] maybeStartICE: tunnel=%s targets=%d", tunnelID, len(targets))
	pairs := collectICEPairsForTunnelTargets(tunnelID, targets)
	if len(pairs) == 0 {
		logger.Debugf("[ICE] maybeStartICE: tunnel=%s no publisher-consumer pair ready", tunnelID)
		return
	}

	for _, pair := range pairs {
		logger.Debugf(
			"[ICE] maybeStartICE: tunnel=%s triggering ICE, pubClient=%s conClient=%s",
			tunnelID,
			pair.publisherClientID,
			pair.consumerClientID,
		)
		go m.OnPeerSessionPairReady(tunnelID, pair.publisherClientID, pair.consumerClientID)
	}
}

func (m *ChannelManager) StartICEForConsumer(tunnelID, consumerUserID, consumerDeviceID string) error {
	if m == nil {
		return fmt.Errorf("channel manager is nil")
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return fmt.Errorf("missing tunnel id")
	}
	consumerClientID := composeClientID(consumerUserID, consumerDeviceID)
	if consumerClientID == "" {
		return fmt.Errorf("missing consumer identity")
	}

	m.mu.RLock()
	ctrl := m.iceController
	m.mu.RUnlock()
	if ctrl == nil {
		return fmt.Errorf("ice controller unavailable")
	}

	targets := m.listTunnelTargets(tunnelID)
	publisherClientID, ok := resolveActiveP2PPublisherClientID(tunnelID, targets)
	if !ok {
		return fmt.Errorf("tunnel has no active p2p publisher")
	}
	if publisherClientID == consumerClientID {
		return fmt.Errorf("publisher and consumer identities are the same")
	}

	logger.Debugf(
		"[ICE] start-for-consumer: tunnel=%s pubClient=%s conClient=%s",
		tunnelID,
		publisherClientID,
		consumerClientID,
	)
	go m.OnPeerSessionPairReady(tunnelID, publisherClientID, consumerClientID)
	return nil
}

func (m *ChannelManager) StopICEForConsumer(tunnelID, consumerUserID, consumerDeviceID, reason string) int {
	if m == nil {
		return 0
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return 0
	}
	consumerClientID := composeClientID(consumerUserID, consumerDeviceID)
	if consumerClientID == "" {
		return 0
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "consumer left tunnel"
	}

	m.mu.RLock()
	ctrl := m.iceController
	m.mu.RUnlock()
	if ctrl == nil {
		return 0
	}

	closed := ctrl.OnConsumerLeftTunnel(tunnelID, consumerClientID, reason)
	if closed > 0 {
		logger.Debugf(
			"[ICE] stop-for-consumer: tunnel=%s consumer=%s closed=%d",
			tunnelID,
			consumerClientID,
			closed,
		)
	}
	return closed
}

func (m *ChannelManager) maybeStopICEForStoppedTunnelTargets(tunnelID string, stoppedTargets []*Channel) {
	if m == nil || len(stoppedTargets) == 0 {
		return
	}

	m.mu.RLock()
	ctrl := m.iceController
	m.mu.RUnlock()
	if ctrl == nil {
		return
	}

	candidates := make(map[string]struct{}, len(stoppedTargets))
	for _, target := range stoppedTargets {
		if target == nil || strings.TrimSpace(target.LinkType) != "p2p" {
			continue
		}
		clientID := targetClientID(target)
		if clientID == "" {
			continue
		}
		candidates[clientID] = struct{}{}
	}
	if len(candidates) == 0 {
		return
	}

	for clientID := range candidates {
		if m.hasActiveP2PClientInTunnel(tunnelID, clientID) {
			continue
		}
		logger.Debugf("[ICE] stop: closing client session for tunnel=%s client=%s", tunnelID, clientID)
		ctrl.OnClientSessionDisconnected(clientID)
	}
}

func (m *ChannelManager) hasActiveP2PClientInTunnel(tunnelID, clientID string) bool {
	if m == nil || strings.TrimSpace(tunnelID) == "" || strings.TrimSpace(clientID) == "" {
		return false
	}
	targets := m.listTunnelTargets(tunnelID)
	for _, target := range targets {
		if target == nil {
			continue
		}
		if target.GetState() != StateActive || strings.TrimSpace(target.LinkType) != "p2p" {
			continue
		}
		if targetClientID(target) == clientID {
			return true
		}
	}
	return false
}

type iceClientPair struct {
	publisherClientID string
	consumerClientID  string
}

func collectICEPairsForTunnelTargets(tunnelID string, targets map[string]*Channel) []iceClientPair {
	publishers := make(map[string]struct{})
	consumers := make(map[string]struct{})

	for _, t := range targets {
		if t == nil {
			continue
		}
		state := t.GetState()
		clientID := targetClientID(t)
		logger.Debugf("[ICE] maybeStartICE: tunnel=%s session=%s client=%s role=%d state=%d linkType=%s",
			tunnelID, t.SessionID, clientID, t.ActorRole, state, t.LinkType)
		if state != StateActive || t.LinkType != "p2p" {
			continue
		}
		if clientID == "" {
			logger.Warnf("[ICE] maybeStartICE: tunnel=%s session=%s missing client identity (user=%q device=%q)",
				tunnelID, t.SessionID, strings.TrimSpace(t.UserID), strings.TrimSpace(t.DeviceID))
			continue
		}
		switch t.ActorRole {
		case fbMsg.TunnelActorRolePUBLISHER:
			publishers[clientID] = struct{}{}
		case fbMsg.TunnelActorRoleCONSUMER:
			consumers[clientID] = struct{}{}
		}
	}

	if len(publishers) == 0 || len(consumers) == 0 {
		return nil
	}

	publisherIDs := sortedClientIDs(publishers)
	consumerIDs := sortedClientIDs(consumers)
	// One tunnel is expected to have one effective publisher identity.
	// Pick a deterministic publisher and pair all consumers with it.
	publisherID := publisherIDs[0]

	pairs := make([]iceClientPair, 0, len(consumerIDs))
	for _, consumerID := range consumerIDs {
		if consumerID == publisherID {
			continue
		}
		pairs = append(pairs, iceClientPair{
			publisherClientID: publisherID,
			consumerClientID:  consumerID,
		})
	}
	return pairs
}

func sortedClientIDs(input map[string]struct{}) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, 0, len(input))
	for key := range input {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func resolveActiveP2PPublisherClientID(tunnelID string, targets map[string]*Channel) (string, bool) {
	publishers := make(map[string]struct{})
	for _, t := range targets {
		if t == nil {
			continue
		}
		if t.GetState() != StateActive || strings.TrimSpace(t.LinkType) != "p2p" {
			continue
		}
		if t.ActorRole != fbMsg.TunnelActorRolePUBLISHER {
			continue
		}
		clientID := targetClientID(t)
		if clientID == "" {
			logger.Warnf(
				"[ICE] resolve publisher skipped missing identity: tunnel=%s session=%s user=%q device=%q",
				tunnelID, t.SessionID, strings.TrimSpace(t.UserID), strings.TrimSpace(t.DeviceID),
			)
			continue
		}
		publishers[clientID] = struct{}{}
	}
	if len(publishers) == 0 {
		return "", false
	}
	publisherIDs := sortedClientIDs(publishers)
	if len(publisherIDs) == 0 {
		return "", false
	}
	return publisherIDs[0], true
}

func (m *ChannelManager) handleICEMessage(ctx *HandlerContext, msg *fbMsg.Message) error {
	if m.iceController == nil {
		return nil
	}

	msgType := msg.Header(nil).Type()
	table := new(flatbuffers.Table)
	if !msg.Body(table) {
		return nil
	}

	switch msgType {
	case fbMsg.MessageTypeICE_PUNCH_RESULT:
		var req fbMsg.ICEPunchResult
		req.Init(table.Bytes, table.Pos)
		senderSessionID := ""
		if ctx != nil {
			senderSessionID = composeClientID(ctx.UserID, ctx.DeviceID)
			if senderSessionID == "" {
				senderSessionID = ctx.SessionID
			}
		}
		result := &ice.PunchResult{
			Success:          req.Success(),
			PeerObservedAddr: string(req.PeerObservedAddr()),
			AttemptsSent:     int(req.AttemptsSent()),
			FailureReason:    string(req.FailureReason()),
		}
		m.iceController.OnPunchResultReceived(senderSessionID, string(req.IceSessionId()), result)

	case fbMsg.MessageTypeICE_QUIC_CONNECTED:
		var req fbMsg.ICEQuicConnected
		req.Init(table.Bytes, table.Pos)
		connInfo := &ice.QuicConnInfo{
			ConnectionID: string(req.ConnectionId()),
			LocalAddr:    string(req.LocalAddr()),
			PeerAddr:     string(req.PeerAddr()),
			RTTMs:        req.RttMs(),
		}
		m.iceController.OnQuicConnected(string(req.IceSessionId()), connInfo)
	}

	return nil
}
