package ice

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	message "icool.io/yat/api/build/fb/golang/message"
	p2p "icool.io/yat/edge/internal/channel/p2p"
	logger "icool.io/yat/edge/pkg/log"
)

func tokenPreview(token string) string {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return "<empty>"
	}
	if len(trimmed) > 8 {
		return trimmed[:8] + "..."
	}
	return trimmed
}

func shouldPromoteAltProbe(session *Session, role string) bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	switch role {
	case "pub":
		return session.PublisherEndpoint == nil || session.PublisherEndpoint.UDPAddr == nil
	case "con":
		return session.ConsumerEndpoint == nil || session.ConsumerEndpoint.UDPAddr == nil
	default:
		return false
	}
}

const (
	natFilterProbeAttempts = 3
	natFilterProbeTimeout  = 120 * time.Millisecond
	natFilterProbeInterval = 25 * time.Millisecond

	portPredictPreferredWindow      = 4 * time.Second
	portPredictPreferredMaxAttempts = 80
	portPredictPreferredExtraCount  = 4
	portPredictPreferredTimeoutCap  = 8 * time.Second

	portPredictRequireWindow      = 12 * time.Second
	portPredictRequireMaxAttempts = 180
	portPredictRequireExtraCount  = 5
	portPredictRequireTimeoutCap  = 12 * time.Second
	portPredictRequireBurst       = 2

	standardPredictExtraCount  = 4
	standardPredictMinAttempts = 20
	standardPredictMinTimeout  = 3 * time.Second
	standardPredictBurst       = 2
)

const (
	msgTypeICEStart = message.MessageTypeICE_START
	msgTypeICEPunch = message.MessageTypeICE_PUNCH
	msgTypeICEQuic  = message.MessageTypeICE_QUIC_START
	msgTypeICEState = message.MessageTypeICE_STATE
)

type ChannelManagerBridge interface {
	SendToClient(sessionID string, msgType int, payload []byte) error
	GetTunnelLinkPolicy(tunnelID string) *LinkPolicy
	ReportICEStateChange(
		iceSessionID string,
		tunnelID string,
		publisherSessionID string,
		consumerSessionID string,
		state State,
		detail *StateDetail,
	)
}

type LinkPolicy struct {
	P2PMode            string // "off", "preferred", "required"
	AllowRelayFallback bool
	RequireDirect      bool
}

type portPredictPlan struct {
	attempts        uint32
	extraCount      int
	timeout         time.Duration
	burstPerAttempt int
}

type Controller struct {
	config      Config
	udpListener *UDPListener
	protocol    *Protocol
	sessions    map[string]*Session
	tokenIndex  map[string]*tokenEntry
	natDetector *NATDetector
	bridge      ChannelManagerBridge
	mu          sync.RWMutex
	stopCh      chan struct{}
	running     bool

	punchAttempts     uint64
	punchSuccesses    uint64
	punchFailures     uint64
	punchLatencySumMs float64
	punchLatencyCount uint64
	attemptsSentSum   uint64
	attemptsSamples   uint64
}

type tokenEntry struct {
	sessionID string
	role      string // "pub" or "con"
}

func NewController(cfg Config, bridge ChannelManagerBridge) *Controller {
	return &Controller{
		config:      cfg,
		sessions:    make(map[string]*Session),
		tokenIndex:  make(map[string]*tokenEntry),
		natDetector: NewNATDetector(),
		protocol:    NewProtocol(),
		bridge:      bridge,
		stopCh:      make(chan struct{}),
	}
}

func (c *Controller) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	listener, err := NewUDPListener(c.config.UDPAddr, c.config.UDPAddrAlt, c)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("start udp listener: %w", err)
	}
	c.stopCh = make(chan struct{})
	c.running = true
	c.udpListener = listener
	// Register the listener workers before Stop can close it and wait for them.
	// Serve starts its read goroutines without calling back synchronously.
	listener.Serve()
	go c.sessionGCLoop(c.stopCh)
	c.mu.Unlock()
	logger.Infof("ICE controller started, udp=%s alt=%s",
		listener.Addr(), listener.AddrAlt())
	return nil
}

func (c *Controller) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	close(c.stopCh)
	listener := c.udpListener
	c.udpListener = nil
	c.mu.Unlock()

	if listener != nil {
		listener.Close()
	}
	logger.Info("ICE controller stopped")
}

func (c *Controller) OnPeerSessionEstablished(tunnelID, publisherSessionID, consumerSessionID string) {
	c.mu.Lock()

	for _, s := range c.sessions {
		if s.TunnelID != tunnelID || s.GetState().IsTerminal() {
			continue
		}
		if s.PublisherSessionID == publisherSessionID && s.ConsumerSessionID == consumerSessionID {
			logger.Infof(
				"ICE session already active for pair tunnel=%s pub=%s con=%s: %s",
				tunnelID, publisherSessionID, consumerSessionID, s.ID,
			)
			c.mu.Unlock()
			return
		}
	}

	session, err := NewSession(tunnelID, publisherSessionID, consumerSessionID)
	if err != nil {
		c.mu.Unlock()
		logger.Errorf("failed to create ICE session for tunnel %s: %v", tunnelID, err)
		return
	}

	c.sessions[session.ID] = session
	c.tokenIndex[session.PubToken] = &tokenEntry{sessionID: session.ID, role: "pub"}
	c.tokenIndex[session.ConToken] = &tokenEntry{sessionID: session.ID, role: "con"}
	c.mu.Unlock()
	logger.Infof("ICE session created: %s for tunnel %s", session.ID, tunnelID)

	if err := session.Transition(StateGathering); err != nil {
		logger.Errorf("ICE session %s transition to gathering failed: %v", session.ID, err)
		return
	}

	c.reportState(session, nil)
	go c.startGathering(session)
}

// GetPwdByToken returns the ICE session pwd associated with the given
// per-peer token (ufrag). Used by the UDP listener to verify HMAC on
// inbound probe/punch packets before delivering them to the controller.
// Returns ("", false) if no session owns this token.
func (c *Controller) GetPwdByToken(token string) (string, bool) {
	c.mu.RLock()
	entry, ok := c.tokenIndex[token]
	if !ok {
		c.mu.RUnlock()
		return "", false
	}
	session, exists := c.sessions[entry.sessionID]
	c.mu.RUnlock()
	if !exists {
		return "", false
	}
	return session.Pwd, true
}

func (c *Controller) OnUDPProbeReceived(token string, addr *net.UDPAddr, isAlt bool) {
	c.mu.RLock()
	entry, ok := c.tokenIndex[token]
	if !ok {
		c.mu.RUnlock()
		return
	}
	session, exists := c.sessions[entry.sessionID]
	c.mu.RUnlock()
	if !exists || session.GetState() != StateGathering {
		return
	}
	logger.Debugf(
		"ICE probe received: session=%s tunnel=%s role=%s alt=%v token=%s from=%s",
		session.ID, session.TunnelID, entry.role, isAlt, tokenPreview(token), addr,
	)

	c.natDetector.RecordProbe(token, addr, isAlt)
	c.maybeStartNATFilterProbe(token, session, entry.role)

	natType, detected := c.natDetector.Detect(token)
	if !detected {
		natType = p2p.NATUnknown
	}
	if isAlt && !shouldPromoteAltProbe(session, entry.role) {
		// Prefer primary endpoint when already available; keep alt only for NAT detect.
		return
	}

	endpoint := &PeerEndpoint{
		SessionID: session.ID,
		ClientID:  token,
		UDPAddr:   addr,
		NATType:   natType,
	}
	if isAlt {
		logger.Debugf(
			"ICE alt probe promoted as endpoint: session=%s tunnel=%s role=%s token=%s addr=%s",
			session.ID, session.TunnelID, entry.role, tokenPreview(token), addr,
		)
	}

	if entry.role == "pub" {
		endpoint.SessionID = session.PublisherSessionID
		c.handleProbe(session, endpoint)
	} else {
		endpoint.SessionID = session.ConsumerSessionID
		c.handleProbe(session, endpoint)
	}
}

func (c *Controller) maybeStartNATFilterProbe(token string, session *Session, role string) {
	mappedAddr, ok := c.natDetector.StartFilterProbe(token)
	if !ok || mappedAddr == nil {
		return
	}
	pwd, ok := c.GetPwdByToken(token)
	if !ok || strings.TrimSpace(pwd) == "" {
		return
	}
	logger.Debugf(
		"ICE NAT filter probe scheduled: session=%s tunnel=%s role=%s token=%s target=%s",
		session.ID, session.TunnelID, role, tokenPreview(token), mappedAddr,
	)
	go c.runNATFilterProbe(token, pwd, mappedAddr)
}

func (c *Controller) runNATFilterProbe(token, pwd string, target *net.UDPAddr) {
	if target == nil {
		return
	}
	network := "udp4"
	if target.IP != nil && target.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		logger.Warnf("ICE NAT filter probe listen failed (token=%s target=%s): %v", tokenPreview(token), target, err)
		return
	}
	defer conn.Close()

	packet := buildUDPPacket(UDPPacketProbeFilterChallenge, token, pwd)
	buf := make([]byte, 1500)
	passed := false

	for attempt := 1; attempt <= natFilterProbeAttempts; attempt++ {
		if _, err := conn.WriteToUDP(packet, target); err != nil {
			logger.Debugf(
				"ICE NAT filter probe send failed attempt=%d token=%s target=%s err=%v",
				attempt, tokenPreview(token), target, err,
			)
		}
		if err := conn.SetReadDeadline(time.Now().Add(natFilterProbeTimeout)); err != nil {
			break
		}

		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if isValidNATFilterAck(buf[:n], token, pwd) {
				passed = true
				logger.Debugf(
					"ICE NAT filter probe ack received attempt=%d token=%s from=%s",
					attempt, tokenPreview(token), from,
				)
				break
			}
		}
		if passed {
			break
		}
		if attempt < natFilterProbeAttempts {
			select {
			case <-time.After(natFilterProbeInterval):
			case <-c.stopCh:
				return
			}
		}
	}

	natType, ok := c.natDetector.RecordFilterProbeResult(token, passed)
	if !ok {
		return
	}
	c.updateEndpointNATType(token, natType)
	logger.Infof(
		"ICE NAT filter probe done: token=%s passed=%t classified=%s",
		tokenPreview(token), passed, natType,
	)
}

func (c *Controller) updateEndpointNATType(token string, natType p2p.NATType) {
	c.mu.RLock()
	entry, ok := c.tokenIndex[token]
	if !ok {
		c.mu.RUnlock()
		return
	}
	session, exists := c.sessions[entry.sessionID]
	c.mu.RUnlock()
	if !exists {
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	switch entry.role {
	case "pub":
		if session.PublisherEndpoint != nil {
			session.PublisherEndpoint.NATType = natType
		}
	case "con":
		if session.ConsumerEndpoint != nil {
			session.ConsumerEndpoint.NATType = natType
		}
	}
}

func isValidNATFilterAck(packet []byte, token, pwd string) bool {
	if len(packet) < udpPacketLen {
		return false
	}
	if binary.BigEndian.Uint32(packet[0:4]) != UDPMagic {
		return false
	}
	pktType := UDPPacketType(packet[4])
	if pktType != UDPPacketProbeFilterAck {
		return false
	}
	ufrag := string(packet[5:37])
	if strings.TrimRight(ufrag, " ") != strings.TrimSpace(token) {
		return false
	}
	if !verifyUDPPacketMAC(pwd, UDPMagic, byte(pktType), ufrag, packet[37:69]) {
		return false
	}
	return true
}

func (c *Controller) OnPunchResultReceived(senderSessionID, sessionID string, result *PunchResult) {
	c.mu.RLock()
	session, ok := c.sessions[sessionID]
	c.mu.RUnlock()
	if !ok {
		logger.Warnf("ICE punch result for unknown session: %s", sessionID)
		return
	}

	observation := session.recordPunchResult(senderSessionID, result)
	role := observation.role
	pubPunchOK := observation.succeeded[0]
	conPunchOK := observation.succeeded[1]
	punchStartedAt := observation.startedAt

	c.mu.Lock()
	c.punchAttempts++
	if result.AttemptsSent > 0 {
		c.attemptsSentSum += uint64(result.AttemptsSent)
		c.attemptsSamples++
	}
	if result.Success {
		c.punchSuccesses++
		latencyMs := float64(time.Since(punchStartedAt).Milliseconds())
		c.punchLatencySumMs += latencyMs
		c.punchLatencyCount++
	} else {
		c.punchFailures++
	}
	c.mu.Unlock()

	session.mu.Lock()
	pubNAT := p2p.NATUnknown
	conNAT := p2p.NATUnknown
	if session.PublisherEndpoint != nil {
		pubNAT = session.PublisherEndpoint.NATType
	}
	if session.ConsumerEndpoint != nil {
		conNAT = session.ConsumerEndpoint.NATType
	}
	session.mu.Unlock()
	logger.Infof(
		"ICE punch result: session=%s role=%s success=%t attempts_sent=%d reason=%s pub_nat=%s con_nat=%s peer_observed=%s",
		sessionID,
		role,
		result.Success,
		result.AttemptsSent,
		result.FailureReason,
		pubNAT,
		conNAT,
		result.PeerObservedAddr,
	)

	if result.Success {
		if !pubPunchOK || !conPunchOK {
			logger.Debugf(
				"ICE session %s waiting for both punch successes (pub_ok=%t con_ok=%t, latest_role=%s)",
				sessionID, pubPunchOK, conPunchOK, role,
			)
			return
		}
		if session.GetState() != StatePunching {
			logger.Debugf(
				"ICE session %s ignore punch success in state=%s (role=%s)",
				sessionID, session.GetState(), role,
			)
			return
		}
		if err := session.Transition(StateConnecting); err != nil {
			logger.Errorf("ICE session %s transition to connecting failed: %v", sessionID, err)
			return
		}
		logger.Infof("ICE session %s: both peers reported punch success; entering connecting", sessionID)
		c.reportState(session, nil)
		go c.startQuicConnect(session)
	} else {
		state := session.GetState()
		if state == StateConnecting || state == StateConnected {
			logger.Debugf(
				"ICE session %s ignore late punch failure in state=%s (role=%s reason=%s)",
				sessionID, state, role, result.FailureReason,
			)
			return
		}
		c.handlePunchFailed(session, result.FailureReason)
	}
}

func (c *Controller) OnQuicConnected(sessionID string, connInfo *QuicConnInfo) {
	c.mu.RLock()
	session, ok := c.sessions[sessionID]
	c.mu.RUnlock()
	if !ok {
		return
	}

	session.mu.Lock()
	session.QuicConn = connInfo
	session.mu.Unlock()

	if err := session.Transition(StateConnected); err != nil {
		logger.Errorf("ICE session %s transition to connected failed: %v", sessionID, err)
		return
	}
	c.reportState(session, nil)
	c.cleanupSession(session)
	logger.Infof("ICE session %s connected via QUIC, connID=%s", sessionID, connInfo.ConnectionID)
}

func (c *Controller) OnSessionClosed(sessionID string) {
	c.mu.Lock()
	session, ok := c.sessions[sessionID]
	c.mu.Unlock()
	if !ok {
		return
	}
	_ = session.Transition(StateClosed)
	c.reportState(session, nil)
	c.cleanupSession(session)
}

func (c *Controller) OnClientSessionDisconnected(clientSessionID string) {
	c.mu.RLock()
	var affected []*Session
	for _, s := range c.sessions {
		if s.GetState().IsTerminal() {
			continue
		}
		if s.PublisherSessionID == clientSessionID || s.ConsumerSessionID == clientSessionID {
			affected = append(affected, s)
		}
	}
	c.mu.RUnlock()

	for _, s := range affected {
		if err := s.Transition(StateClosed); err != nil {
			continue
		}
		s.mu.Lock()
		s.Error = "client disconnected: " + clientSessionID
		s.mu.Unlock()
		c.reportState(s, &StateDetail{Error: s.Error})
		c.cleanupSession(s)
		logger.Infof("ICE session %s closed: client %s disconnected", s.ID, clientSessionID)
	}
}

func (c *Controller) OnConsumerLeftTunnel(tunnelID, consumerSessionID, reason string) int {
	tunnelID = strings.TrimSpace(tunnelID)
	consumerSessionID = strings.TrimSpace(consumerSessionID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "consumer left tunnel"
	}
	if tunnelID == "" || consumerSessionID == "" {
		return 0
	}

	c.mu.RLock()
	var affected []*Session
	for _, s := range c.sessions {
		if s.GetState().IsTerminal() {
			continue
		}
		if s.TunnelID == tunnelID && s.ConsumerSessionID == consumerSessionID {
			affected = append(affected, s)
		}
	}
	c.mu.RUnlock()

	closed := 0
	for _, s := range affected {
		if err := s.Transition(StateClosed); err != nil {
			continue
		}
		s.mu.Lock()
		s.Error = reason
		s.mu.Unlock()
		c.reportState(s, &StateDetail{Error: s.Error})
		c.cleanupSession(s)
		closed++
		logger.Infof(
			"ICE session %s closed: consumer left tunnel=%s consumer=%s",
			s.ID, tunnelID, consumerSessionID,
		)
	}
	return closed
}

func (c *Controller) cleanupSession(session *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.tokenIndex, session.PubToken)
	delete(c.tokenIndex, session.ConToken)
	c.natDetector.Clear(session.PubToken)
	c.natDetector.Clear(session.ConToken)
}

func (c *Controller) GetSession(id string) (*Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.sessions[id]
	return s, ok
}

func (c *Controller) Snapshot() *ControllerSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := &ControllerSnapshot{
		TotalCount: len(c.sessions),
	}
	if c.udpListener != nil {
		snap.UDPAddr = c.udpListener.Addr()
		snap.UDPAddrAlt = c.udpListener.AddrAlt()
	}

	for _, s := range c.sessions {
		ss := s.Snapshot()
		snap.Sessions = append(snap.Sessions, ss)
		if !ss.State.IsTerminal() {
			snap.ActiveCount++
		}
	}
	return snap
}

func (c *Controller) Stats() ICEStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := ICEStats{
		TotalSessions:   uint32(len(c.sessions)),
		SessionsByState: make(map[State]uint32),
		PunchAttempts:   c.punchAttempts,
		PunchSuccesses:  c.punchSuccesses,
		PunchFailures:   c.punchFailures,
		AttemptsSamples: c.attemptsSamples,
	}
	for _, s := range c.sessions {
		state := s.GetState()
		stats.SessionsByState[state]++
		if !state.IsTerminal() {
			stats.ActiveSessions++
		}
	}
	if c.punchLatencyCount > 0 {
		stats.AvgPunchLatency = c.punchLatencySumMs / float64(c.punchLatencyCount)
	}
	if c.attemptsSamples > 0 {
		stats.AvgAttemptsSent = float64(c.attemptsSentSum) / float64(c.attemptsSamples)
	}
	return stats
}

func resolveAdvertiseAddr(listenAddr, advertiseHost string) string {
	normalizedListen := strings.TrimSpace(listenAddr)
	if normalizedListen == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(normalizedListen)
	if err != nil {
		return normalizedListen
	}
	if strings.TrimSpace(advertiseHost) == "" {
		return normalizedListen
	}
	if !isUnspecifiedHost(host) {
		return normalizedListen
	}
	return net.JoinHostPort(strings.TrimSpace(advertiseHost), port)
}

func isUnspecifiedHost(host string) bool {
	normalized := strings.Trim(strings.TrimSpace(host), "[]")
	if normalized == "" {
		return true
	}
	if normalized == "0.0.0.0" || normalized == "::" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsUnspecified()
}

func (c *Controller) startGathering(session *Session) {
	c.mu.RLock()
	if !c.running || c.udpListener == nil {
		c.mu.RUnlock()
		return
	}
	udpAddr, udpAddrAlt := c.udpListener.Addr(), c.udpListener.AddrAlt()
	stopCh := c.stopCh
	c.mu.RUnlock()
	// Never hold the controller lock across Bridge callbacks: they may reenter
	// Snapshot or Stop. This attempt keeps the cancellation captured with its
	// listener addresses instead of looking up a later controller run.
	c.gatherEndpoints(session, udpAddr, udpAddrAlt, stopCh)
}

// Listener ownership stays with ICE. Keeping resolved listener addresses at
// this boundary also permits orchestration regression without opening sockets.
func (c *Controller) gatherEndpoints(session *Session, udpListenAddr, udpListenAddrAlt string, stopCh <-chan struct{}) {
	logger.Infof("ICE session %s: waiting for UDP probes from peers", session.ID)

	gatherMs := uint32(c.config.GatherTimeout.Milliseconds())
	udpAddr := resolveAdvertiseAddr(udpListenAddr, c.config.AdvertiseHost)
	udpAddrAlt := resolveAdvertiseAddr(udpListenAddrAlt, c.config.AdvertiseHost)

	if udpAddr != udpListenAddr || udpAddrAlt != udpListenAddrAlt {
		logger.Debugf(
			"ICE session %s: advertise udp addr rewritten listen=(%s,%s) advertise=(%s,%s) host=%s",
			session.ID,
			udpListenAddr,
			udpListenAddrAlt,
			udpAddr,
			udpAddrAlt,
			strings.TrimSpace(c.config.AdvertiseHost),
		)
	}

	pubMsg := c.protocol.BuildICEStart(session.ID, session.TunnelID, session.PubToken, session.Pwd, udpAddr, udpAddrAlt, gatherMs)
	conMsg := c.protocol.BuildICEStart(session.ID, session.TunnelID, session.ConToken, session.Pwd, udpAddr, udpAddrAlt, gatherMs)

	retryInterval := c.config.PunchInterval
	if retryInterval <= 0 {
		retryInterval = 500 * time.Millisecond
	} else {
		if retryInterval < 500*time.Millisecond {
			retryInterval = 500 * time.Millisecond
		} else if retryInterval > time.Second {
			retryInterval = time.Second
		}
	}
	window := session.phaseWindow(StateGathering, c.config.GatherTimeout)
	attempt := 1
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		if session.GetState() != StateGathering || session.BothEndpointsReady() {
			return
		}

		if err := c.bridge.SendToClient(session.PublisherSessionID, int(msgTypeICEStart), pubMsg); err != nil {
			logger.Errorf("ICE session %s: send ICE_START to publisher failed: %v", session.ID, err)
		}
		select {
		case <-stopCh:
			return
		default:
		}
		if err := c.bridge.SendToClient(session.ConsumerSessionID, int(msgTypeICEStart), conMsg); err != nil {
			logger.Errorf("ICE session %s: send ICE_START to consumer failed: %v", session.ID, err)
		}
		if attempt > 1 {
			logger.Debugf(
				"ICE session %s: retransmit ICE_START attempt=%d (pub=%s con=%s)",
				session.ID, attempt, session.PublisherSessionID, session.ConsumerSessionID,
			)
		}

		if session.GetState() != StateGathering || session.BothEndpointsReady() {
			return
		}

		remaining := window.Remaining(time.Now())
		if remaining <= 0 {
			break
		}
		wait := retryInterval
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-time.After(wait):
		case <-stopCh:
			return
		}
		attempt++
	}

	select {
	case <-stopCh:
		return
	default:
	}
	if !session.phaseTimeoutDue(window, time.Now()) {
		return
	}
	session.mu.Lock()
	pubReady := session.PublisherEndpoint != nil && session.PublisherEndpoint.UDPAddr != nil
	conReady := session.ConsumerEndpoint != nil && session.ConsumerEndpoint.UDPAddr != nil
	pubAddr := "<nil>"
	conAddr := "<nil>"
	if session.PublisherEndpoint != nil && session.PublisherEndpoint.UDPAddr != nil {
		pubAddr = session.PublisherEndpoint.UDPAddr.String()
	}
	if session.ConsumerEndpoint != nil && session.ConsumerEndpoint.UDPAddr != nil {
		conAddr = session.ConsumerEndpoint.UDPAddr.String()
	}
	session.mu.Unlock()
	c.handlePunchFailed(
		session,
		fmt.Sprintf(
			"gather timeout: probes not received (pub_ready=%t pub_addr=%s con_ready=%t con_addr=%s)",
			pubReady, pubAddr, conReady, conAddr,
		),
	)
}

func (c *Controller) sessionGCLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.gcStaleSessions()
		case <-stopCh:
			return
		}
	}
}

func (c *Controller) gcStaleSessions() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, s := range c.sessions {
		s.mu.Lock()
		state := s.State
		updated := s.UpdatedAt
		s.mu.Unlock()

		if state.IsTerminal() && now.Sub(updated) > c.config.SessionRetention {
			delete(c.sessions, id)
			logger.Infof("ICE session %s GC'd (state=%s)", id, state)
		}
	}
}

func (c *Controller) handleProbe(session *Session, endpoint *PeerEndpoint) {
	if endpoint.SessionID == session.PublisherSessionID {
		session.SetPublisherEndpoint(endpoint)
	} else if endpoint.SessionID == session.ConsumerSessionID {
		session.SetConsumerEndpoint(endpoint)
	}

	if session.BothEndpointsReady() {
		strategy := session.DetermineStrategy()
		session.mu.Lock()
		session.Strategy = strategy
		session.mu.Unlock()

		if strategy == StrategyRelay {
			c.handlePunchFailed(session, "symmetric+symmetric NAT, relay required")
			return
		}

		if err := session.Transition(StatePunching); err != nil {
			logger.Errorf("ICE session %s transition to punching failed: %v", session.ID, err)
			return
		}
		c.reportState(session, &StateDetail{PunchStrategy: strategy})
		go c.startPunching(session)
	}
}

func (c *Controller) startPunching(session *Session) {
	logger.Infof("ICE session %s: coordinating punch (strategy=%s)", session.ID, session.Strategy)

	session.mu.Lock()
	pubEP := session.PublisherEndpoint
	conEP := session.ConsumerEndpoint
	strategy := session.Strategy
	session.mu.Unlock()

	attempts := uint32(c.config.PunchAttempts)
	intervalMs := uint32(c.config.PunchInterval.Milliseconds())
	punchTimeout := c.config.PunchTimeout

	var pubExtra, conExtra []string
	if strategy == StrategyPortPredict {
		policy := c.bridge.GetTunnelLinkPolicy(session.TunnelID)
		plan := computePortPredictPlan(c.config, policy)
		hintSent := plan.burstPerAttempt > 1
		if pubEP.NATType == p2p.NATSymmetric {
			pubExtra = c.natDetector.PredictPorts(session.PubToken, pubEP.UDPAddr.IP.String(), plan.extraCount)
		}
		if conEP.NATType == p2p.NATSymmetric {
			conExtra = c.natDetector.PredictPorts(session.ConToken, conEP.UDPAddr.IP.String(), plan.extraCount)
		}
		pubExtra = attachBurstHint(pubExtra, plan.burstPerAttempt)
		conExtra = attachBurstHint(conExtra, plan.burstPerAttempt)
		attempts = plan.attempts
		punchTimeout = plan.timeout
		logger.Infof(
			"ICE session %s: port_predict profile require_direct=%t attempts=%d interval_ms=%d extra_count=%d timeout_ms=%d burst_per_attempt=%d hint_sent=%t pub_targets=%d con_targets=%d",
			session.ID,
			policy != nil && policy.RequireDirect,
			attempts,
			intervalMs,
			plan.extraCount,
			punchTimeout.Milliseconds(),
			plan.burstPerAttempt,
			hintSent,
			len(conExtra)+1, // publisher punches toward consumer targets
			len(pubExtra)+1, // consumer punches toward publisher targets
		)
	} else {
		// Even under "standard" strategy, destination-dependent NAT mapping can still
		// miss the exact peer port. Add a conservative predicted ring to improve hit rate.
		pubExtra = c.natDetector.PredictPorts(session.PubToken, pubEP.UDPAddr.IP.String(), standardPredictExtraCount)
		conExtra = c.natDetector.PredictPorts(session.ConToken, conEP.UDPAddr.IP.String(), standardPredictExtraCount)
		if len(pubExtra) > 0 || len(conExtra) > 0 {
			pubExtra = attachBurstHint(pubExtra, standardPredictBurst)
			conExtra = attachBurstHint(conExtra, standardPredictBurst)
			if attempts < standardPredictMinAttempts {
				attempts = standardPredictMinAttempts
			}
			if punchTimeout < standardPredictMinTimeout {
				punchTimeout = standardPredictMinTimeout
			}
			logger.Infof(
				"ICE session %s: standard profile predictive extras enabled attempts=%d interval_ms=%d timeout_ms=%d burst_per_attempt=%d pub_targets=%d con_targets=%d",
				session.ID,
				attempts,
				intervalMs,
				punchTimeout.Milliseconds(),
				standardPredictBurst,
				len(conExtra)+1, // publisher punches toward consumer targets
				len(pubExtra)+1, // consumer punches toward publisher targets
			)
		}
	}

	pubMsg := c.protocol.BuildICEPunch(session.ID, conEP.UDPAddr.String(), session.PubToken, session.Pwd, attempts, intervalMs, 0, conExtra)
	conMsg := c.protocol.BuildICEPunch(session.ID, pubEP.UDPAddr.String(), session.ConToken, session.Pwd, attempts, intervalMs, 0, pubExtra)

	if err := c.bridge.SendToClient(session.PublisherSessionID, int(msgTypeICEPunch), pubMsg); err != nil {
		logger.Errorf("ICE session %s: send ICE_PUNCH to publisher failed: %v", session.ID, err)
	}
	if err := c.bridge.SendToClient(session.ConsumerSessionID, int(msgTypeICEPunch), conMsg); err != nil {
		logger.Errorf("ICE session %s: send ICE_PUNCH to consumer failed: %v", session.ID, err)
	}

	if !c.waitPhaseTimeout(session, StatePunching, punchTimeout) {
		return
	}
	c.mu.Lock()
	c.punchAttempts++
	c.punchFailures++
	c.mu.Unlock()
	c.handlePunchFailed(session, "punch timeout: no result received")
}

func computePortPredictPlan(cfg Config, policy *LinkPolicy) portPredictPlan {
	baseAttempts := cfg.PunchAttempts
	if baseAttempts < 1 {
		baseAttempts = 1
	}
	interval := cfg.PunchInterval
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	baseTimeout := cfg.PunchTimeout
	if baseTimeout <= 0 {
		baseTimeout = 5 * time.Second
	}

	requireDirect := policy != nil && policy.RequireDirect
	targetWindow := portPredictPreferredWindow
	maxAttempts := portPredictPreferredMaxAttempts
	extraCount := portPredictPreferredExtraCount
	timeoutCap := portPredictPreferredTimeoutCap
	burstPerAttempt := 1
	if requireDirect {
		targetWindow = portPredictRequireWindow
		maxAttempts = portPredictRequireMaxAttempts
		extraCount = portPredictRequireExtraCount
		timeoutCap = portPredictRequireTimeoutCap
		burstPerAttempt = portPredictRequireBurst
	}

	attemptsByWindow := int((targetWindow + interval - 1) / interval)
	attempts := maxInt(baseAttempts*2, attemptsByWindow)
	attempts = minInt(attempts, maxAttempts)

	plannedSendWindow := time.Duration(attempts)*interval + interval*2
	timeout := maxDuration(baseTimeout*2, plannedSendWindow)
	timeout = minDuration(timeout, timeoutCap)
	if requireDirect {
		timeout = maxDuration(timeout, targetWindow)
	}

	return portPredictPlan{
		attempts:        uint32(attempts),
		extraCount:      extraCount,
		timeout:         timeout,
		burstPerAttempt: burstPerAttempt,
	}
}

func attachBurstHint(extra []string, burstPerAttempt int) []string {
	if burstPerAttempt <= 1 {
		return extra
	}
	hint := fmt.Sprintf("ice:burst=%d", burstPerAttempt)
	out := make([]string, 0, len(extra)+1)
	out = append(out, hint)
	out = append(out, extra...)
	return out
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a >= b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a >= b {
		return a
	}
	return b
}

func (c *Controller) startQuicConnect(session *Session) {
	logger.Infof("ICE session %s: initiating QUIC connection", session.ID)

	session.mu.Lock()
	pubEP := session.PublisherEndpoint
	conEP := session.ConsumerEndpoint
	session.mu.Unlock()

	connectMs := uint32(c.config.ConnectTimeout.Milliseconds())

	pubMsg := c.protocol.BuildICEQuicStart(session.ID, message.ICEQuicRoleSERVER, conEP.UDPAddr.String(), ALPN, connectMs)
	conMsg := c.protocol.BuildICEQuicStart(session.ID, message.ICEQuicRoleCLIENT, pubEP.UDPAddr.String(), ALPN, connectMs)

	if err := c.bridge.SendToClient(session.PublisherSessionID, int(msgTypeICEQuic), pubMsg); err != nil {
		logger.Errorf("ICE session %s: send ICE_QUIC_START to publisher failed: %v", session.ID, err)
	}
	if err := c.bridge.SendToClient(session.ConsumerSessionID, int(msgTypeICEQuic), conMsg); err != nil {
		logger.Errorf("ICE session %s: send ICE_QUIC_START to consumer failed: %v", session.ID, err)
	}

	if !c.waitPhaseTimeout(session, StateConnecting, c.config.ConnectTimeout) {
		return
	}
	c.handlePunchFailed(session, "connect timeout: QUIC handshake not completed")
}

func (c *Controller) handlePunchFailed(session *Session, reason string) {
	policy := c.bridge.GetTunnelLinkPolicy(session.TunnelID)
	if policy != nil && policy.AllowRelayFallback {
		if err := session.Transition(StateFallback); err != nil {
			logger.Errorf("ICE session %s transition to fallback failed: %v", session.ID, err)
			return
		}
		session.mu.Lock()
		session.Error = reason
		session.mu.Unlock()
		c.reportState(session, &StateDetail{Error: reason})
		c.cleanupSession(session)
		logger.Infof("ICE session %s: falling back to relay (%s)", session.ID, reason)
	} else {
		if err := session.Transition(StateFailed); err != nil {
			logger.Errorf("ICE session %s transition to failed failed: %v", session.ID, err)
			return
		}
		session.mu.Lock()
		session.Error = reason
		session.mu.Unlock()
		c.reportState(session, &StateDetail{Error: reason})
		c.cleanupSession(session)
		logger.Infof("ICE session %s: failed (%s)", session.ID, reason)
	}
}

func (c *Controller) reportState(session *Session, detail *StateDetail) {
	state := session.GetState()
	if c.bridge != nil {
		c.bridge.ReportICEStateChange(
			session.ID,
			session.TunnelID,
			session.PublisherSessionID,
			session.ConsumerSessionID,
			state,
			detail,
		)
	}

	errMsg := ""
	if detail != nil {
		errMsg = detail.Error
	}
	payload := c.protocol.BuildICEStateChange(session.ID, session.TunnelID, state, session.Strategy, errMsg)
	if err := c.bridge.SendToClient(session.PublisherSessionID, int(msgTypeICEState), payload); err != nil {
		logger.Warnf("ICE session %s: send state change to publisher failed: %v", session.ID, err)
	}
	if err := c.bridge.SendToClient(session.ConsumerSessionID, int(msgTypeICEState), payload); err != nil {
		logger.Warnf("ICE session %s: send state change to consumer failed: %v", session.ID, err)
	}
}
