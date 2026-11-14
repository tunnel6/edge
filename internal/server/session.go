package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	channel "icool.io/yat/edge/internal/channel/types"
)

type Session struct {
	controlSourceMu sync.RWMutex    // association lock; always precedes source gate/session locks
	controlSource   *SessionManager // set once by Add, never transferred between managers
	ID              string          // Session ID
	UserID          string
	Role            string // CA-signed per-Edge role, fixed at authentication
	DeviceID        string
	Hostname        string
	Conn            *tls.Conn
	Protocol        *Protocol // Handle
	Channels        map[string]*Channel
	Capabilities    map[string]struct{}
	ScopeClaims     []string // Certificate scope claims (nil = full access)
	LastActive      time.Time
	CreatedAt       time.Time // Create
	mu              sync.RWMutex
	deviceSessionMu sync.Mutex    // pins device-indexed session against concurrent replacement
	closeCh         chan struct{} // Close
	closed          bool
}

// Create
func NewSession(id, userID, deviceID, hostname string, conn *tls.Conn) *Session {
	return &Session{
		ID:           id,
		UserID:       userID,
		DeviceID:     deviceID,
		Hostname:     hostname,
		Conn:         conn,
		Protocol:     NewProtocol(),
		Channels:     make(map[string]*Channel),
		Capabilities: make(map[string]struct{}),
		LastActive:   time.Now(),
		CreatedAt:    time.Now(),
		closeCh:      make(chan struct{}),
	}
}

func (s *Session) SetCapabilities(caps []string) {
	_ = s.changeControlFacts(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.Capabilities = make(map[string]struct{}, len(caps))
		for _, c := range caps {
			if c != "" {
				s.Capabilities[c] = struct{}{}
			}
		}
		return nil
	})
}

func (s *Session) HasCapability(cap string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.Capabilities[cap]
	return ok
}

func (s *Session) CapabilitiesSlice() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.Capabilities))
	for c := range s.Capabilities {
		out = append(out, c)
	}
	return out
}

// Interface
func (s *Session) GetProtocol() channel.Protocol {
	return &sessionProtocolAdapter{p: s.Protocol}
}

// Interface
func (s *Session) GetConn() net.Conn {
	return s.Conn
}

// Add
func (s *Session) AddChannel(ch *Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Channels[ch.ID] = ch
	s.LastActive = time.Now()
}

// Get
func (s *Session) GetChannel(channelID string) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Channels[channelID]
}

// Remove
func (s *Session) RemoveChannel(channelID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Channels, channelID)
}

// Update
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActive = time.Now()
}

// Close
func (s *Session) Close() error {
	closed := false
	if err := s.changeControlFacts(func() error {
		closed = s.closeState()
		return nil
	}); err != nil {
		return err
	}
	if closed {
		return s.closeTransport()
	}
	return nil
}

type Channel struct {
	ID          string            // Channel ID
	Type        fbMsg.ChannelType // HTTP/TCP/etc
	LocalAddr   string
	RemoteAddr  string
	Domain      string
	Active      bool
	BytesIn     uint64
	BytesOut    uint64 // Send
	Connections uint32
	CreatedAt   time.Time
	mu          sync.RWMutex
}

// Close
func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Active = false
}

type sessionProtocolAdapter struct {
	p *Protocol
}

func (a *sessionProtocolAdapter) SendPushRequest(conn net.Conn, requestID, channelID, method, path, query string,
	headers []channel.HTTPHeader, body []byte, remoteAddr, sessionID string) error {

	return a.p.SendPushRequest(conn, requestID, channelID, method, path, query, headers, body, remoteAddr, sessionID)
}

func (a *sessionProtocolAdapter) SendDataPacket(conn net.Conn, channelID, connectionID string, seq uint32,
	data []byte, flags uint8, sessionID string) error {
	return a.p.SendDataPacket(conn, channelID, connectionID, seq, data, flags, sessionID)
}

func (a *sessionProtocolAdapter) SendError(conn net.Conn, errCode fbMsg.ErrorCode, errMsg, sessionID string) error {
	return a.p.SendError(conn, errCode, errMsg, sessionID)
}

func (a *sessionProtocolAdapter) SendTunnelStartResponse(conn net.Conn, resp *fbMsg.TunnelStartResponseT, sessionID string) error {
	return a.p.SendTunnelStartResponse(conn, resp, sessionID)
}

func (a *sessionProtocolAdapter) SendTunnelStopResponse(conn net.Conn, resp *fbMsg.TunnelStopResponseT, sessionID string) error {
	return a.p.SendTunnelStopResponse(conn, resp, sessionID)
}

func (a *sessionProtocolAdapter) SendTunnelJoinResponse(conn net.Conn, resp *fbMsg.TunnelJoinResponseT, sessionID string) error {
	return a.p.SendTunnelJoinResponse(conn, resp, sessionID)
}

func (a *sessionProtocolAdapter) SendTunnelLeaveResponse(conn net.Conn, resp *fbMsg.TunnelLeaveResponseT, sessionID string) error {
	return a.p.SendTunnelLeaveResponse(conn, resp, sessionID)
}

func (a *sessionProtocolAdapter) SendDataAck(conn net.Conn, channelID, connectionID string, seq uint32, sessionID string) error {
	return a.p.SendDataAck(conn, channelID, connectionID, seq, sessionID)
}

func (a *sessionProtocolAdapter) WriteMessage(conn net.Conn, data []byte) error {
	return a.p.WriteMessage(conn, data)
}

type SessionManager struct {
	pathMutations  clientSessionMutations
	sessions       sync.Map // map[sessionID]*Session
	userSessions   sync.Map
	clientSessions sync.Map
	maxSessions    int

	// onClientConnect is called after a session is added.  Used to restore
	// WireGuard member online status when a device reconnects.
	onClientConnect func(userID, deviceID string)

	// broadcaster is the async ring-buffer push hub.  Set by Server after
	// construction; may be nil during tests.
	broadcaster *PushBroadcaster
}

// SetOnClientConnect installs a callback invoked whenever a client connects
// (TLS session established).  The callback receives the authenticated
// userID and deviceID.
func (sm *SessionManager) SetOnClientConnect(fn func(userID, deviceID string)) {
	sm.onClientConnect = fn
}

// Create
func NewSessionManager(maxSessions int) *SessionManager {
	return &SessionManager{
		maxSessions: maxSessions,
	}
}

// Add
func (sm *SessionManager) Add(session *Session) error {
	session.controlSourceMu.Lock()
	if session.controlSource != nil && session.controlSource != sm {
		session.controlSourceMu.Unlock()
		return fmt.Errorf("session already belongs to another manager")
	}
	previousSource := session.controlSource
	session.controlSource = sm
	var retired *Session
	err := sm.changeClientSession(func() error {
		var err error
		retired, err = sm.addSessionState(session)
		return err
	})
	if err != nil && previousSource == nil {
		// Failed admission did not publish this session. Do not retain an
		// association that would prevent retrying with another manager.
		session.controlSource = nil
	}
	session.controlSourceMu.Unlock()
	if err != nil {
		return err
	}
	if retired != nil {
		_ = retired.closeTransport()
	}
	// External bridge callbacks are outside all source/session locks.
	if sm.onClientConnect != nil && session.UserID != "" && session.DeviceID != "" {
		go sm.onClientConnect(session.UserID, session.DeviceID)
	}
	return nil
}

func (sm *SessionManager) addSessionState(session *Session) (*Session, error) {
	// A cleanup must not close a newly indexed session while registration is
	// still waiting to replace the old device connection.
	session.deviceSessionMu.Lock()
	defer session.deviceSessionMu.Unlock()

	// Check global limit
	count := 0
	sm.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	if count >= sm.maxSessions {
		return nil, ErrMaxSessionsExceeded
	}

	sm.sessions.Store(session.ID, session)

	// Add
	sessions, _ := sm.userSessions.LoadOrStore(session.UserID, &sync.Map{})
	sessMap := sessions.(*sync.Map)
	sessMap.Store(session.ID, session)

	// Add
	// Use bare deviceID as the clientSessions key.  The WireGuard layer
	// identifies peers by bare deviceID (member.ClientID), so PushToClient
	// and HasClientSession lookups use the same format.
	var retired *Session
	if session.DeviceID != "" {
		retired = sm.publishClientSession(session)
	}

	return retired, nil
}

// Get
func (sm *SessionManager) Get(sessionID string) (channel.SessionWriter, bool) {
	val, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// Get
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	val, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

// Get
func (sm *SessionManager) GetByUser(userID string) []*Session {
	val, ok := sm.userSessions.Load(userID)
	if !ok {
		return nil
	}

	sessMap := val.(*sync.Map)
	var sessions []*Session
	sessMap.Range(func(_, val interface{}) bool {
		sessions = append(sessions, val.(*Session))
		return true
	})
	return sessions
}

// ListOnlineDevicesByUser 实现 channel.OnlineDeviceLister：
// 返回该用户当前在线（已连到本 edge）的设备列表，按 deviceId 去重。
func (sm *SessionManager) ListOnlineDevicesByUser(userID string) []channel.OnlineDevice {
	sessions := sm.GetByUser(userID)
	if len(sessions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(sessions))
	devices := make([]channel.OnlineDevice, 0, len(sessions))
	for _, sess := range sessions {
		if sess == nil {
			continue
		}
		deviceID := strings.TrimSpace(sess.DeviceID)
		if deviceID == "" {
			continue
		}
		if _, dup := seen[deviceID]; dup {
			continue
		}
		seen[deviceID] = struct{}{}
		devices = append(devices, channel.OnlineDevice{
			ClientID:   deviceID,
			DeviceID:   deviceID,
			Hostname:   sess.Hostname,
			LastActive: sess.LastActive.UnixMilli(),
		})
	}
	return devices
}

// Remove
func (sm *SessionManager) Remove(sessionID string) {
	var closed *Session
	_ = sm.changeClientSession(func() error {
		closed = sm.removeSessionState(sessionID)
		return nil
	})
	if closed != nil {
		_ = closed.closeTransport()
	}
}

func (sm *SessionManager) removeSessionState(sessionID string) *Session {
	val, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil
	}

	session := val.(*Session)
	session.deviceSessionMu.Lock()
	defer session.deviceSessionMu.Unlock()
	if !sm.sessions.CompareAndDelete(sessionID, session) {
		return nil
	}

	// Remove
	if val, ok := sm.userSessions.Load(session.UserID); ok {
		sessMap := val.(*sync.Map)
		sessMap.Delete(sessionID)
	}

	// Remove from clientID index only if it still points to THIS session.
	// A newer session with the same clientID may have already overwritten
	// the entry — blindly deleting would orphan the new session.
	if session.DeviceID != "" {
		sm.clientSessions.CompareAndDelete(session.DeviceID, session)
	}

	if session.closeState() {
		return session
	}
	return nil
}

// Get
func (sm *SessionManager) Count() uint32 {
	count := uint32(0)
	sm.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Get
func (sm *SessionManager) GetAll() []*Session {
	var sessions []*Session
	sm.sessions.Range(func(_, val interface{}) bool {
		sessions = append(sessions, val.(*Session))
		return true
	})
	return sessions
}

// Clean
func (sm *SessionManager) CleanExpired(timeout time.Duration) int {
	var expiredIDs []string
	now := time.Now()

	sm.sessions.Range(func(key, val interface{}) bool {
		session := val.(*Session)
		if now.Sub(session.LastActive) > timeout {
			expiredIDs = append(expiredIDs, key.(string))
		}
		return true
	})

	for _, id := range expiredIDs {
		sm.Remove(id)
	}

	return len(expiredIDs)
}

// Errors
var (
	ErrMaxSessionsExceeded = fmt.Errorf("max sessions exceeded")
)

// Get

func (sm *SessionManager) GetByClientID(clientID string) (*Session, bool) {
	val, ok := sm.clientSessions.Load(clientID)
	if !ok {
		return nil, false
	}
	return val.(*Session), true
}

func (sm *SessionManager) HasClientSession(clientID string) bool {
	_, ok := sm.GetByClientID(clientID)
	return ok
}

// CurrentClientSession returns an immutable auth snapshot, rather than the live
// Session pointer exposed by legacy getters. Recheck the device index after
// copying: reconnect may have replaced it while the session lock was acquired.
func (sm *SessionManager) CurrentClientSession(deviceID string) (channel.SessionIdentity, bool) {
	session, ok := sm.GetByClientID(deviceID)
	if !ok {
		return channel.SessionIdentity{}, false
	}
	session.mu.RLock()
	defer session.mu.RUnlock()
	if session.closed || session.DeviceID != deviceID {
		return channel.SessionIdentity{}, false
	}
	current, ok := sm.clientSessions.Load(deviceID)
	if !ok || current != session {
		return channel.SessionIdentity{}, false
	}
	identity := channel.SessionIdentity{
		SessionID: session.ID, UserID: session.UserID, DeviceID: session.DeviceID,
		Hostname: session.Hostname, ScopeClaims: append([]string(nil), session.ScopeClaims...),
		Capabilities: make([]string, 0, len(session.Capabilities)),
	}
	for capability := range session.Capabilities {
		identity.Capabilities = append(identity.Capabilities, capability)
	}
	return identity, true
}

func (sm *SessionManager) PushToClient(clientID string, data []byte) error {
	session, ok := sm.GetByClientID(clientID)
	if !ok {
		// Diagnostic: list all registered clientIDs to help debug mismatches.
		var registered []string
		sm.clientSessions.Range(func(key, _ interface{}) bool {
			if id, ok := key.(string); ok {
				registered = append(registered, id)
			}
			return true
		})
		return fmt.Errorf("%w: %s (registered: %v)", channel.ErrSessionNotFoundForClient, clientID, registered)
	}

	return session.Protocol.WriteMessage(session.Conn, data)
}

// AsyncPushToClients publishes pre-serialized bytes via the async ring-buffer
// broadcaster.  Only sessions whose DeviceID is in targetClients receive the
// message.  This is non-blocking — slow peers cannot stall the caller.
func (sm *SessionManager) AsyncPushToClients(targetClients []string, data []byte) {
	if sm.broadcaster == nil || len(data) == 0 {
		return
	}
	targetSet := make(map[string]struct{}, len(targetClients))
	for _, c := range targetClients {
		if c != "" {
			targetSet[c] = struct{}{}
		}
	}
	sm.broadcaster.Publish(broadcastEntry{
		kind:             kindRawBytes,
		rawData:          data,
		rawTargetClients: targetSet,
	})
}

// Broadcast
func (sm *SessionManager) BroadcastError(errCode fbMsg.ErrorCode, errMsg string) {
	sm.sessions.Range(func(key, val interface{}) bool {
		session := val.(*Session)
		// Send
		go func(s *Session) {
			s.Protocol.SendError(s.Conn, errCode, errMsg, s.ID)
			// Handle
			time.Sleep(200 * time.Millisecond)
			sm.Remove(s.ID)
		}(session)
		return true
	})
}
