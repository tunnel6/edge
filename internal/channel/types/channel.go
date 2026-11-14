package types

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

// State indicates channel lifecycle state.
type State uint8

const (
	StateCreating State = iota
	StateActive
	StatePaused
	StateClosing
	StateClosed
)

var stateNames = map[State]string{
	StateCreating: "creating",
	StateActive:   "active",
	StatePaused:   "paused",
	StateClosing:  "closing",
	StateClosed:   "closed",
}

func (s State) String() string {
	if name, ok := stateNames[s]; ok {
		return name
	}
	return "unknown"
}

// Channel is the unified runtime entity for a client tunnel channel.
type Channel struct {
	ID        string
	Type      fbMsg.ChannelType
	SessionID string
	UserID    string
	DeviceID  string
	Hostname  string
	ActorRole fbMsg.TunnelActorRole
	// ActorSessionID is the business-level session identifier from host/runtime,
	// different from the transport mTLS session ID.
	ActorSessionID string
	ActorDeviceID  string
	ActorHostname  string
	LocalAddr      string

	Domain      string
	Subdomain   string
	AliasDomain string // User-specified alias domain for this channel.
	Config      string
	// EagerConnectRemote only applies to TCP channels and is used for server-first protocols.
	EagerConnectRemote bool

	// Channel identity fields (new domain model)
	ChannelKey     string // 逻辑 channel 标识
	Protocol       string // 协议类型（"tcp", "udp", "http", "https", "wireguard"）
	LinkType       string // 数据面链路类型（"relay", "p2p", "wireguard"）
	PreferredLinks []string
	// AllowRelayFallback indicates whether dataplane may fallback to relay.
	AllowRelayFallback bool
	// RequireDirect indicates strict direct-only mode.
	RequireDirect  bool
	RemoteEndpoint string // 数据面远端地址（host:port）
	// ConnRemoteAddr 是承载该 channel 的 Session.Conn 的对端地址（客户端到 edge 的真实 host:port）。
	// 仅在 runtime 存在，不落库，由 StatusManager 透出给 CLI/订阅者。
	ConnRemoteAddr string

	Port  uint16
	State State

	CreatedAt time.Time
	ClosedAt  time.Time

	stats ChannelStats

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// ChannelStats contains accumulated metrics for one channel.
type ChannelStats struct {
	BytesIn     uint64
	BytesOut    uint64
	Requests    uint64
	Connections uint64
	Errors      uint64
	ActiveConns int32
}

// NewChannel creates a channel runtime model.
func NewChannel(id string, typ fbMsg.ChannelType, sessionID, userID, deviceID, hostname, localAddr string) *Channel {
	ctx, cancel := context.WithCancel(context.Background())
	return &Channel{
		ID:        id,
		Type:      typ,
		SessionID: sessionID,
		UserID:    userID,
		DeviceID:  deviceID,
		Hostname:  strings.TrimSpace(hostname),
		ActorRole: fbMsg.TunnelActorRolePUBLISHER,
		// Default actor identity follows transport identity until client passes explicit values.
		ActorSessionID: sessionID,
		ActorDeviceID:  deviceID,
		ActorHostname:  strings.TrimSpace(hostname),
		LocalAddr:      localAddr,
		State:          StateCreating,
		CreatedAt:      time.Now(),
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (c *Channel) SetState(state State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.State = state
	if state == StateClosed {
		c.ClosedAt = time.Now()
	}
}

func (c *Channel) GetState() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.State
}

func (c *Channel) IsActive() bool {
	return c.GetState() == StateActive
}

func (c *Channel) Context() context.Context {
	return c.ctx
}

func (c *Channel) Close() {
	c.SetState(StateClosed)
	if c.cancel != nil {
		c.cancel()
	}
}

func (t *Channel) GetStats() ChannelStats {
	return ChannelStats{
		BytesIn:     atomic.LoadUint64(&t.stats.BytesIn),
		BytesOut:    atomic.LoadUint64(&t.stats.BytesOut),
		Requests:    atomic.LoadUint64(&t.stats.Requests),
		Connections: atomic.LoadUint64(&t.stats.Connections),
		Errors:      atomic.LoadUint64(&t.stats.Errors),
		ActiveConns: atomic.LoadInt32(&t.stats.ActiveConns),
	}
}

func (t *Channel) AddBytesIn(n uint64) {
	atomic.AddUint64(&t.stats.BytesIn, n)
}

func (t *Channel) AddBytesOut(n uint64) {
	atomic.AddUint64(&t.stats.BytesOut, n)
}

func (t *Channel) IncrRequests() {
	atomic.AddUint64(&t.stats.Requests, 1)
}

func (t *Channel) IncrConnections() {
	atomic.AddUint64(&t.stats.Connections, 1)
	atomic.AddInt32(&t.stats.ActiveConns, 1)
}

func (t *Channel) DecrConnections() {
	atomic.AddInt32(&t.stats.ActiveConns, -1)
}

func (t *Channel) IncrErrors() {
	atomic.AddUint64(&t.stats.Errors, 1)
}

// CloneBinding returns a shallow copy capturing the current binding fields.
func (c *Channel) CloneBinding() *Channel {
	if c == nil {
		return nil
	}
	return &Channel{
		ID:                 c.ID,
		Type:               c.Type,
		SessionID:          c.SessionID,
		UserID:             c.UserID,
		DeviceID:           c.DeviceID,
		Hostname:           c.Hostname,
		ActorRole:          c.ActorRole,
		ActorSessionID:     c.ActorSessionID,
		ActorDeviceID:      c.ActorDeviceID,
		ActorHostname:      c.ActorHostname,
		LocalAddr:          c.LocalAddr,
		Domain:             c.Domain,
		Subdomain:          c.Subdomain,
		AliasDomain:        c.AliasDomain,
		Port:               c.Port,
		EagerConnectRemote: c.EagerConnectRemote,
		ChannelKey:         c.ChannelKey,
		Protocol:           c.Protocol,
		LinkType:           c.LinkType,
		PreferredLinks:     cloneStringSlice(c.PreferredLinks),
		AllowRelayFallback: c.AllowRelayFallback,
		RequireDirect:      c.RequireDirect,
		RemoteEndpoint:     c.RemoteEndpoint,
		ConnRemoteAddr:     c.ConnRemoteAddr,
	}
}

func cloneStringSlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, len(input))
	copy(out, input)
	return out
}

// RouteSubdomain returns the effective subdomain used for HTTP routing.
func (c *Channel) RouteSubdomain() string {
	if c == nil {
		return ""
	}
	sub := strings.TrimSpace(c.Subdomain)
	if sub == "" {
		// Fall back to extracting subdomain from full domain.
		domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
		if idx := strings.Index(domain, "."); idx > 0 {
			sub = domain[:idx]
		} else {
			sub = domain
		}
	}
	return strings.ToLower(strings.TrimSpace(sub))
}
