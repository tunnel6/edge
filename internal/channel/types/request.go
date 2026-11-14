package types

import (
	"strings"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

// HTTPHeader represents an HTTP header key-value pair.
type HTTPHeader struct {
	Key   string
	Value string
}

// CreateRequest is the input for creating a channel.
type CreateRequest struct {
	ID             string
	Type           fbMsg.ChannelType
	SessionID      string
	UserID         string
	DeviceID       string
	DeviceHostname string
	ActorRole      fbMsg.TunnelActorRole
	ActorSessionID string
	ActorDeviceID  string
	ActorHostname  string
	LocalAddr      string
	Subdomain      string
	AliasDomain    string // User-specified alias domain for this channel.
	RemotePort     uint16 // Requested remote port for TCP/UDP (0 means auto-assign).
	// EagerConnectRemote asks edge TCP proxy to notify client immediately after accept,
	// so server-first protocols (e.g. VNC/RFB) can start handshake without client payload.
	EagerConnectRemote bool

	ChannelKey string // 逻辑 channel 标识（从 ID 解析：tunnelId:channelKey 中的 channelKey 部分）
	Protocol   string // 协议类型（"tcp", "udp", "http", "https", "wireguard"）
	LinkType   string // 数据面链路类型（"relay", "p2p", "wireguard"）
	// PreferredLinks / AllowRelayFallback / RequireDirect carry normalized data-plane
	// strategy hints for future dataplane orchestration.
	PreferredLinks     []string
	AllowRelayFallback bool
	RequireDirect      bool
	// ConnRemoteAddr 是 session.Conn 的对端地址（host:port），由 handler 从底层连接注入。
	ConnRemoteAddr string
}

// Normalize trims and lowercases user-supplied fields in place.
func (r *CreateRequest) Normalize() {
	r.Subdomain = strings.ToLower(strings.TrimSpace(r.Subdomain))
	r.AliasDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.AliasDomain)), ".")
}

// CreateResult is the output of a channel creation.
type CreateResult struct {
	Success      bool
	TargetID     string
	Domain       string // HTTP
	Port         uint16 // TCP/UDP (internal)
	Subdomain    string
	AliasDomain  string
	ErrorCode    uint32
	ErrorMessage string

	ChannelKey     string // 逻辑 channel 标识
	RemoteEndpoint string // Edge 分配的数据面远端地址（host:port，TCP/UDP）
}

// ChannelRecord is the persistent storage record for a channel.
type ChannelRecord struct {
	ID           int64 // Database autoincrement ID for subdomain generation.
	ChannelID    string
	SessionID    string
	Type         fbMsg.ChannelType
	LocalAddr    string
	Port         uint16 // Last allocated remote port for TCP/UDP.
	Subdomain    string
	AliasDomain  string // User-specified alias domain for this channel.
	CreatedAt    time.Time
	LastActiveAt time.Time
}
