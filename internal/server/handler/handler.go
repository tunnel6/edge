package handler

import (
	"net"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	channel "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/pkg/config"
)

// Context Provides dependencies and context needed by handler
type Context struct {
	// Session identity (immutable snapshot from server.Session)
	channel.SessionIdentity

	Conn net.Conn

	// Dependency injection
	ChannelRegistry ChannelRegistry
	SessionManager  SessionManager
	Lifecycle       Lifecycle
	StatusManager   StatusManager
	OwnerVerifier   OwnerVerifier
	Config          *config.Config

	// Protocol for sending responses
	Protocol Protocol

	ServiceManager ServiceManager

	// DNS-01 challenge provider (used by edge/tunnel status reporting)
	DNS01ChallengeProvider DNS01ChallengeProvider

	// CnameChecker for CNAME status check in status push
	CnameChecker CnameChecker

	// DomainStatusProvider for cached DNS/cert status
	DomainStatusProvider DomainStatusProvider
}

// SessionManager Session management interface
type SessionManager interface {
	// BroadcastError Broadcast error to all sessions and close
	BroadcastError(errCode fbMsg.ErrorCode, errMsg string)
}

type ServiceManager interface {
	EnsureForChannelType(typ fbMsg.ChannelType) error
}

// ChannelRegistry Channel registry interface
type ChannelRegistry interface {
	// Create Create Channel
	Create(req *channel.CreateRequest) (*channel.CreateResult, error)

	// Close Close Channel
	Close(channelID string) error

	// Get Get Channel
	Get(channelID string) *channel.Channel
}

// Lifecycle controls the local Edge state.
type Lifecycle interface {
	// MarkOnline Mark as online (local state sync, notification async)
	MarkOnline()

	// MarkOffline Mark as offline (local state sync, notification async)
	MarkOffline()
}

// Protocol Protocol interface (for sending responses)
type Protocol interface {
	// SendError Send error response
	SendError(conn net.Conn, errCode fbMsg.ErrorCode, errMsg, sessionID string) error

	// SendEdgeOnlineResponse Send online response
	SendEdgeOnlineResponse(conn net.Conn, success bool, errCode uint32, errMsg, sessionID string) error

	// SendEdgeOfflineResponse Send offline response
	SendEdgeOfflineResponse(conn net.Conn, success bool, errCode uint32, errMsg, sessionID string) error

	// WriteMessage Write raw message
	WriteMessage(conn net.Conn, data []byte) error

	// GetBuilder Get FlatBuffers builder
	GetBuilder() Builder
}

// Builder FlatBuffers builder interface
type Builder interface {
	Reset()
	CreateString(s string) flatbuffers.UOffsetT
	CreateByteVector(b []byte) flatbuffers.UOffsetT
	Finish(rootTable flatbuffers.UOffsetT)
	FinishedBytes() []byte
}

// DNS01ChallengeProvider provides active DNS-01 challenge info for status reporting.
type DNS01ChallengeProvider interface {
	GetActiveDNS01Challenges() []DNS01ChallengeStatusInfo
}

// CnameChecker performs a single CNAME verification check.
type CnameChecker interface {
	CheckCNAMEOnce() uint8
}

// DomainStatusProvider provides cached DNS/cert status for domains.
type DomainStatusProvider interface {
	GetAssignedDomainStatus() DomainStatusInfo
	GetCustomDomainStatus() DomainStatusInfo
	GetChannelDomainStatus(channelDomain string) DomainStatusInfo
	GetChannelAliasDomainStatus(aliasDomain, assignedDomain string) DomainStatusInfo
}

// OwnerVerifier owner verification interface
type OwnerVerifier interface {
	// IsEdgeOwner Check if user is Edge owner
	IsEdgeOwner(userID string) bool
}

// StatusManager Status management interface
type StatusManager interface {
	// GetStatus Get current status
	GetStatus() *EdgeServiceStatus
}

// EdgeServiceStatus Edge service status
type EdgeServiceStatus struct {
	EdgeID                     string
	Online                     bool
	Uptime                     int64
	LastUpdated                int64
	WireGuardRelayRuntimeReady bool
	Channels                   []ChannelStatus
	Stats                      ServiceStats
}

// ChannelStatus Channel status
type ChannelStatus struct {
	ID             string
	Type           uint8
	SessionID      string
	UserID         string
	DeviceID       string
	ActorRole      uint8
	ActorSessionID string
	ActorDeviceID  string
	Domain         string
	Subdomain      string
	AliasDomain    string
	Port           uint16
	LocalAddr      string
	State          string
	BytesIn        uint64
	BytesOut       uint64
	Connections    uint64
	ActiveConns    int32
	CreatedAt      int64
	ChannelKey     string
	Protocol       string
	LinkType       string
	RemoteEndpoint string
}

// ServiceStats Service statistics
type ServiceStats struct {
	TotalSessions    uint32
	ActiveSessions   uint32
	TotalChannels    uint32
	ActiveChannels   uint32
	TotalBytesIn     uint64
	TotalBytesOut    uint64
	TotalConnections uint64
	TotalRequests    uint64
	TotalErrors      uint64
}
