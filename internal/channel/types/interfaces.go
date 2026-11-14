package types

import (
	"crypto/tls"
	"net"
	"net/http"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

// ChannelRuntime handles protocol-specific bind/unbind/data behavior for channels.
type ChannelRuntime interface {
	Upsert(target *Channel, previous *Channel) error
	Remove(target *Channel) error
	HandleData(target *Channel, connectionID string, seq uint32, data []byte, flags uint8) error
}

// Service represents a startable/stoppable service.
type Service interface {
	Start() error
	Stop() error
}

// ChannelCreateAckBuilder builds protocol-specific acknowledgment metadata
// when a channel is created.
type ChannelCreateAckBuilder interface {
	BuildChannelCreateAck(
		channelType fbMsg.ChannelType,
		configRaw []byte,
		createReq *CreateRequest,
		result *CreateResult,
	) (aliasDomain, customDomain, assignedDomain, remoteEndpoint, ackErrorMessage string, err error)
}

// TunnelSender sends data through tunnel sessions back to clients.
type TunnelSender interface {
	SendHTTPRequest(sessionID, channelID, requestID, method, path, query string,
		headers map[string]string, body []byte, remoteAddr string) error
	SendTCPData(sessionID, channelID, connectionID string, data []byte, flags uint8) error
	SendUDPData(sessionID, channelID string, data []byte, srcAddr string) error
}

// DomainProvider provides edge-level domain configuration.
type DomainProvider interface {
	GetAssignedDomain() string
	GetCustomDomain() string
}

// ClientPusher pushes data to a connected client by ID.
type ClientPusher interface {
	PushToClient(clientID string, data []byte) error
	// AsyncPushToClients publishes data via the async ring-buffer broadcaster.
	// Only sessions whose DeviceID is in targetClients receive the message.
	AsyncPushToClients(targetClients []string, data []byte)
}

// OnlineDevice 描述某用户当前在线（已连到本 edge）的一台设备。
type OnlineDevice struct {
	ClientID   string
	DeviceID   string
	Hostname   string
	LastActive int64 // epoch ms
}

// OnlineDeviceLister 枚举某用户当前在线的设备，用于「扫描可加入网络的在线设备」。
type OnlineDeviceLister interface {
	ListOnlineDevicesByUser(userID string) []OnlineDevice
}

// ClientConnectNotifier is implemented by session managers that support
// a callback when a client connects (TLS session established).
type ClientConnectNotifier interface {
	SetOnClientConnect(fn func(userID, deviceID string))
}

// Protocol defines the transport-level message sending contract.
type Protocol interface {
	SendError(conn net.Conn, errCode fbMsg.ErrorCode, errMsg, sessionID string) error
	SendTunnelStartResponse(conn net.Conn, resp *fbMsg.TunnelStartResponseT, sessionID string) error
	SendTunnelStopResponse(conn net.Conn, resp *fbMsg.TunnelStopResponseT, sessionID string) error
	SendTunnelJoinResponse(conn net.Conn, resp *fbMsg.TunnelJoinResponseT, sessionID string) error
	SendTunnelLeaveResponse(conn net.Conn, resp *fbMsg.TunnelLeaveResponseT, sessionID string) error
	SendDataAck(conn net.Conn, channelID, connectionID string, seq uint32, sessionID string) error
	WriteMessage(conn net.Conn, data []byte) error
	SendPushRequest(conn net.Conn, requestID, channelID, method, path, query string, headers []HTTPHeader, body []byte, remoteAddr, sessionID string) error
	SendDataPacket(conn net.Conn, channelID, connectionID string, seq uint32, data []byte, flags uint8, sessionID string) error
}

// SessionWriter provides access to a session's protocol and connection.
type SessionWriter interface {
	GetProtocol() Protocol
	GetConn() net.Conn
}

// SessionGetter looks up a session by ID.
type SessionGetter interface {
	Get(sessionID string) (SessionWriter, bool)
}

// HTTPProxyConfigurator allows external components (e.g. ACME cert service)
// to configure the HTTP proxy's TLS and handler settings.
type HTTPProxyConfigurator interface {
	SetACMEHTTP01Handler(handler http.Handler)
	SetACMETLSALPN01CertResolver(resolver func(hello *tls.ClientHelloInfo) (*tls.Certificate, bool))
	SetTLSCertificateResolver(resolver func(serverName string) (*tls.Certificate, error))
	SetHTTPSDomainRequestHandler(handler func(aliasDomain, assignedDomain string))
}
