package channel

import (
	"fmt"

	chtype "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

// Re-export from types/.
type TunnelSender = chtype.TunnelSender
type SessionWriter = chtype.SessionWriter
type SessionGetter = chtype.SessionGetter

// TunnelSenderImpl implements TunnelSender by looking up sessions.
type TunnelSenderImpl struct {
	sessions SessionGetter
}

func NewTunnelSender(sessions SessionGetter) TunnelSender {
	return &TunnelSenderImpl{
		sessions: sessions,
	}
}

func (t *TunnelSenderImpl) SendHTTPRequest(sessionID, channelID, requestID, method, path, query string,
	headers map[string]string, body []byte, remoteAddr string) error {
	session, ok := t.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	var httpHeaders []HTTPHeader
	for k, v := range headers {
		httpHeaders = append(httpHeaders, HTTPHeader{Key: k, Value: v})
	}

	return session.GetProtocol().SendPushRequest(
		session.GetConn(),
		requestID,
		channelID,
		method,
		path,
		query,
		httpHeaders,
		body,
		remoteAddr,
		sessionID,
	)
}

func (t *TunnelSenderImpl) SendTCPData(sessionID, channelID, connectionID string, data []byte, flags uint8) error {
	session, ok := t.sessions.Get(sessionID)
	if !ok {
		logger.Errorf("SendTCPData failed: session not found: %s, channel: %s, connection: %s", sessionID, channelID, connectionID)
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return session.GetProtocol().SendDataPacket(
		session.GetConn(),
		channelID,
		connectionID,
		0,
		data,
		flags,
		sessionID,
	)
}

func (t *TunnelSenderImpl) SendUDPData(sessionID, channelID string, data []byte, srcAddr string) error {
	session, ok := t.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	return session.GetProtocol().SendDataPacket(
		session.GetConn(),
		channelID,
		srcAddr,
		0,
		data,
		0,
		sessionID,
	)
}
