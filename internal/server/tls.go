package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/upstream/certmgr"
	logger "icool.io/yat/edge/pkg/log"
)

// extractDeviceIdentity extracts device identity and scope capabilities from a TLS
// client certificate. The returned capabilities slice is nil when the
// certificate carries no yat-scope extension (meaning full access).
func extractDeviceIdentity(conn *tls.Conn) (deviceID string, capabilities []string, err error) {

	if err := conn.Handshake(); err != nil {
		return "", nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", nil, ErrNoClientCertificate
	}

	cert := state.PeerCertificates[0]
	cn := cert.Subject.CommonName

	// Extract scope claims from the yat-scope X.509 extension.
	// nil = no extension present = full (unrestricted) access.
	scopes := certmgr.FindScopeExtension(cert)

	parts := strings.Split(cn, "_")

	// Single format: device_{deviceId} (device-only certificate, no user ID)
	if len(parts) >= 2 && parts[0] == "device" {
		deviceID := strings.Join(parts[1:], "_")
		return deviceID, scopes, nil
	}

	return "", nil, ErrInvalidCertificateCN
}

// Handle
func (s *Server) handleCertRequestOnly(tlsConn *tls.Conn) {
	protocol := NewProtocol()

	// Set
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Defer to ensure cleanup and error handling
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Recovered from panic in handleCertRequestOnly: %v", r)
			tlsConn.Close()
		}
	}()

	msg, err := protocol.ReadMessage(tlsConn)
	if err != nil {
		// Type
		if err == io.EOF || strings.Contains(err.Error(), "read length: EOF") {
			// Check
			logger.Debug("connection closed before sending certificate request")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Read
			logger.Warn("certificate request read timeout")
		} else if strings.Contains(err.Error(), "invalid message length") {
			// Invalid protocol or corrupted data
			logger.Warnf("Invalid protocol data received: %v", err)
		} else if strings.Contains(err.Error(), "message data too short") ||
			strings.Contains(err.Error(), "message has no header") ||
			strings.Contains(err.Error(), "failed to parse message") ||
			strings.Contains(err.Error(), "panic during message parsing") {
			// Corrupted FlatBuffers data
			logger.Warnf("Corrupted message data received: %v", err)
		} else {
			// Check
			if strings.Contains(err.Error(), "tls:") {
				logger.Errorf("TLS error during certificate request: %v", err)
				state := tlsConn.ConnectionState()
				logger.Errorf("TLS connection state: handshakeComplete=%v, didResume=%v, version=0x%x, negotiatedProto=%s",
					state.HandshakeComplete,
					state.DidResume,
					state.Version,
					state.NegotiatedProtocol)
				if len(state.PeerCertificates) > 0 {
					logger.Errorf("Peer certificate count: %d", len(state.PeerCertificates))
					for i, cert := range state.PeerCertificates {
						logger.Errorf("Peer certificate[%d]: Subject=%s, Issuer=%s", i, cert.Subject, cert.Issuer)
					}
				} else {
					logger.Info("No peer certificates presented")
				}
				logger.Errorf("Local certificate count: %d", len(state.VerifiedChains))
			} else {
				// Error
				logger.Errorf("read certificate request failed: %v", err)
			}
		}
		return
	}

	if msg.Header(nil).Type() != fbMsg.MessageTypeCERT_REQUEST {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeINVALID_MESSAGE, "only CERT_REQUEST allowed without client certificate", "")
		return
	}

	// Parse
	req := new(fbMsg.CertRequest)
	table := new(flatbuffers.Table)
	msg.Body(table)
	req.Init(table.Bytes, table.Pos)

	token := string(req.Token())
	deviceID := string(req.DeviceId())
	csrBytes := req.CsrBytes()

	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "device_id is required", "")
		return
	}
	block, _ := pem.Decode(csrBytes)
	if block == nil {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invalid CSR", "")
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invalid CSR signature", "")
		return
	}
	credential, parseErr := parseEnrollmentToken(token)
	if parseErr != nil {
		protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invalid enrollment token", "")
		return
	}
	var certScopes []string
	role := certmgr.RoleDevice
	switch credential.scheme {
	case "pair":
		if s.pairTokenVerifier == nil {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "pairing unavailable", "")
			return
		}
		role, err = s.pairTokenVerifier.Verify(credential.secret)
		if err != nil {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invalid or expired pairing token", "")
			return
		}
		certScopes = []string{"*"}
	case "invite":
		if s.inviteVerifier == nil {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invite verification unavailable", "")
			return
		}
		networkID, _, verifyErr := s.inviteVerifier.Peek(credential.secret)
		if verifyErr != nil {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "invalid invite token", "")
			return
		}
		// A caller cannot widen its invite by requesting wildcard scopes.
		certScopes = []string{"network:" + networkID}
	default:
		protocol.SendError(tlsConn, fbMsg.ErrorCodeAUTH_FAILED, "valid pair or invite token required", "")
		return
	}
	// Handle
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.certIssuer.Issue(ctx, &IssueRequest{
		EdgeID:   s.config.Node.ID,
		Role:     role,
		DeviceID: deviceID,
		CSR:      csrBytes,
		Scopes:   certScopes,
	})
	if err != nil {
		logger.Errorf("certificate issuing failed: %v", err)

		// Type
		if errors.Is(err, ErrCertServiceUnavailable) {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeINTERNAL_ERROR, "certificate signing service not available", "")
		} else {
			protocol.SendError(tlsConn, fbMsg.ErrorCodeINTERNAL_ERROR, "certificate signing failed", "")
		}
		return
	}

	logger.Infof("client cert issued, device: %s, serial: %s", deviceID, result.SerialNumber)

	// Send
	if err := s.sendCertResponseDirect(tlsConn, protocol, result); err != nil {
		logger.Errorf("send cert response failed: %v", err)
	}
}

// Handle
func (s *Server) handleClientCertRequestForSession(session *Session, msg *fbMsg.Message) error {

	// Parse
	req := new(fbMsg.CertRequest)
	table := new(flatbuffers.Table)
	msg.Body(table)
	req.Init(table.Bytes, table.Pos)

	requestedDeviceID := strings.TrimSpace(string(req.DeviceId()))
	csrBytes := req.CsrBytes()

	userID, deviceID, identityErr := resolveSessionCSRIdentity(
		session.UserID,
		session.DeviceID,
		"",
		requestedDeviceID,
	)
	if identityErr != nil {
		logger.Warnf(
			"reject cert request from session due to identity mismatch, session=%s, session_user=%s, req_user=%s, session_device=%s, req_device=%s, err=%v",
			strings.TrimSpace(session.ID),
			strings.TrimSpace(session.UserID),
			"",
			strings.TrimSpace(session.DeviceID),
			requestedDeviceID,
			identityErr,
		)
		return session.Protocol.SendError(
			session.Conn,
			fbMsg.ErrorCodeAUTH_FAILED,
			"certificate request identity mismatch, please reconnect and retry",
			session.ID,
		)
	}

	logger.Infof(
		"cert request from session, session=%s, user=%s, device=%s",
		strings.TrimSpace(session.ID),
		userID,
		deviceID,
	)

	// Only the current certificate and a verified invite can grant scopes.
	certScopes := append([]string(nil), session.ScopeClaims...)
	if token := string(req.Token()); token != "" {
		credential, err := parseEnrollmentToken(token)
		if err != nil || credential.scheme != "invite" {
			return session.Protocol.SendError(session.Conn, fbMsg.ErrorCodeAUTH_FAILED, "use an invite token or renew with the current certificate", session.ID)
		}
		if s.inviteVerifier == nil {
			return session.Protocol.SendError(session.Conn, fbMsg.ErrorCodeAUTH_FAILED, "invite verification unavailable", session.ID)
		}
		networkID, _, err := s.inviteVerifier.Peek(credential.secret)
		if err != nil {
			return session.Protocol.SendError(session.Conn, fbMsg.ErrorCodeAUTH_FAILED, "invalid invite token", session.ID)
		}
		unrestricted, present := len(certScopes) == 0, false
		for _, scope := range certScopes {
			unrestricted = unrestricted || scope == "*"
			present = present || scope == "network:"+networkID
		}
		if !unrestricted && !present {
			certScopes = append(certScopes, "network:"+networkID)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := s.certIssuer.Issue(ctx, &IssueRequest{
		EdgeID:   s.config.Node.ID,
		Role:     session.Role,
		DeviceID: deviceID,
		CSR:      csrBytes,
		Scopes:   certScopes,
	})
	if err != nil {
		logger.Errorf("forward CSR failed: %v", err)
		return session.Protocol.SendError(session.Conn, fbMsg.ErrorCodeINTERNAL_ERROR,
			fmt.Sprintf("certificate signing failed: %v", err), session.ID)
	}

	logger.Infof("client cert issued via EdgeCA, user: %s, device: %s, serial: %s", userID, deviceID, result.SerialNumber)
	// Send
	return s.sendCertResponseDirect(session.Conn, session.Protocol, result)
}

// Send
func (s *Server) sendCertResponseDirect(conn *tls.Conn, protocol *Protocol, result *CertIssueResult) error {
	builder := flatbuffers.NewBuilder(2048)

	// Create
	certOffset := builder.CreateByteVector(result.CertificatePEM)
	chainOffset := builder.CreateByteVector(result.CertificateChain)
	caOffset := builder.CreateByteVector(result.CACertificatePEM)
	serialOffset := builder.CreateString(result.SerialNumber)
	errMsgOffset := builder.CreateString("")

	fbMsg.CertResponseStart(builder)
	fbMsg.CertResponseAddSuccess(builder, true)
	fbMsg.CertResponseAddCertificate(builder, certOffset)
	fbMsg.CertResponseAddCertificateChain(builder, chainOffset)
	fbMsg.CertResponseAddCaCertificate(builder, caOffset)
	fbMsg.CertResponseAddExpiresAt(builder, uint64(result.ExpiresAt.UnixMilli()))
	fbMsg.CertResponseAddSerialNumber(builder, serialOffset)
	fbMsg.CertResponseAddErrorCode(builder, 0)
	fbMsg.CertResponseAddErrorMessage(builder, errMsgOffset)
	resp := fbMsg.CertResponseEnd(builder)

	sessIDOffset := builder.CreateString("")
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeCERT_RESPONSE)
	fbMsg.MessageHeaderAddSessionId(builder, sessIDOffset)
	header := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, header)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyCertResponse)
	fbMsg.MessageAddBody(builder, resp)
	msgObj := fbMsg.MessageEnd(builder)

	builder.Finish(msgObj)
	data := builder.FinishedBytes()

	return protocol.WriteMessage(conn, data)
}

// tokenPrefix returns the enrollment token type for logging.
func tokenPrefix(token string) string {
	switch {
	case strings.HasPrefix(token, "pair:"):
		return "pair"
	case strings.HasPrefix(token, "invite:"):
		return "invite"
	case token == "":
		return "<empty>"
	default:
		return "legacy"
	}
}

// mergeScopes combines two scope lists and deduplicates.
// If either list contains "*" (full access), the result is ["*"].
func mergeScopes(a, b []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, s := range a {
		if s == "*" {
			return []string{"*"}
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if s == "*" {
			return []string{"*"}
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
