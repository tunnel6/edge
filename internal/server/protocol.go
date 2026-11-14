package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	message "icool.io/yat/api/build/fb/golang/message"
	channel "icool.io/yat/edge/internal/channel/types"
	"icool.io/yat/edge/internal/server/handler"
	"icool.io/yat/edge/pkg/config"
)

// Handle

type Protocol struct {
	builder *flatbuffers.Builder
	mu      sync.Mutex
}

type AuthNegotiationResult struct {
	NegotiatedProtocolMajor uint16
	NegotiatedProtocolMinor uint16
	AcceptedFeatures        []string
	RejectedFeatures        []string
	CompatibilityLevel      message.CompatibilityLevel
	ReasonCode              message.CompatibilityReasonCode
}

// Handle
func NewProtocol() *Protocol {
	return &Protocol{
		builder: flatbuffers.NewBuilder(1024),
	}
}

// Read
func (p *Protocol) ReadMessage(conn net.Conn) (msg *message.Message, err error) {
	// Recover from any panics during parsing
	defer func() {
		if r := recover(); r != nil {
			// Convert panic to error
			err = fmt.Errorf("panic during message parsing: %v", r)
			msg = nil
		}
	}()

	// Read
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	// Check
	if length == 0 || length > 10*1024*1024 {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	// Read
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// Validate data before parsing
	if len(data) < 8 {
		return nil, fmt.Errorf("message data too short: %d bytes", len(data))
	}

	msg = message.GetRootAsMessage(data, 0)

	// Validate parsed message structure
	if msg == nil {
		return nil, fmt.Errorf("failed to parse message")
	}

	// Basic validation: check if we can access the header without panic
	header := msg.Header(nil)
	if header == nil {
		return nil, fmt.Errorf("message has no header")
	}

	return msg, nil
}

// Write
func (p *Protocol) writeMessageUnlocked(conn net.Conn, msg []byte) error {
	// Guard against slow peers: cap each write at 5s to prevent
	// handleSession from blocking indefinitely on a congested TCP buffer.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetWriteDeadline(time.Time{}) // clear deadline

	// Write
	length := uint32(len(msg))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %w", err)
	}

	// Write
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}

	return nil
}

// Write
func (p *Protocol) WriteMessage(conn net.Conn, msg []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeMessageUnlocked(conn, msg)
}

// Send
func (p *Protocol) SendAuthResponse(conn net.Conn, success bool, sessionID, errorMsg string, errorCode uint32, nego *AuthNegotiationResult) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	// Create
	sessionIDOffset := p.builder.CreateString(sessionID)
	errorOffset := p.builder.CreateString(errorMsg)
	serverVersion := p.builder.CreateString(config.Version)
	var acceptedFeaturesOffset flatbuffers.UOffsetT
	var rejectedFeaturesOffset flatbuffers.UOffsetT
	if nego != nil && len(nego.AcceptedFeatures) > 0 {
		offsets := make([]flatbuffers.UOffsetT, 0, len(nego.AcceptedFeatures))
		for _, item := range nego.AcceptedFeatures {
			offsets = append(offsets, p.builder.CreateString(item))
		}
		message.AuthResponseStartAcceptedFeaturesVector(p.builder, len(offsets))
		for i := len(offsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(offsets[i])
		}
		acceptedFeaturesOffset = p.builder.EndVector(len(offsets))
	}
	if nego != nil && len(nego.RejectedFeatures) > 0 {
		offsets := make([]flatbuffers.UOffsetT, 0, len(nego.RejectedFeatures))
		for _, item := range nego.RejectedFeatures {
			offsets = append(offsets, p.builder.CreateString(item))
		}
		message.AuthResponseStartRejectedFeaturesVector(p.builder, len(offsets))
		for i := len(offsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(offsets[i])
		}
		rejectedFeaturesOffset = p.builder.EndVector(len(offsets))
	}

	// Build
	message.AuthResponseStart(p.builder)
	message.AuthResponseAddSuccess(p.builder, success)
	message.AuthResponseAddSessionId(p.builder, sessionIDOffset)
	message.AuthResponseAddServerVersion(p.builder, serverVersion)
	message.AuthResponseAddErrorCode(p.builder, errorCode)
	message.AuthResponseAddErrorMessage(p.builder, errorOffset)
	message.AuthResponseAddServerTime(p.builder, uint64(now()))
	if nego != nil {
		message.AuthResponseAddNegotiatedProtocolMajor(p.builder, nego.NegotiatedProtocolMajor)
		message.AuthResponseAddNegotiatedProtocolMinor(p.builder, nego.NegotiatedProtocolMinor)
		if acceptedFeaturesOffset != 0 {
			message.AuthResponseAddAcceptedFeatures(p.builder, acceptedFeaturesOffset)
		}
		if rejectedFeaturesOffset != 0 {
			message.AuthResponseAddRejectedFeatures(p.builder, rejectedFeaturesOffset)
		}
		message.AuthResponseAddCompatibilityLevel(p.builder, nego.CompatibilityLevel)
		message.AuthResponseAddReasonCode(p.builder, nego.ReasonCode)
	}
	authResp := message.AuthResponseEnd(p.builder)

	// Build
	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeAUTH_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	// Build
	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyAuthResponse)
	message.MessageAddBody(p.builder, authResp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendHeartbeatAck(conn net.Conn, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	// Build
	message.HeartbeatAckStart(p.builder)
	message.HeartbeatAckAddServerTime(p.builder, uint64(now()))
	hbAck := message.HeartbeatAckEnd(p.builder)

	// Build
	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeHEARTBEAT_ACK)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	// Build
	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyHeartbeatAck)
	message.MessageAddBody(p.builder, hbAck)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// SendError sends an ERROR message with seq=0 (legacy behavior).
// Use SendErrorWithSeq when responding to a specific request to ensure
// the error is matched to the correct pending waiter on the client side.
func (p *Protocol) SendError(conn net.Conn, code message.ErrorCode, msg string, sessionID string) error {
	return p.SendErrorWithSeq(conn, code, msg, sessionID, 0)
}

// SendErrorWithSeq sends an ERROR message with the specified sequence number.
// When seq is non-zero, the client's dispatch logic will match the error to
// the pending request with the same seq, preventing misdelivery to unrelated waiters.
func (p *Protocol) SendErrorWithSeq(conn net.Conn, code message.ErrorCode, msg string, sessionID string, seq uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	msgOffset := p.builder.CreateString(msg)
	detailsOffset := p.builder.CreateString(sessionID)

	// Build
	message.ErrorStart(p.builder)
	message.ErrorAddCode(p.builder, code)
	message.ErrorAddMessage(p.builder, msgOffset)
	message.ErrorAddDetails(p.builder, detailsOffset)
	errMsg := message.ErrorEnd(p.builder)

	// Build
	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeERROR)
	message.MessageHeaderAddSeq(p.builder, seq)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	// Build
	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyError)
	message.MessageAddBody(p.builder, errMsg)
	msgObj := message.MessageEnd(p.builder)

	p.builder.Finish(msgObj)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

func (p *Protocol) SendTunnelStartResponse(conn net.Conn, resp *message.TunnelStartResponseT, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	payload := resp
	if payload == nil {
		payload = &message.TunnelStartResponseT{}
	}

	tunnelIDOffset := maybeCreateString(p.builder, payload.TunnelId)
	edgeIDOffset := maybeCreateString(p.builder, payload.EdgeId)
	errorMessageOffset := maybeCreateString(p.builder, payload.ErrorMessage)
	summaryOffset := buildTunnelOperationSummaryOffset(p.builder, payload.Summary)
	runtimeSnapshotOffset := buildTunnelRuntimeSnapshotOffset(p.builder, payload.RuntimeSnapshot)
	channelVec := buildTunnelStartResultVectorOffset(p.builder, payload.Channels)

	message.TunnelStartResponseStart(p.builder)
	message.TunnelStartResponseAddSuccess(p.builder, payload.Success)
	message.TunnelStartResponseAddMode(p.builder, payload.Mode)
	if tunnelIDOffset != 0 {
		message.TunnelStartResponseAddTunnelId(p.builder, tunnelIDOffset)
	}
	if edgeIDOffset != 0 {
		message.TunnelStartResponseAddEdgeId(p.builder, edgeIDOffset)
	}
	if summaryOffset != 0 {
		message.TunnelStartResponseAddSummary(p.builder, summaryOffset)
	}
	if channelVec != 0 {
		message.TunnelStartResponseAddChannels(p.builder, channelVec)
	}
	if runtimeSnapshotOffset != 0 {
		message.TunnelStartResponseAddRuntimeSnapshot(p.builder, runtimeSnapshotOffset)
	}
	message.TunnelStartResponseAddErrorCode(p.builder, payload.ErrorCode)
	if errorMessageOffset != 0 {
		message.TunnelStartResponseAddErrorMessage(p.builder, errorMessageOffset)
	}
	respOffset := message.TunnelStartResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_START_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelStartResponse)
	message.MessageAddBody(p.builder, respOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelStopResponse(conn net.Conn, resp *message.TunnelStopResponseT, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	payload := resp
	if payload == nil {
		payload = &message.TunnelStopResponseT{}
	}

	tunnelIDOffset := maybeCreateString(p.builder, payload.TunnelId)
	edgeIDOffset := maybeCreateString(p.builder, payload.EdgeId)
	errorMessageOffset := maybeCreateString(p.builder, payload.ErrorMessage)
	summaryOffset := buildTunnelOperationSummaryOffset(p.builder, payload.Summary)
	runtimeSnapshotOffset := buildTunnelRuntimeSnapshotOffset(p.builder, payload.RuntimeSnapshot)
	channelVec := buildTunnelStopResultVectorOffset(p.builder, payload.Channels)

	message.TunnelStopResponseStart(p.builder)
	message.TunnelStopResponseAddSuccess(p.builder, payload.Success)
	message.TunnelStopResponseAddMode(p.builder, payload.Mode)
	if tunnelIDOffset != 0 {
		message.TunnelStopResponseAddTunnelId(p.builder, tunnelIDOffset)
	}
	if edgeIDOffset != 0 {
		message.TunnelStopResponseAddEdgeId(p.builder, edgeIDOffset)
	}
	if summaryOffset != 0 {
		message.TunnelStopResponseAddSummary(p.builder, summaryOffset)
	}
	if channelVec != 0 {
		message.TunnelStopResponseAddChannels(p.builder, channelVec)
	}
	if runtimeSnapshotOffset != 0 {
		message.TunnelStopResponseAddRuntimeSnapshot(p.builder, runtimeSnapshotOffset)
	}
	message.TunnelStopResponseAddErrorCode(p.builder, payload.ErrorCode)
	if errorMessageOffset != 0 {
		message.TunnelStopResponseAddErrorMessage(p.builder, errorMessageOffset)
	}
	respOffset := message.TunnelStopResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_STOP_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelStopResponse)
	message.MessageAddBody(p.builder, respOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelJoinResponse(conn net.Conn, resp *message.TunnelJoinResponseT, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	payload := resp
	if payload == nil {
		payload = &message.TunnelJoinResponseT{}
	}

	tunnelIDOffset := maybeCreateString(p.builder, payload.TunnelId)
	edgeIDOffset := maybeCreateString(p.builder, payload.EdgeId)
	errorMessageOffset := maybeCreateString(p.builder, payload.ErrorMessage)
	summaryOffset := buildTunnelOperationSummaryOffset(p.builder, payload.Summary)
	runtimeSnapshotOffset := buildTunnelRuntimeSnapshotOffset(p.builder, payload.RuntimeSnapshot)
	channelVec := buildTunnelStartResultVectorOffset(p.builder, payload.Channels)

	message.TunnelJoinResponseStart(p.builder)
	message.TunnelJoinResponseAddSuccess(p.builder, payload.Success)
	message.TunnelJoinResponseAddMode(p.builder, payload.Mode)
	if tunnelIDOffset != 0 {
		message.TunnelJoinResponseAddTunnelId(p.builder, tunnelIDOffset)
	}
	if edgeIDOffset != 0 {
		message.TunnelJoinResponseAddEdgeId(p.builder, edgeIDOffset)
	}
	if summaryOffset != 0 {
		message.TunnelJoinResponseAddSummary(p.builder, summaryOffset)
	}
	if channelVec != 0 {
		message.TunnelJoinResponseAddChannels(p.builder, channelVec)
	}
	if runtimeSnapshotOffset != 0 {
		message.TunnelJoinResponseAddRuntimeSnapshot(p.builder, runtimeSnapshotOffset)
	}
	message.TunnelJoinResponseAddErrorCode(p.builder, payload.ErrorCode)
	if errorMessageOffset != 0 {
		message.TunnelJoinResponseAddErrorMessage(p.builder, errorMessageOffset)
	}
	respOffset := message.TunnelJoinResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_JOIN_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelJoinResponse)
	message.MessageAddBody(p.builder, respOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelLeaveResponse(conn net.Conn, resp *message.TunnelLeaveResponseT, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	payload := resp
	if payload == nil {
		payload = &message.TunnelLeaveResponseT{}
	}

	tunnelIDOffset := maybeCreateString(p.builder, payload.TunnelId)
	edgeIDOffset := maybeCreateString(p.builder, payload.EdgeId)
	errorMessageOffset := maybeCreateString(p.builder, payload.ErrorMessage)
	summaryOffset := buildTunnelOperationSummaryOffset(p.builder, payload.Summary)
	runtimeSnapshotOffset := buildTunnelRuntimeSnapshotOffset(p.builder, payload.RuntimeSnapshot)
	channelVec := buildTunnelStopResultVectorOffset(p.builder, payload.Channels)

	message.TunnelLeaveResponseStart(p.builder)
	message.TunnelLeaveResponseAddSuccess(p.builder, payload.Success)
	message.TunnelLeaveResponseAddMode(p.builder, payload.Mode)
	if tunnelIDOffset != 0 {
		message.TunnelLeaveResponseAddTunnelId(p.builder, tunnelIDOffset)
	}
	if edgeIDOffset != 0 {
		message.TunnelLeaveResponseAddEdgeId(p.builder, edgeIDOffset)
	}
	if summaryOffset != 0 {
		message.TunnelLeaveResponseAddSummary(p.builder, summaryOffset)
	}
	if channelVec != 0 {
		message.TunnelLeaveResponseAddChannels(p.builder, channelVec)
	}
	if runtimeSnapshotOffset != 0 {
		message.TunnelLeaveResponseAddRuntimeSnapshot(p.builder, runtimeSnapshotOffset)
	}
	message.TunnelLeaveResponseAddErrorCode(p.builder, payload.ErrorCode)
	if errorMessageOffset != 0 {
		message.TunnelLeaveResponseAddErrorMessage(p.builder, errorMessageOffset)
	}
	respOffset := message.TunnelLeaveResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_LEAVE_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelLeaveResponse)
	message.MessageAddBody(p.builder, respOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

// Send
func (p *Protocol) SendChannelStatus(conn net.Conn, channelID string, active bool, bytesIn, bytesOut uint64, connections uint32, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	channelIDOffset := p.builder.CreateString(channelID)

	message.ChannelStatusStart(p.builder)
	message.ChannelStatusAddChannelId(p.builder, channelIDOffset)
	message.ChannelStatusAddActive(p.builder, active)
	message.ChannelStatusAddBytesIn(p.builder, bytesIn)
	message.ChannelStatusAddBytesOut(p.builder, bytesOut)
	message.ChannelStatusAddConnections(p.builder, connections)
	status := message.ChannelStatusEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeCHANNEL_STATUS)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyChannelStatus)
	message.MessageAddBody(p.builder, status)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendEdgeOnlineResponse(conn net.Conn, success bool, errorCode uint32, errorMsg, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	errMsgOffset := p.builder.CreateString(errorMsg)

	message.EdgeOnlineResponseStart(p.builder)
	message.EdgeOnlineResponseAddSuccess(p.builder, success)
	message.EdgeOnlineResponseAddErrorCode(p.builder, errorCode)
	message.EdgeOnlineResponseAddErrorMessage(p.builder, errMsgOffset)
	resp := message.EdgeOnlineResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeEDGE_ONLINE_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyEdgeOnlineResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendEdgeOfflineResponse(conn net.Conn, success bool, errorCode uint32, errorMsg, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	errMsgOffset := p.builder.CreateString(errorMsg)

	message.EdgeOfflineResponseStart(p.builder)
	message.EdgeOfflineResponseAddSuccess(p.builder, success)
	message.EdgeOfflineResponseAddErrorCode(p.builder, errorCode)
	message.EdgeOfflineResponseAddErrorMessage(p.builder, errMsgOffset)
	resp := message.EdgeOfflineResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeEDGE_OFFLINE_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyEdgeOfflineResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendDataPacket(conn net.Conn, channelID, connectionID string, seq uint32, data []byte, flags uint8, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	channelIDOffset := p.builder.CreateString(channelID)
	connIDOffset := p.builder.CreateString(connectionID)
	dataOffset := p.builder.CreateByteVector(data)

	message.DataPacketStart(p.builder)
	message.DataPacketAddChannelId(p.builder, channelIDOffset)
	message.DataPacketAddConnectionId(p.builder, connIDOffset)
	message.DataPacketAddSeq(p.builder, seq)
	message.DataPacketAddData(p.builder, dataOffset)
	message.DataPacketAddFlags(p.builder, flags)
	packet := message.DataPacketEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeDATA_PACKET)
	message.MessageHeaderAddSeq(p.builder, seq)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyDataPacket)
	message.MessageAddBody(p.builder, packet)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	msgData := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, msgData)
}

// Send
func (p *Protocol) SendDataAck(conn net.Conn, channelID, connectionID string, ackSeq uint32, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	channelIDOffset := p.builder.CreateString(channelID)
	connIDOffset := p.builder.CreateString(connectionID)

	message.DataAckStart(p.builder)
	message.DataAckAddChannelId(p.builder, channelIDOffset)
	message.DataAckAddConnectionId(p.builder, connIDOffset)
	message.DataAckAddAckSeq(p.builder, ackSeq)
	ack := message.DataAckEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeDATA_ACK)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyDataAck)
	message.MessageAddBody(p.builder, ack)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendPushRequest(conn net.Conn, requestID, channelID, method, path, query string, headers []channel.HTTPHeader, body []byte, remoteAddr, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	// Create
	reqIDOffset := p.builder.CreateString(requestID)
	channelIDOffset := p.builder.CreateString(channelID)
	methodOffset := p.builder.CreateString(method)
	pathOffset := p.builder.CreateString(path)
	queryOffset := p.builder.CreateString(query)
	remoteAddrOffset := p.builder.CreateString(remoteAddr)

	// Create
	headerOffsets := make([]flatbuffers.UOffsetT, len(headers))
	for i, h := range headers {
		keyOffset := p.builder.CreateString(h.Key)
		valueOffset := p.builder.CreateString(h.Value)
		message.HTTPHeaderStart(p.builder)
		message.HTTPHeaderAddKey(p.builder, keyOffset)
		message.HTTPHeaderAddValue(p.builder, valueOffset)
		headerOffsets[i] = message.HTTPHeaderEnd(p.builder)
	}

	message.PushRequestStartHeadersVector(p.builder, len(headers))
	for i := len(headerOffsets) - 1; i >= 0; i-- {
		p.builder.PrependUOffsetT(headerOffsets[i])
	}
	headersVec := p.builder.EndVector(len(headers))

	// Create
	bodyOffset := p.builder.CreateByteVector(body)

	message.PushRequestStart(p.builder)
	message.PushRequestAddRequestId(p.builder, reqIDOffset)
	message.PushRequestAddChannelId(p.builder, channelIDOffset)
	message.PushRequestAddMethod(p.builder, methodOffset)
	message.PushRequestAddPath(p.builder, pathOffset)
	message.PushRequestAddQuery(p.builder, queryOffset)
	message.PushRequestAddHeaders(p.builder, headersVec)
	message.PushRequestAddBody(p.builder, bodyOffset)
	message.PushRequestAddRemoteAddr(p.builder, remoteAddrOffset)
	req := message.PushRequestEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypePUSH_REQUEST)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyPushRequest)
	message.MessageAddBody(p.builder, req)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

// Send
func (p *Protocol) SendEdgeStatusPush(conn net.Conn, status *handler.EdgeStatusInfo, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	// Create
	edgeIDOffset := p.builder.CreateString(status.EdgeID)

	// Create
	tcpRangeOffset := p.builder.CreateString(status.PortUsage.TCPRange)
	udpRangeOffset := p.builder.CreateString(status.PortUsage.UDPRange)
	message.PortUsageInfoStart(p.builder)
	message.PortUsageInfoAddTcpUsed(p.builder, status.PortUsage.TCPUsed)
	message.PortUsageInfoAddTcpTotal(p.builder, status.PortUsage.TCPTotal)
	message.PortUsageInfoAddTcpRange(p.builder, tcpRangeOffset)
	message.PortUsageInfoAddUdpUsed(p.builder, status.PortUsage.UDPUsed)
	message.PortUsageInfoAddUdpTotal(p.builder, status.PortUsage.UDPTotal)
	message.PortUsageInfoAddUdpRange(p.builder, udpRangeOffset)
	message.PortUsageInfoAddHttpPort(p.builder, status.PortUsage.HTTPPort)
	message.PortUsageInfoAddHttpsPort(p.builder, status.PortUsage.HTTPSPort)
	portUsageOffset := message.PortUsageInfoEnd(p.builder)

	// Create
	message.ServiceStatsInfoStart(p.builder)
	message.ServiceStatsInfoAddTotalSessions(p.builder, status.Stats.TotalSessions)
	message.ServiceStatsInfoAddActiveSessions(p.builder, status.Stats.ActiveSessions)
	message.ServiceStatsInfoAddTotalChannels(p.builder, status.Stats.TotalChannels)
	message.ServiceStatsInfoAddActiveChannels(p.builder, status.Stats.ActiveChannels)
	message.ServiceStatsInfoAddTotalBytesIn(p.builder, status.Stats.TotalBytesIn)
	message.ServiceStatsInfoAddTotalBytesOut(p.builder, status.Stats.TotalBytesOut)
	message.ServiceStatsInfoAddTotalConnections(p.builder, status.Stats.TotalConnections)
	message.ServiceStatsInfoAddTotalRequests(p.builder, status.Stats.TotalRequests)
	message.ServiceStatsInfoAddTotalErrors(p.builder, status.Stats.TotalErrors)
	statsOffset := message.ServiceStatsInfoEnd(p.builder)

	// Create
	var protoOffsets []flatbuffers.UOffsetT
	for _, proto := range status.SupportedProtocols {
		protoOffsets = append(protoOffsets, p.builder.CreateString(proto))
	}
	message.EdgeStatusPushStartSupportedProtocolsVector(p.builder, len(protoOffsets))
	for i := len(protoOffsets) - 1; i >= 0; i-- {
		p.builder.PrependUOffsetT(protoOffsets[i])
	}
	protocolsVec := p.builder.EndVector(len(protoOffsets))

	var dns01Vec flatbuffers.UOffsetT
	if len(status.DNS01Challenges) > 0 {
		dns01Offsets := make([]flatbuffers.UOffsetT, 0, len(status.DNS01Challenges))
		for _, ch := range status.DNS01Challenges {
			rnOffset := p.builder.CreateString(ch.RecordName)
			rvOffset := p.builder.CreateString(ch.RecordValue)
			domOffset := p.builder.CreateString(ch.Domain)
			var leOffset flatbuffers.UOffsetT
			if ch.LastError != "" {
				leOffset = p.builder.CreateString(ch.LastError)
			}
			message.DNS01ChallengeInfoStart(p.builder)
			message.DNS01ChallengeInfoAddRecordName(p.builder, rnOffset)
			message.DNS01ChallengeInfoAddRecordValue(p.builder, rvOffset)
			message.DNS01ChallengeInfoAddDomain(p.builder, domOffset)
			message.DNS01ChallengeInfoAddCreatedAt(p.builder, ch.CreatedAt)
			if leOffset != 0 {
				message.DNS01ChallengeInfoAddLastError(p.builder, leOffset)
			}
			if ch.UpdatedAt > 0 {
				message.DNS01ChallengeInfoAddUpdatedAt(p.builder, ch.UpdatedAt)
			}
			dns01Offsets = append(dns01Offsets, message.DNS01ChallengeInfoEnd(p.builder))
		}
		p.builder.StartVector(4, len(dns01Offsets), 4)
		for i := len(dns01Offsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(dns01Offsets[i])
		}
		dns01Vec = p.builder.EndVector(len(dns01Offsets))
	}

	// Create domain status info tables
	var assignedStatusOffset, customStatusOffset flatbuffers.UOffsetT
	if status.AssignedDNSStatus.DNSStatus != 0 || status.AssignedDNSStatus.CertStatus != 0 ||
		status.AssignedDNSStatus.Error != "" || status.AssignedDNSStatus.CertLastError != "" || status.AssignedDNSStatus.UpdatedAt > 0 {
		var errOffset, certErrOffset flatbuffers.UOffsetT
		if status.AssignedDNSStatus.Error != "" {
			errOffset = p.builder.CreateString(status.AssignedDNSStatus.Error)
		}
		if status.AssignedDNSStatus.CertLastError != "" {
			certErrOffset = p.builder.CreateString(status.AssignedDNSStatus.CertLastError)
		}
		message.DomainStatusInfoStart(p.builder)
		message.DomainStatusInfoAddDnsStatus(p.builder, status.AssignedDNSStatus.DNSStatus)
		message.DomainStatusInfoAddCertStatus(p.builder, status.AssignedDNSStatus.CertStatus)
		if errOffset != 0 {
			message.DomainStatusInfoAddError(p.builder, errOffset)
		}
		if certErrOffset != 0 {
			message.DomainStatusInfoAddCertLastError(p.builder, certErrOffset)
		}
		if status.AssignedDNSStatus.UpdatedAt > 0 {
			message.DomainStatusInfoAddUpdatedAt(p.builder, status.AssignedDNSStatus.UpdatedAt)
		}
		assignedStatusOffset = message.DomainStatusInfoEnd(p.builder)
	}
	if status.CustomDNSStatus.DNSStatus != 0 || status.CustomDNSStatus.CertStatus != 0 ||
		status.CustomDNSStatus.Error != "" || status.CustomDNSStatus.CertLastError != "" || status.CustomDNSStatus.UpdatedAt > 0 {
		var errOffset, certErrOffset flatbuffers.UOffsetT
		if status.CustomDNSStatus.Error != "" {
			errOffset = p.builder.CreateString(status.CustomDNSStatus.Error)
		}
		if status.CustomDNSStatus.CertLastError != "" {
			certErrOffset = p.builder.CreateString(status.CustomDNSStatus.CertLastError)
		}
		message.DomainStatusInfoStart(p.builder)
		message.DomainStatusInfoAddDnsStatus(p.builder, status.CustomDNSStatus.DNSStatus)
		message.DomainStatusInfoAddCertStatus(p.builder, status.CustomDNSStatus.CertStatus)
		if errOffset != 0 {
			message.DomainStatusInfoAddError(p.builder, errOffset)
		}
		if certErrOffset != 0 {
			message.DomainStatusInfoAddCertLastError(p.builder, certErrOffset)
		}
		if status.CustomDNSStatus.UpdatedAt > 0 {
			message.DomainStatusInfoAddUpdatedAt(p.builder, status.CustomDNSStatus.UpdatedAt)
		}
		customStatusOffset = message.DomainStatusInfoEnd(p.builder)
	}

	// Create unified domain runtime table
	var domainRuntimeOffset flatbuffers.UOffsetT
	{
		var requiredRecordsVec flatbuffers.UOffsetT
		if len(status.DomainRuntime.RequiredRecords) > 0 {
			recordOffsets := make([]flatbuffers.UOffsetT, 0, len(status.DomainRuntime.RequiredRecords))
			for _, rec := range status.DomainRuntime.RequiredRecords {
				recordNameOffset := p.builder.CreateString(rec.RecordName)
				recordValueOffset := p.builder.CreateString(rec.RecordValue)
				sourceOffset := p.builder.CreateString(rec.Source)

				message.DomainRecordInfoStart(p.builder)
				message.DomainRecordInfoAddRecordType(p.builder, message.DomainRecordType(rec.RecordType))
				message.DomainRecordInfoAddRecordName(p.builder, recordNameOffset)
				message.DomainRecordInfoAddRecordValue(p.builder, recordValueOffset)
				message.DomainRecordInfoAddTtl(p.builder, rec.TTL)
				if sourceOffset != 0 {
					message.DomainRecordInfoAddSource(p.builder, sourceOffset)
				}
				recordOffsets = append(recordOffsets, message.DomainRecordInfoEnd(p.builder))
			}

			message.DomainRuntimeInfoStartRequiredRecordsVector(p.builder, len(recordOffsets))
			for i := len(recordOffsets) - 1; i >= 0; i-- {
				p.builder.PrependUOffsetT(recordOffsets[i])
			}
			requiredRecordsVec = p.builder.EndVector(len(recordOffsets))
		}

		pendingReasonCodeOffset := p.builder.CreateString(status.DomainRuntime.PendingReasonCode)
		lastErrorOffset := p.builder.CreateString(status.DomainRuntime.LastError)
		message.DomainRuntimeInfoStart(p.builder)
		message.DomainRuntimeInfoAddOwnerView(p.builder, status.DomainRuntime.OwnerView)
		message.DomainRuntimeInfoAddState(p.builder, message.DomainRuntimeState(status.DomainRuntime.State))
		if requiredRecordsVec != 0 {
			message.DomainRuntimeInfoAddRequiredRecords(p.builder, requiredRecordsVec)
		}
		if pendingReasonCodeOffset != 0 {
			message.DomainRuntimeInfoAddPendingReasonCode(p.builder, pendingReasonCodeOffset)
		}
		if lastErrorOffset != 0 {
			message.DomainRuntimeInfoAddLastError(p.builder, lastErrorOffset)
		}
		message.DomainRuntimeInfoAddCnameStatus(p.builder, status.DomainRuntime.CnameStatus)
		message.DomainRuntimeInfoAddCertStatus(p.builder, status.DomainRuntime.CertStatus)
		if status.DomainRuntime.UpdatedAt > 0 {
			message.DomainRuntimeInfoAddUpdatedAt(p.builder, status.DomainRuntime.UpdatedAt)
		}
		domainRuntimeOffset = message.DomainRuntimeInfoEnd(p.builder)
	}

	// Create
	message.EdgeStatusPushStart(p.builder)
	message.EdgeStatusPushAddEdgeId(p.builder, edgeIDOffset)
	message.EdgeStatusPushAddOnline(p.builder, status.Online)
	message.EdgeStatusPushAddUptime(p.builder, status.Uptime)
	message.EdgeStatusPushAddPortUsage(p.builder, portUsageOffset)
	message.EdgeStatusPushAddStats(p.builder, statsOffset)
	message.EdgeStatusPushAddTimestamp(p.builder, status.Timestamp)
	message.EdgeStatusPushAddSupportedProtocols(p.builder, protocolsVec)
	message.EdgeStatusPushAddActiveSessions(p.builder, status.ActiveSessions)
	message.EdgeStatusPushAddIsOwnerView(p.builder, status.IsOwnerView)
	if dns01Vec != 0 {
		message.EdgeStatusPushAddDns01Challenges(p.builder, dns01Vec)
	}
	message.EdgeStatusPushAddCnameStatus(p.builder, status.CnameStatus)
	if assignedStatusOffset != 0 {
		message.EdgeStatusPushAddAssignedDomainStatus(p.builder, assignedStatusOffset)
	}
	if customStatusOffset != 0 {
		message.EdgeStatusPushAddCustomDomainStatus(p.builder, customStatusOffset)
	}
	if domainRuntimeOffset != 0 {
		message.EdgeStatusPushAddDomainRuntime(p.builder, domainRuntimeOffset)
	}
	message.EdgeStatusPushAddWireguardRelayRuntimeReady(p.builder, status.WireGuardRelayRuntimeReady)
	statusOffset := message.EdgeStatusPushEnd(p.builder)

	// Create
	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeEDGE_STATUS_PUSH)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, status.Timestamp)
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	// Create
	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyEdgeStatusPush)
	message.MessageAddBody(p.builder, statusOffset)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()

	return p.writeMessageUnlocked(conn, data)
}

func (p *Protocol) SendTunnelStatusResponse(conn net.Conn, status *handler.TunnelStatusInfo, sessionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	tunnelIDOffset := p.builder.CreateString(status.TunnelID)
	edgeIDOffset := p.builder.CreateString(status.EdgeID)
	errorMessageOffset := p.builder.CreateString(status.ErrorMessage)

	var dns01Vec flatbuffers.UOffsetT
	if len(status.DNS01Challenges) > 0 {
		dns01Offsets := make([]flatbuffers.UOffsetT, 0, len(status.DNS01Challenges))
		for _, ch := range status.DNS01Challenges {
			rnOffset := p.builder.CreateString(ch.RecordName)
			rvOffset := p.builder.CreateString(ch.RecordValue)
			domOffset := p.builder.CreateString(ch.Domain)
			var leOffset flatbuffers.UOffsetT
			if ch.LastError != "" {
				leOffset = p.builder.CreateString(ch.LastError)
			}
			message.DNS01ChallengeInfoStart(p.builder)
			message.DNS01ChallengeInfoAddRecordName(p.builder, rnOffset)
			message.DNS01ChallengeInfoAddRecordValue(p.builder, rvOffset)
			message.DNS01ChallengeInfoAddDomain(p.builder, domOffset)
			message.DNS01ChallengeInfoAddCreatedAt(p.builder, ch.CreatedAt)
			if leOffset != 0 {
				message.DNS01ChallengeInfoAddLastError(p.builder, leOffset)
			}
			if ch.UpdatedAt > 0 {
				message.DNS01ChallengeInfoAddUpdatedAt(p.builder, ch.UpdatedAt)
			}
			dns01Offsets = append(dns01Offsets, message.DNS01ChallengeInfoEnd(p.builder))
		}
		p.builder.StartVector(4, len(dns01Offsets), 4)
		for i := len(dns01Offsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(dns01Offsets[i])
		}
		dns01Vec = p.builder.EndVector(len(dns01Offsets))
	}

	buildDomainStatusOffset := func(value handler.DomainStatusInfo) flatbuffers.UOffsetT {
		if value.DNSStatus == 0 && value.CertStatus == 0 &&
			value.Error == "" && value.CertLastError == "" && value.UpdatedAt == 0 {
			return 0
		}
		var errOffset, certErrOffset flatbuffers.UOffsetT
		if value.Error != "" {
			errOffset = p.builder.CreateString(value.Error)
		}
		if value.CertLastError != "" {
			certErrOffset = p.builder.CreateString(value.CertLastError)
		}
		message.DomainStatusInfoStart(p.builder)
		message.DomainStatusInfoAddDnsStatus(p.builder, value.DNSStatus)
		message.DomainStatusInfoAddCertStatus(p.builder, value.CertStatus)
		if errOffset != 0 {
			message.DomainStatusInfoAddError(p.builder, errOffset)
		}
		if certErrOffset != 0 {
			message.DomainStatusInfoAddCertLastError(p.builder, certErrOffset)
		}
		if value.UpdatedAt > 0 {
			message.DomainStatusInfoAddUpdatedAt(p.builder, value.UpdatedAt)
		}
		return message.DomainStatusInfoEnd(p.builder)
	}

	customStatusOffset := buildDomainStatusOffset(status.CustomDNSStatus)

	var domainRuntimeOffset flatbuffers.UOffsetT
	{
		var requiredRecordsVec flatbuffers.UOffsetT
		if len(status.DomainRuntime.RequiredRecords) > 0 {
			recordOffsets := make([]flatbuffers.UOffsetT, 0, len(status.DomainRuntime.RequiredRecords))
			for _, rec := range status.DomainRuntime.RequiredRecords {
				recordNameOffset := p.builder.CreateString(rec.RecordName)
				recordValueOffset := p.builder.CreateString(rec.RecordValue)
				sourceOffset := p.builder.CreateString(rec.Source)

				message.DomainRecordInfoStart(p.builder)
				message.DomainRecordInfoAddRecordType(p.builder, message.DomainRecordType(rec.RecordType))
				message.DomainRecordInfoAddRecordName(p.builder, recordNameOffset)
				message.DomainRecordInfoAddRecordValue(p.builder, recordValueOffset)
				message.DomainRecordInfoAddTtl(p.builder, rec.TTL)
				if sourceOffset != 0 {
					message.DomainRecordInfoAddSource(p.builder, sourceOffset)
				}
				recordOffsets = append(recordOffsets, message.DomainRecordInfoEnd(p.builder))
			}

			message.DomainRuntimeInfoStartRequiredRecordsVector(p.builder, len(recordOffsets))
			for i := len(recordOffsets) - 1; i >= 0; i-- {
				p.builder.PrependUOffsetT(recordOffsets[i])
			}
			requiredRecordsVec = p.builder.EndVector(len(recordOffsets))
		}

		pendingReasonCodeOffset := p.builder.CreateString(status.DomainRuntime.PendingReasonCode)
		lastErrorOffset := p.builder.CreateString(status.DomainRuntime.LastError)
		message.DomainRuntimeInfoStart(p.builder)
		message.DomainRuntimeInfoAddOwnerView(p.builder, status.DomainRuntime.OwnerView)
		message.DomainRuntimeInfoAddState(p.builder, message.DomainRuntimeState(status.DomainRuntime.State))
		if requiredRecordsVec != 0 {
			message.DomainRuntimeInfoAddRequiredRecords(p.builder, requiredRecordsVec)
		}
		if pendingReasonCodeOffset != 0 {
			message.DomainRuntimeInfoAddPendingReasonCode(p.builder, pendingReasonCodeOffset)
		}
		if lastErrorOffset != 0 {
			message.DomainRuntimeInfoAddLastError(p.builder, lastErrorOffset)
		}
		message.DomainRuntimeInfoAddCnameStatus(p.builder, status.DomainRuntime.CnameStatus)
		message.DomainRuntimeInfoAddCertStatus(p.builder, status.DomainRuntime.CertStatus)
		if status.DomainRuntime.UpdatedAt > 0 {
			message.DomainRuntimeInfoAddUpdatedAt(p.builder, status.DomainRuntime.UpdatedAt)
		}
		domainRuntimeOffset = message.DomainRuntimeInfoEnd(p.builder)
	}

	var channelsVec flatbuffers.UOffsetT
	if len(status.Channels) > 0 {
		channelOffsets := make([]flatbuffers.UOffsetT, 0, len(status.Channels))
		for _, ch := range status.Channels {
			idOffset := p.builder.CreateString(ch.ID)
			sessionIDOffset := p.builder.CreateString(ch.SessionID)
			userIDOffset := p.builder.CreateString(ch.UserID)
			deviceIDOffset := p.builder.CreateString(ch.DeviceID)
			actorSessionIDOffset := p.builder.CreateString(ch.ActorSessionID)
			actorDeviceIDOffset := p.builder.CreateString(ch.ActorDeviceID)
			domainOffset := p.builder.CreateString(ch.Domain)
			subdomainOffset := p.builder.CreateString(ch.Subdomain)
			aliasDomainOffset := p.builder.CreateString(ch.AliasDomain)
			channelKeyOffset := p.builder.CreateString(ch.ChannelKey)
			protocolOffset := p.builder.CreateString(ch.Protocol)
			linkTypeOffset := p.builder.CreateString(ch.LinkType)
			remoteEndpointOffset := p.builder.CreateString(ch.RemoteEndpoint)
			localAddrOffset := p.builder.CreateString(ch.LocalAddr)
			stateOffset := p.builder.CreateString(ch.State)

			domainStatusOffset := buildDomainStatusOffset(ch.DomainStatus)
			aliasDomainStatusOffset := buildDomainStatusOffset(ch.AliasDomainStatus)

			message.ChannelInfoStart(p.builder)
			message.ChannelInfoAddId(p.builder, idOffset)
			message.ChannelInfoAddSessionId(p.builder, sessionIDOffset)
			message.ChannelInfoAddUserId(p.builder, userIDOffset)
			message.ChannelInfoAddDeviceId(p.builder, deviceIDOffset)
			message.ChannelInfoAddActorRole(p.builder, message.TunnelActorRole(ch.ActorRole))
			message.ChannelInfoAddActorSessionId(p.builder, actorSessionIDOffset)
			message.ChannelInfoAddActorDeviceId(p.builder, actorDeviceIDOffset)
			message.ChannelInfoAddDomain(p.builder, domainOffset)
			message.ChannelInfoAddSubdomain(p.builder, subdomainOffset)
			message.ChannelInfoAddAliasDomain(p.builder, aliasDomainOffset)
			if domainStatusOffset != 0 {
				message.ChannelInfoAddDomainStatus(p.builder, domainStatusOffset)
			}
			if aliasDomainStatusOffset != 0 {
				message.ChannelInfoAddAliasDomainStatus(p.builder, aliasDomainStatusOffset)
			}
			message.ChannelInfoAddChannelKey(p.builder, channelKeyOffset)
			message.ChannelInfoAddProtocol(p.builder, protocolOffset)
			message.ChannelInfoAddLinkType(p.builder, linkTypeOffset)
			message.ChannelInfoAddRemoteEndpoint(p.builder, remoteEndpointOffset)
			message.ChannelInfoAddLocalAddr(p.builder, localAddrOffset)
			message.ChannelInfoAddState(p.builder, stateOffset)
			message.ChannelInfoAddBytesIn(p.builder, ch.BytesIn)
			message.ChannelInfoAddBytesOut(p.builder, ch.BytesOut)
			message.ChannelInfoAddActiveConns(p.builder, ch.ActiveConns)
			message.ChannelInfoAddCreatedAt(p.builder, ch.CreatedAt)
			channelOffsets = append(channelOffsets, message.ChannelInfoEnd(p.builder))
		}

		message.TunnelStatusResponseStartChannelsVector(p.builder, len(channelOffsets))
		for i := len(channelOffsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(channelOffsets[i])
		}
		channelsVec = p.builder.EndVector(len(channelOffsets))
	}

	message.TunnelStatusResponseStart(p.builder)
	message.TunnelStatusResponseAddSuccess(p.builder, status.Success)
	message.TunnelStatusResponseAddTunnelId(p.builder, tunnelIDOffset)
	message.TunnelStatusResponseAddEdgeId(p.builder, edgeIDOffset)
	message.TunnelStatusResponseAddOnline(p.builder, status.Online)
	message.TunnelStatusResponseAddUptime(p.builder, status.Uptime)
	message.TunnelStatusResponseAddTimestamp(p.builder, status.Timestamp)
	message.TunnelStatusResponseAddTotalBytesIn(p.builder, status.TotalBytesIn)
	message.TunnelStatusResponseAddTotalBytesOut(p.builder, status.TotalBytesOut)
	if channelsVec != 0 {
		message.TunnelStatusResponseAddChannels(p.builder, channelsVec)
	}
	if dns01Vec != 0 {
		message.TunnelStatusResponseAddDns01Challenges(p.builder, dns01Vec)
	}
	message.TunnelStatusResponseAddCnameStatus(p.builder, status.CnameStatus)
	if customStatusOffset != 0 {
		message.TunnelStatusResponseAddCustomDomainStatus(p.builder, customStatusOffset)
	}
	if domainRuntimeOffset != 0 {
		message.TunnelStatusResponseAddDomainRuntime(p.builder, domainRuntimeOffset)
	}
	message.TunnelStatusResponseAddErrorCode(p.builder, status.ErrorCode)
	message.TunnelStatusResponseAddErrorMessage(p.builder, errorMessageOffset)
	resp := message.TunnelStatusResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_STATUS_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, status.Timestamp)
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelStatusResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	data := p.builder.FinishedBytes()
	return p.writeMessageUnlocked(conn, data)
}

func (p *Protocol) SendTunnelSyncResponse(
	conn net.Conn,
	success bool,
	fullSnapshot bool,
	nextRevision uint64,
	hasMore bool,
	definitions []*message.TunnelDefinitionInfoT,
	errorCode uint32,
	errorMessage string,
	sessionID string,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	defOffsets := make([]flatbuffers.UOffsetT, 0, len(definitions))
	for _, def := range definitions {
		offset := buildTunnelDefinitionInfo(p.builder, def)
		if offset != 0 {
			defOffsets = append(defOffsets, offset)
		}
	}

	var defsVec flatbuffers.UOffsetT
	if len(defOffsets) > 0 {
		message.TunnelSyncResponseStartDefinitionsVector(p.builder, len(defOffsets))
		for i := len(defOffsets) - 1; i >= 0; i-- {
			p.builder.PrependUOffsetT(defOffsets[i])
		}
		defsVec = p.builder.EndVector(len(defOffsets))
	}

	errOffset := p.builder.CreateString(errorMessage)

	message.TunnelSyncResponseStart(p.builder)
	message.TunnelSyncResponseAddSuccess(p.builder, success)
	message.TunnelSyncResponseAddFullSnapshot(p.builder, fullSnapshot)
	message.TunnelSyncResponseAddNextRevision(p.builder, nextRevision)
	message.TunnelSyncResponseAddHasMore(p.builder, hasMore)
	if defsVec != 0 {
		message.TunnelSyncResponseAddDefinitions(p.builder, defsVec)
	}
	message.TunnelSyncResponseAddErrorCode(p.builder, errorCode)
	message.TunnelSyncResponseAddErrorMessage(p.builder, errOffset)
	resp := message.TunnelSyncResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_SYNC_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelSyncResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelUpsertResponse(
	conn net.Conn,
	success bool,
	conflict bool,
	nextRevision uint64,
	definition *message.TunnelDefinitionInfoT,
	errorCode uint32,
	errorMessage string,
	sessionID string,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	defOffset := buildTunnelDefinitionInfo(p.builder, definition)
	errOffset := p.builder.CreateString(errorMessage)

	message.TunnelUpsertResponseStart(p.builder)
	message.TunnelUpsertResponseAddSuccess(p.builder, success)
	message.TunnelUpsertResponseAddConflict(p.builder, conflict)
	message.TunnelUpsertResponseAddNextRevision(p.builder, nextRevision)
	if defOffset != 0 {
		message.TunnelUpsertResponseAddDefinition(p.builder, defOffset)
	}
	message.TunnelUpsertResponseAddErrorCode(p.builder, errorCode)
	message.TunnelUpsertResponseAddErrorMessage(p.builder, errOffset)
	resp := message.TunnelUpsertResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_UPSERT_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelUpsertResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelDeleteResponse(
	conn net.Conn,
	success bool,
	conflict bool,
	tunnelID string,
	nextRevision uint64,
	errorCode uint32,
	errorMessage string,
	sessionID string,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	tunnelIDOffset := p.builder.CreateString(tunnelID)
	errOffset := p.builder.CreateString(errorMessage)

	message.TunnelDeleteResponseStart(p.builder)
	message.TunnelDeleteResponseAddSuccess(p.builder, success)
	message.TunnelDeleteResponseAddConflict(p.builder, conflict)
	message.TunnelDeleteResponseAddTunnelId(p.builder, tunnelIDOffset)
	message.TunnelDeleteResponseAddNextRevision(p.builder, nextRevision)
	message.TunnelDeleteResponseAddErrorCode(p.builder, errorCode)
	message.TunnelDeleteResponseAddErrorMessage(p.builder, errOffset)
	resp := message.TunnelDeleteResponseEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_DELETE_RESPONSE)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelDeleteResponse)
	message.MessageAddBody(p.builder, resp)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func (p *Protocol) SendTunnelEventPush(
	conn net.Conn,
	action message.TunnelEventAction,
	nextRevision uint64,
	definition *message.TunnelDefinitionInfoT,
	sessionID string,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.builder.Reset()

	defOffset := buildTunnelDefinitionInfo(p.builder, definition)

	message.TunnelEventPushStart(p.builder)
	message.TunnelEventPushAddAction(p.builder, action)
	message.TunnelEventPushAddNextRevision(p.builder, nextRevision)
	if defOffset != 0 {
		message.TunnelEventPushAddDefinition(p.builder, defOffset)
	}
	push := message.TunnelEventPushEnd(p.builder)

	sessIDOffset := p.builder.CreateString(sessionID)
	message.MessageHeaderStart(p.builder)
	message.MessageHeaderAddType(p.builder, message.MessageTypeTUNNEL_EVENT_PUSH)
	message.MessageHeaderAddSeq(p.builder, 0)
	message.MessageHeaderAddTimestamp(p.builder, uint64(now()))
	message.MessageHeaderAddSessionId(p.builder, sessIDOffset)
	header := message.MessageHeaderEnd(p.builder)

	message.MessageStart(p.builder)
	message.MessageAddHeader(p.builder, header)
	message.MessageAddBodyType(p.builder, message.MessageBodyTunnelEventPush)
	message.MessageAddBody(p.builder, push)
	msg := message.MessageEnd(p.builder)

	p.builder.Finish(msg)
	return p.writeMessageUnlocked(conn, p.builder.FinishedBytes())
}

func buildTunnelDefinitionInfo(builder *flatbuffers.Builder, definition *message.TunnelDefinitionInfoT) flatbuffers.UOffsetT {
	if definition == nil {
		return 0
	}

	tunnelIDOffset := maybeCreateString(builder, definition.TunnelId)
	edgeIDOffset := maybeCreateString(builder, definition.EdgeId)
	ownerIDOffset := maybeCreateString(builder, definition.OwnerUserId)
	nameOffset := maybeCreateString(builder, definition.Name)
	appIDOffset := maybeCreateString(builder, definition.AppId)
	protocolOffset := maybeCreateString(builder, definition.Protocol)
	intentOffset := maybeCreateString(builder, definition.IntentJson)
	configOffset := maybeCreateString(builder, definition.ConfigJson)
	runtimeOffset := maybeCreateString(builder, definition.RuntimeJson)
	stateOffset := maybeCreateString(builder, definition.State)
	actorSessionIDOffset := maybeCreateString(builder, definition.ActorSessionId)
	actorDeviceIDOffset := maybeCreateString(builder, definition.ActorDeviceId)

	message.TunnelDefinitionInfoStart(builder)
	if tunnelIDOffset != 0 {
		message.TunnelDefinitionInfoAddTunnelId(builder, tunnelIDOffset)
	}
	if edgeIDOffset != 0 {
		message.TunnelDefinitionInfoAddEdgeId(builder, edgeIDOffset)
	}
	if ownerIDOffset != 0 {
		message.TunnelDefinitionInfoAddOwnerUserId(builder, ownerIDOffset)
	}
	if nameOffset != 0 {
		message.TunnelDefinitionInfoAddName(builder, nameOffset)
	}
	if appIDOffset != 0 {
		message.TunnelDefinitionInfoAddAppId(builder, appIDOffset)
	}
	if protocolOffset != 0 {
		message.TunnelDefinitionInfoAddProtocol(builder, protocolOffset)
	}
	if intentOffset != 0 {
		message.TunnelDefinitionInfoAddIntentJson(builder, intentOffset)
	}
	if configOffset != 0 {
		message.TunnelDefinitionInfoAddConfigJson(builder, configOffset)
	}
	if runtimeOffset != 0 {
		message.TunnelDefinitionInfoAddRuntimeJson(builder, runtimeOffset)
	}
	if stateOffset != 0 {
		message.TunnelDefinitionInfoAddState(builder, stateOffset)
	}
	message.TunnelDefinitionInfoAddActorRole(builder, definition.ActorRole)
	if actorSessionIDOffset != 0 {
		message.TunnelDefinitionInfoAddActorSessionId(builder, actorSessionIDOffset)
	}
	if actorDeviceIDOffset != 0 {
		message.TunnelDefinitionInfoAddActorDeviceId(builder, actorDeviceIDOffset)
	}
	message.TunnelDefinitionInfoAddVersion(builder, definition.Version)
	message.TunnelDefinitionInfoAddRevision(builder, definition.Revision)
	message.TunnelDefinitionInfoAddDeleted(builder, definition.Deleted)
	message.TunnelDefinitionInfoAddCreatedAt(builder, definition.CreatedAt)
	message.TunnelDefinitionInfoAddUpdatedAt(builder, definition.UpdatedAt)
	return message.TunnelDefinitionInfoEnd(builder)
}

func buildTunnelOperationSummaryOffset(builder *flatbuffers.Builder, summary *message.TunnelOperationSummaryT) flatbuffers.UOffsetT {
	if summary == nil {
		return 0
	}
	message.TunnelOperationSummaryStart(builder)
	message.TunnelOperationSummaryAddRequested(builder, summary.Requested)
	message.TunnelOperationSummaryAddSucceeded(builder, summary.Succeeded)
	message.TunnelOperationSummaryAddFailed(builder, summary.Failed)
	return message.TunnelOperationSummaryEnd(builder)
}

func buildTunnelRuntimeSnapshotOffset(builder *flatbuffers.Builder, snapshot *message.TunnelRuntimeSnapshotT) flatbuffers.UOffsetT {
	if snapshot == nil {
		return 0
	}
	tunnelIDOffset := maybeCreateString(builder, snapshot.TunnelId)
	stateOffset := maybeCreateString(builder, snapshot.State)
	runtimeJSONOffset := maybeCreateString(builder, snapshot.RuntimeJson)

	message.TunnelRuntimeSnapshotStart(builder)
	if tunnelIDOffset != 0 {
		message.TunnelRuntimeSnapshotAddTunnelId(builder, tunnelIDOffset)
	}
	if stateOffset != 0 {
		message.TunnelRuntimeSnapshotAddState(builder, stateOffset)
	}
	if runtimeJSONOffset != 0 {
		message.TunnelRuntimeSnapshotAddRuntimeJson(builder, runtimeJSONOffset)
	}
	message.TunnelRuntimeSnapshotAddUpdatedAt(builder, snapshot.UpdatedAt)
	return message.TunnelRuntimeSnapshotEnd(builder)
}

func buildTunnelStartResultVectorOffset(builder *flatbuffers.Builder, results []*message.TunnelChannelStartResultT) flatbuffers.UOffsetT {
	if len(results) == 0 {
		return 0
	}
	offsets := make([]flatbuffers.UOffsetT, 0, len(results))
	for _, item := range results {
		if item == nil {
			continue
		}
		keyOffset := maybeCreateString(builder, item.Key)
		channelIDOffset := maybeCreateString(builder, item.ChannelId)
		errorMessageOffset := maybeCreateString(builder, item.ErrorMessage)
		remoteEndpointOffset := maybeCreateString(builder, item.RemoteEndpoint)
		aliasDomainOffset := maybeCreateString(builder, item.AliasDomain)
		customDomainOffset := maybeCreateString(builder, item.CustomDomain)
		assignedDomainOffset := maybeCreateString(builder, item.AssignedDomain)

		message.TunnelChannelStartResultStart(builder)
		if keyOffset != 0 {
			message.TunnelChannelStartResultAddKey(builder, keyOffset)
		}
		if channelIDOffset != 0 {
			message.TunnelChannelStartResultAddChannelId(builder, channelIDOffset)
		}
		message.TunnelChannelStartResultAddSuccess(builder, item.Success)
		message.TunnelChannelStartResultAddErrorCode(builder, item.ErrorCode)
		if errorMessageOffset != 0 {
			message.TunnelChannelStartResultAddErrorMessage(builder, errorMessageOffset)
		}
		if remoteEndpointOffset != 0 {
			message.TunnelChannelStartResultAddRemoteEndpoint(builder, remoteEndpointOffset)
		}
		if aliasDomainOffset != 0 {
			message.TunnelChannelStartResultAddAliasDomain(builder, aliasDomainOffset)
		}
		if customDomainOffset != 0 {
			message.TunnelChannelStartResultAddCustomDomain(builder, customDomainOffset)
		}
		if assignedDomainOffset != 0 {
			message.TunnelChannelStartResultAddAssignedDomain(builder, assignedDomainOffset)
		}
		message.TunnelChannelStartResultAddNegotiatedBufferSize(builder, item.NegotiatedBufferSize)
		offsets = append(offsets, message.TunnelChannelStartResultEnd(builder))
	}

	if len(offsets) == 0 {
		return 0
	}
	message.TunnelStartResponseStartChannelsVector(builder, len(offsets))
	for i := len(offsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(offsets[i])
	}
	return builder.EndVector(len(offsets))
}

func buildTunnelStopResultVectorOffset(builder *flatbuffers.Builder, results []*message.TunnelChannelStopResultT) flatbuffers.UOffsetT {
	if len(results) == 0 {
		return 0
	}
	offsets := make([]flatbuffers.UOffsetT, 0, len(results))
	for _, item := range results {
		if item == nil {
			continue
		}
		keyOffset := maybeCreateString(builder, item.Key)
		channelIDOffset := maybeCreateString(builder, item.ChannelId)
		errorMessageOffset := maybeCreateString(builder, item.ErrorMessage)

		message.TunnelChannelStopResultStart(builder)
		if keyOffset != 0 {
			message.TunnelChannelStopResultAddKey(builder, keyOffset)
		}
		if channelIDOffset != 0 {
			message.TunnelChannelStopResultAddChannelId(builder, channelIDOffset)
		}
		message.TunnelChannelStopResultAddSuccess(builder, item.Success)
		message.TunnelChannelStopResultAddErrorCode(builder, item.ErrorCode)
		if errorMessageOffset != 0 {
			message.TunnelChannelStopResultAddErrorMessage(builder, errorMessageOffset)
		}
		offsets = append(offsets, message.TunnelChannelStopResultEnd(builder))
	}

	if len(offsets) == 0 {
		return 0
	}
	message.TunnelStopResponseStartChannelsVector(builder, len(offsets))
	for i := len(offsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(offsets[i])
	}
	return builder.EndVector(len(offsets))
}

func maybeCreateString(builder *flatbuffers.Builder, value string) flatbuffers.UOffsetT {
	if value == "" {
		return 0
	}
	return builder.CreateString(value)
}

// Get
func now() int64 {
	return time.Now().UnixMilli()
}
