package handler

import (
	"strings"
	"sync"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	logger "icool.io/yat/edge/pkg/log"
)

// LogSubscriptionManager manages log subscriptions for sessions
type LogSubscriptionManager struct {
	mu            sync.Mutex
	subscriptions map[string]chan struct{} // sessionID -> quit chan
}

var logManager = &LogSubscriptionManager{
	subscriptions: make(map[string]chan struct{}),
}

func (m *LogSubscriptionManager) replace(sessionID string, next chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.subscriptions[sessionID]; ok {
		close(old)
	}
	m.subscriptions[sessionID] = next
}

func (m *LogSubscriptionManager) remove(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.subscriptions[sessionID]; ok {
		close(old)
		delete(m.subscriptions, sessionID)
	}
}

func hasCapability(capabilities []string, target string) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		return false
	}
	for _, item := range capabilities {
		if strings.TrimSpace(strings.ToLower(item)) == target {
			return true
		}
	}
	return false
}

// HandleEdgeLogRequest handles log subscription requests
func HandleEdgeLogRequest(ctx *Context, msg *fbMsg.Message) error {
	req := new(fbMsg.EdgeLogRequest)
	table := new(flatbuffers.Table)
	msg.Body(table)
	req.Init(table.Bytes, table.Pos)

	logger.Infof("log request, session: %s, subscribe: %v", ctx.SessionID, req.Subscribe())

	// Check permission (Owner only)
	if ctx.OwnerVerifier == nil {
		logger.Warnf("owner verifier unavailable, deny log request, session: %s", ctx.SessionID)
		return sendLogResponse(ctx, false, "permission denied")
	}
	if !ctx.OwnerVerifier.IsEdgeOwner(ctx.UserID) {
		logger.Warnf("non-owner user %s tried to access logs", ctx.UserID)
		return sendLogResponse(ctx, false, "permission denied: not edge owner")
	}
	if !hasCapability(ctx.Capabilities, "logs") {
		logger.Warnf("user %s without logs capability tried to access logs", ctx.UserID)
		return sendLogResponse(ctx, false, "permission denied: logs capability required")
	}

	if req.Subscribe() {
		// Start new subscription
		quit := make(chan struct{})
		logManager.replace(ctx.SessionID, quit)
		go streamLogs(ctx, quit, req.TailLines())
	} else {
		// Unsubscribe
		logManager.remove(ctx.SessionID)
	}

	return sendLogResponse(ctx, true, "")
}

func sendLogResponse(ctx *Context, success bool, errMsg string) error {
	builder := flatbuffers.NewBuilder(256)
	errOffset := builder.CreateString(errMsg)

	fbMsg.EdgeLogResponseStart(builder)
	fbMsg.EdgeLogResponseAddSuccess(builder, success)
	fbMsg.EdgeLogResponseAddErrorMessage(builder, errOffset)
	resp := fbMsg.EdgeLogResponseEnd(builder)

	sessIDOffset := builder.CreateString(ctx.SessionID)
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeEDGE_LOG_RESPONSE)
	fbMsg.MessageHeaderAddSessionId(builder, sessIDOffset)
	header := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, header)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyEdgeLogResponse)
	fbMsg.MessageAddBody(builder, resp)
	msg := fbMsg.MessageEnd(builder)

	builder.Finish(msg)
	return ctx.Protocol.WriteMessage(ctx.Conn, builder.FinishedBytes())
}

func streamLogs(ctx *Context, quit chan struct{}, tailLines int32) {
	broadcaster := logger.GetBroadcaster()
	logChan, history := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(logChan)

	// Send history if requested
	if tailLines > 0 {
		startIdx := 0
		if len(history) > int(tailLines) {
			startIdx = len(history) - int(tailLines)
		}

		// Send in batches to avoid huge packets, but for simplicity sending line by line is safer for now
		// Or we can bundle them. Let's send line by line to keep latency low and packet size small
		for i := startIdx; i < len(history); i++ {
			if err := sendLogPush(ctx, []string{history[i]}); err != nil {
				logger.Errorf("failed to send history log: %v", err)
				return
			}
		}
	}

	// Stream new logs
	// Buffer a few logs to reduce packet overhead?
	// For low latency debugging, line-by-line is better.

	for {
		select {
		case line, ok := <-logChan:
			if !ok {
				return
			}
			if err := sendLogPush(ctx, []string{line}); err != nil {
				logger.Errorf("failed to send log push: %v", err)
				return
			}
		case <-quit:
			return
		}
	}
}

func sendLogPush(ctx *Context, lines []string) error {
	builder := flatbuffers.NewBuilder(1024)

	// Create string vector
	lineOffsets := make([]flatbuffers.UOffsetT, len(lines))
	for i, line := range lines {
		lineOffsets[i] = builder.CreateString(line)
	}

	fbMsg.EdgeLogPushStartLogLinesVector(builder, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(lineOffsets[i])
	}
	linesVector := builder.EndVector(len(lines))

	fbMsg.EdgeLogPushStart(builder)
	fbMsg.EdgeLogPushAddLogLines(builder, linesVector)
	push := fbMsg.EdgeLogPushEnd(builder)

	sessIDOffset := builder.CreateString(ctx.SessionID)
	fbMsg.MessageHeaderStart(builder)
	fbMsg.MessageHeaderAddType(builder, fbMsg.MessageTypeEDGE_LOG_PUSH)
	fbMsg.MessageHeaderAddSessionId(builder, sessIDOffset)
	fbMsg.MessageHeaderAddTimestamp(builder, uint64(time.Now().UnixMilli()))
	header := fbMsg.MessageHeaderEnd(builder)

	fbMsg.MessageStart(builder)
	fbMsg.MessageAddHeader(builder, header)
	fbMsg.MessageAddBodyType(builder, fbMsg.MessageBodyEdgeLogPush)
	fbMsg.MessageAddBody(builder, push)
	msg := fbMsg.MessageEnd(builder)

	builder.Finish(msg)
	return ctx.Protocol.WriteMessage(ctx.Conn, builder.FinishedBytes())
}
