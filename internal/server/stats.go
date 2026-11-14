package server

import (
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/internal/server/handler"
	logger "icool.io/yat/edge/pkg/log"
)

// Clean
func (s *Server) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			count := s.sessions.CleanExpired(s.config.Tunnel.SessionTimeout)
			if count > 0 {
				logger.Infof("cleaned expired sessions, count: %d", count)
			}

			// Connection accumulation warning: log when session count is high
			// to help diagnose connection storm / leak issues.
			sessionCount := s.sessions.Count()
			connCount := s.activeConnCount()
			if sessionCount > 50 || connCount > 100 {
				logger.Warnf(
					"[ConnMonitor] high connection count: sessions=%d activeConns=%d maxSessions=%d",
					sessionCount, connCount, s.config.Tunnel.MaxSessions,
				)
			} else if sessionCount > 0 || connCount > 0 {
				logger.Debugf(
					"[ConnMonitor] sessions=%d activeConns=%d",
					sessionCount, connCount,
				)
			}
		}
	}
}

// activeConnCount returns the number of active connections tracked by the server.
func (s *Server) activeConnCount() int {
	count := 0
	s.activeConns.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// MarkOnline resumes local channel services.
func (s *Server) MarkOnline() {
	if err := s.resumeChannelServices(); err != nil {
		logger.Warnf("resume channel services failed: %v", err)
		return
	}
	if s.channelMgr != nil {
		s.channelMgr.SetOnline(true)
	}
}

// MarkOffline suspends local services while keeping the control port available.
func (s *Server) MarkOffline() {
	if err := s.applyOfflineLocally(); err != nil {
		logger.Warnf("suspend channel services failed: %v", err)
	}
}

func (s *Server) applyOfflineLocally() error {
	// Update runtime status first so subsequent status pull reflects offline immediately.
	if s.channelMgr != nil {
		s.channelMgr.SetOnline(false)
	}

	// Close all user sessions/channels but keep tunnel control port alive.
	// Session removal triggers registry cleanup (CloseBySession), which releases channel ports.
	if s.sessions != nil {
		s.sessions.BroadcastError(fbMsg.ErrorCodeEDGE_OFFLINE, "edge is going offline")
		// Wait briefly for async session teardown to drain channel resources.
		time.Sleep(300 * time.Millisecond)
	}

	if err := s.suspendChannelServices(); err != nil {
		return err
	}

	return nil
}

func (s *Server) suspendChannelServices() error {
	s.mu.Lock()
	if s.channelSuspended {
		s.mu.Unlock()
		return nil
	}
	s.channelSuspended = true
	s.mu.Unlock()

	if s.channelMgr == nil {
		return nil
	}
	if err := s.channelMgr.Stop(); err != nil {
		s.mu.Lock()
		s.channelSuspended = false
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Server) resumeChannelServices() error {
	s.mu.Lock()
	needResume := s.channelSuspended
	s.mu.Unlock()
	if !needResume {
		return nil
	}

	if s.channelMgr == nil {
		return nil
	}
	if err := s.channelMgr.Start(); err != nil {
		return err
	}

	s.mu.Lock()
	s.channelSuspended = false
	s.mu.Unlock()
	return nil
}

// Broadcast edge status to all sessions via the async ring-buffer broadcaster.
// This method is non-blocking: it publishes a single entry into the ring buffer
// and each session's delivery goroutine handles the actual write independently.
func (s *Server) broadcastStatusToSessions(status *channel.EdgeServiceStatus) {
	// Skip status push during shutdown to avoid blocking on slow/closing connections.
	s.mu.Lock()
	shuttingDown := s.shuttingDown
	s.mu.Unlock()
	if shuttingDown {
		return
	}

	if status == nil {
		return
	}

	source := convertServiceStatus(status)
	timestamp := status.LastUpdated
	if timestamp <= 0 {
		timestamp = time.Now().UnixMilli()
	} else if timestamp < 1_000_000_000_000 {
		timestamp *= 1000
	}
	if s.broadcaster != nil {
		s.broadcaster.Publish(broadcastEntry{
			kind: kindEdgeStatus,
			projectEdgeStatus: func(session *Session) *handler.EdgeStatusInfo {
				ctx := s.buildHandlerContext(session)
				info := handler.BuildEdgeStatusInfo(ctx, source, ctx.OwnerVerifier.IsEdgeOwner(session.UserID))
				// Replayed ring entries retain their snapshot time so an old push
				// cannot overwrite a newer query merely because delivery was delayed.
				info.Timestamp = uint64(timestamp)
				return info
			},
		})
		logger.Debugf("broadcast status via ring buffer, subscribers: %d, online: %v", s.broadcaster.SubscriberCount(), status.Online)
	}
}
