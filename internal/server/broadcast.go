package server

import (
	"container/ring"
	"sync"
	"sync/atomic"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/server/handler"
	logger "icool.io/yat/edge/pkg/log"
)

// ---------------------------------------------------------------------------
// Broadcast entry — a tagged union stored in the ring buffer.
// ---------------------------------------------------------------------------

// broadcastKind discriminates the payload stored in a broadcastEntry.
type broadcastKind int

const (
	kindEdgeStatus  broadcastKind = iota // Edge status push
	kindTunnelEvent                      // Tunnel event push
	kindRawBytes                         // Pre-serialized bytes to targeted clients
)

// broadcastEntry is a single immutable slot in the ring buffer.
// Exactly one payload field is non-nil depending on Kind.
type broadcastEntry struct {
	kind broadcastKind

	// kindEdgeStatus — snapshot fallback or a projector invoked for each
	// authenticated subscriber, including replayed entries.
	edgeStatus        *handler.EdgeStatusInfo
	projectEdgeStatus func(*Session) *handler.EdgeStatusInfo

	// kindTunnelEvent
	tunnelAction      fbMsg.TunnelEventAction
	tunnelRevision    uint64
	tunnelDefinition  *fbMsg.TunnelDefinitionInfoT
	tunnelOwnerUserID string // only sessions of this user receive the event

	// kindRawBytes — pre-serialized flatbuffers message with a target set.
	// Only sessions whose DeviceID appears in rawTargetClients receive it.
	// If rawTargetClients is nil/empty, ALL subscribers receive it.
	rawData          []byte
	rawTargetClients map[string]struct{}

	// excludeSessionID — if non-empty, the subscriber with this session ID
	// will NOT receive the entry (used for tunnel event echo suppression).
	excludeSessionID string
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

// subscriber represents one session's async delivery endpoint.
type subscriber struct {
	ch      chan *broadcastEntry
	filter  func(*broadcastEntry) bool // nil → receive all
	invalid chan struct{}
}

// ---------------------------------------------------------------------------
// PushBroadcaster
// ---------------------------------------------------------------------------

// PushBroadcaster is a ring-buffer-based async broadcast hub.
//
// Messages are written once into a fixed-size ring buffer and simultaneously
// fanned out to every matching subscriber's buffered channel via a
// non-blocking send.  Slow consumers cannot block the broadcaster — if a
// subscriber's channel is full its stream is explicitly invalidated and the
// physical session closes, forcing a new authenticated baseline.
//
// New subscribers receive recent history from the ring buffer so they can
// catch up on messages they missed before connecting.
type PushBroadcaster struct {
	mu     sync.RWMutex
	buf    *ring.Ring // ring buffer of broadcastEntry
	subs   map[string]*subscriber
	closed bool

	cap int // current ring capacity

	drops atomic.Int64
}

// NewPushBroadcaster creates a broadcaster with the given ring buffer size.
func NewPushBroadcaster(bufferSize int) *PushBroadcaster {
	if bufferSize <= 0 {
		bufferSize = defaultBroadcastBufferSize
	}
	return &PushBroadcaster{
		buf:  ring.New(bufferSize),
		subs: make(map[string]*subscriber),
		cap:  bufferSize,
	}
}

const (
	defaultBroadcastBufferSize = 64
	minBroadcastBufferSize     = 8
	maxBroadcastBufferSize     = 1024
	defaultSubscriberChanSize  = 32
)

// SetBufferSize dynamically adjusts the ring buffer capacity.  The most
// recent min(old_count, new_cap) entries are preserved.  Safe to call at
// runtime.
func (b *PushBroadcaster) SetBufferSize(size int) {
	if size < minBroadcastBufferSize {
		size = minBroadcastBufferSize
	}
	if size > maxBroadcastBufferSize {
		size = maxBroadcastBufferSize
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if size == b.cap {
		return
	}

	// Drain existing entries.
	var entries []broadcastEntry
	b.buf.Do(func(v interface{}) {
		if v != nil {
			entries = append(entries, v.(broadcastEntry))
		}
	})
	// Keep only the last 'size' entries.
	if len(entries) > size {
		entries = entries[len(entries)-size:]
	}

	newRing := ring.New(size)
	for _, e := range entries {
		newRing.Value = e
		newRing = newRing.Next()
	}
	b.buf = newRing
	b.cap = size
	logger.Infof("[PushBroadcaster] buffer size adjusted to %d", size)
}

// BufferSize returns the current ring buffer capacity.
func (b *PushBroadcaster) BufferSize() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cap
}

// Subscribe registers a session as a broadcast subscriber.
//
// chSize controls the buffered channel size (0 → default).
// filter is optional — pass nil to receive all broadcasts.
//
// Returns the read channel and a slice of recent history (oldest first).
func (b *PushBroadcaster) Subscribe(sessionID string, chSize int, filter func(*broadcastEntry) bool) (<-chan *broadcastEntry, []broadcastEntry) {
	if chSize <= 0 {
		chSize = defaultSubscriberChanSize
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Replace previous subscription if any.
	if old, ok := b.subs[sessionID]; ok {
		close(old.ch)
	}

	ch := make(chan *broadcastEntry, chSize)
	b.subs[sessionID] = &subscriber{ch: ch, filter: filter, invalid: make(chan struct{})}

	// Collect history.
	var history []broadcastEntry
	b.buf.Do(func(v interface{}) {
		if v == nil {
			return
		}
		entry := v.(broadcastEntry)
		if filter == nil || filter(&entry) {
			history = append(history, entry)
		}
	})
	return ch, history
}

// Invalidated is independent of the data queue and closes on overflow.
func (b *PushBroadcaster) Invalidated(sessionID string) <-chan struct{} {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if sub, ok := b.subs[sessionID]; ok {
		return sub.invalid
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

func (s *Session) acceptsBroadcast(entry *broadcastEntry) bool {
	if entry.excludeSessionID == s.ID {
		return false
	}
	if entry.kind == kindTunnelEvent && entry.tunnelOwnerUserID != "" && entry.tunnelOwnerUserID != s.UserID {
		return false
	}
	if entry.kind == kindRawBytes && len(entry.rawTargetClients) > 0 {
		_, ok := entry.rawTargetClients[s.DeviceID]
		return ok
	}
	return true
}

// Unsubscribe removes a session and closes its channel.
func (b *PushBroadcaster) Unsubscribe(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if sub, ok := b.subs[sessionID]; ok {
		close(sub.ch)
		delete(b.subs, sessionID)
	}
}

// Publish writes an entry into the ring buffer and fans it out to all
// matching subscribers.  Non-blocking — never waits on a slow consumer.
func (b *PushBroadcaster) Publish(entry broadcastEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	// Store in ring buffer.
	b.buf.Value = entry
	b.buf = b.buf.Next()

	// Fan out.
	for id, sub := range b.subs {
		// Skip excluded session (echo suppression).
		if entry.excludeSessionID != "" && id == entry.excludeSessionID {
			continue
		}
		if sub.filter != nil && !sub.filter(&entry) {
			continue
		}
		select {
		case sub.ch <- &entry:
		default:
			b.drops.Add(1)
			// Out-of-band invalidation cannot itself be blocked by the full queue.
			close(sub.invalid)
			close(sub.ch)
			delete(b.subs, id)
		}
	}
}

// Close shuts down the broadcaster, closing all subscriber channels.
func (b *PushBroadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for id, sub := range b.subs {
		close(sub.ch)
		delete(b.subs, id)
	}
}

// DropCount returns total messages dropped due to full channels.
func (b *PushBroadcaster) DropCount() int64 {
	return b.drops.Load()
}

// SubscriberCount returns the number of active subscribers.
func (b *PushBroadcaster) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// ---------------------------------------------------------------------------
// Per-session delivery loop
// ---------------------------------------------------------------------------

// runBroadcastDelivery reads from the broadcast channel and writes push
// messages to the session's connection.  It runs as a goroutine per session
// and exits when the channel is closed (unsubscribe or broadcaster close).
//
// This function should be called once per session after Subscribe.
func (s *Session) runBroadcastDelivery(ch <-chan *broadcastEntry, invalid <-chan struct{}) {
	for {
		select {
		case <-invalid:
			_ = s.Close()
			return
		default:
		}
		var entry *broadcastEntry
		select {
		case <-s.closeCh:
			return
		case <-invalid:
			_ = s.Close()
			return
		case value, ok := <-ch:
			if !ok {
				return
			}
			entry = value
		}
		if entry == nil {
			continue
		}
		switch entry.kind {
		case kindEdgeStatus:
			status := entry.edgeStatus
			if entry.projectEdgeStatus != nil {
				status = entry.projectEdgeStatus(s)
			}
			if status == nil || s.Protocol == nil || s.Conn == nil {
				continue
			}
			if err := s.Protocol.SendEdgeStatusPush(s.Conn, status, s.ID); err != nil {
				logger.Warnf("broadcast delivery: status push failed session=%s err=%v", s.ID, err)
				_ = s.Close()
				return
			}

		case kindTunnelEvent:
			if entry.tunnelDefinition == nil || s.Protocol == nil || s.Conn == nil {
				continue
			}
			// Only deliver to sessions belonging to the tunnel owner.
			if entry.tunnelOwnerUserID != "" && s.UserID != entry.tunnelOwnerUserID {
				continue
			}
			if err := s.Protocol.SendTunnelEventPush(s.Conn, entry.tunnelAction, entry.tunnelRevision, entry.tunnelDefinition, s.ID); err != nil {
				logger.Warnf("broadcast delivery: tunnel event push failed session=%s err=%v", s.ID, err)
				_ = s.Close()
				return
			}

		case kindRawBytes:
			if len(entry.rawData) == 0 || s.Conn == nil {
				continue
			}
			// Targeted delivery: skip if this session is not in the target set.
			if len(entry.rawTargetClients) > 0 {
				if _, ok := entry.rawTargetClients[s.DeviceID]; !ok {
					continue
				}
			}
			if s.Protocol != nil {
				if err := s.Protocol.WriteMessage(s.Conn, entry.rawData); err != nil {
					logger.Warnf("broadcast delivery: raw bytes write failed session=%s err=%v", s.ID, err)
					_ = s.Close()
					return
				}
			}
		}
	}
}
