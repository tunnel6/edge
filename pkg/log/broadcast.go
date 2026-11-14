package log

import (
	"container/ring"
	"sync"

	"github.com/sirupsen/logrus"
)

const defaultBufferSize = 100

type Broadcaster struct {
	mu          sync.RWMutex
	buffer      *ring.Ring
	subscribers map[chan string]struct{}
}

var _broadcaster *Broadcaster
var once sync.Once

func GetBroadcaster() *Broadcaster {
	once.Do(func() {
		_broadcaster = &Broadcaster{
			buffer:      ring.New(defaultBufferSize),
			subscribers: make(map[chan string]struct{}),
		}
	})
	return _broadcaster
}

func (b *Broadcaster) Write(p []byte) (n int, err error) {
	msg := string(p)
	
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Store in buffer
	b.buffer.Value = msg
	b.buffer = b.buffer.Next()

	// Broadcast to subscribers
	for ch := range b.subscribers {
		select {
		case ch <- msg:
		default:
			// Drop message if channel is full
		}
	}
	return len(p), nil
}

func (b *Broadcaster) Subscribe() (chan string, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan string, 100)
	b.subscribers[ch] = struct{}{}

	// Get history
	var history []string
	b.buffer.Do(func(p interface{}) {
		if p != nil {
			history = append(history, p.(string))
		}
	})

	return ch, history
}

func (b *Broadcaster) Unsubscribe(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Hook for Logrus
type BroadcastHook struct {
	broadcaster *Broadcaster
}

func NewBroadcastHook() *BroadcastHook {
	return &BroadcastHook{
		broadcaster: GetBroadcaster(),
	}
}

func (h *BroadcastHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *BroadcastHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = h.broadcaster.Write([]byte(line))
	return err
}
