package udpproxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	udpFlagFIN uint8 = 0x01
	udpFlagRST uint8 = 0x02

	udpReadDeadline      = 1 * time.Second
	udpWriteDeadline     = 5 * time.Second
	udpListenerReadBufSz = 64 * 1024
	udpSrcLogInterval    = 10 * time.Second
	udpSrcLogExpire      = 2 * time.Minute
)

type UDPProxy struct {
	tunnel    ct.TunnelSender
	listeners map[uint16]*udpListener
	mu        sync.RWMutex
}

type udpListener struct {
	target   *ct.Channel
	conn     *net.UDPConn
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	srcLogMu         sync.Mutex
	srcLastLogTime   map[string]time.Time
	replyLogMu       sync.Mutex
	replyLastLogTime map[string]time.Time
}

func New(tunnel ct.TunnelSender) *UDPProxy {
	return &UDPProxy{
		tunnel:    tunnel,
		listeners: make(map[uint16]*udpListener),
	}
}

func (p *UDPProxy) Type() fbMsg.ChannelType {
	return fbMsg.ChannelTypeUDP
}

func (p *UDPProxy) Start() error {
	return nil
}

func (p *UDPProxy) Stop() error {
	p.mu.Lock()
	listeners := make([]*udpListener, 0, len(p.listeners))
	for port, l := range p.listeners {
		listeners = append(listeners, l)
		delete(p.listeners, port)
	}
	p.mu.Unlock()

	for _, l := range listeners {
		p.stopListener(l)
	}
	return nil
}

func (p *UDPProxy) SetTunnel(tunnel ct.TunnelSender) {
	p.mu.Lock()
	p.tunnel = tunnel
	p.mu.Unlock()
}

func (p *UDPProxy) Upsert(target *ct.Channel, previous *ct.Channel) error {
	if p == nil || target == nil {
		return nil
	}
	if previous != nil && previous.Port > 0 && previous.Port != target.Port {
		_ = p.Close(previous.Port)
	}
	if target.Port == 0 {
		return nil
	}
	return p.Listen(target)
}

func (p *UDPProxy) Remove(target *ct.Channel) error {
	if p == nil || target == nil {
		return nil
	}
	if target.Port == 0 {
		return nil
	}
	return p.Close(target.Port)
}

func (p *UDPProxy) HandleData(target *ct.Channel, connectionID string, _ uint32, data []byte, flags uint8) error {
	if p == nil || target == nil {
		return nil
	}
	if flags&udpFlagFIN != 0 || flags&udpFlagRST != 0 {
		return nil
	}
	if len(data) == 0 {
		return nil
	}

	p.mu.RLock()
	l := p.listeners[target.Port]
	p.mu.RUnlock()
	if l == nil || l.conn == nil {
		return fmt.Errorf("udp listener not found on port %d", target.Port)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", connectionID)
	if err != nil {
		return fmt.Errorf("resolve udp connection id %q: %w", connectionID, err)
	}

	_ = l.conn.SetWriteDeadline(time.Now().Add(udpWriteDeadline))
	n, err := l.conn.WriteToUDP(data, remoteAddr)
	if err != nil {
		return fmt.Errorf("write udp data to %s: %w", remoteAddr.String(), err)
	}
	target.AddBytesOut(uint64(n))
	p.maybeLogUDPReply(l, remoteAddr.String(), n)
	return nil
}

func (p *UDPProxy) Listen(target *ct.Channel) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, exists := p.listeners[target.Port]; exists {
		if existing.target != nil && existing.target.ID == target.ID {
			existing.target = target
			logger.Infof("UDP proxy listener updated on port %d, target: %s", target.Port, target.ID)
			return nil
		}
		return fmt.Errorf("port %d already in use", target.Port)
	}

	addr := &net.UDPAddr{Port: int(target.Port)}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen on :%d: %w", target.Port, err)
	}

	l := &udpListener{
		target:           target,
		conn:             conn,
		stopCh:           make(chan struct{}),
		srcLastLogTime:   make(map[string]time.Time),
		replyLastLogTime: make(map[string]time.Time),
	}

	p.listeners[target.Port] = l

	l.wg.Add(1)
	go p.readLoop(l)

	logger.Infof("UDP proxy listening on port %d, target: %s", target.Port, target.ID)
	return nil
}

func (p *UDPProxy) Close(port uint16) error {
	p.mu.Lock()
	l, ok := p.listeners[port]
	if ok {
		delete(p.listeners, port)
	}
	p.mu.Unlock()

	if ok {
		p.stopListener(l)
	}
	return nil
}

func (p *UDPProxy) stopListener(l *udpListener) {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopCh)
		if l.conn != nil {
			_ = l.conn.Close()
		}
		l.wg.Wait()
		if l.target != nil {
			logger.Infof("UDP proxy stopped on port %d", l.target.Port)
		}
	})
}

func (p *UDPProxy) readLoop(l *udpListener) {
	defer l.wg.Done()

	buf := make([]byte, udpListenerReadBufSz)

	for {
		select {
		case <-l.stopCh:
			return
		default:
		}

		_ = l.conn.SetReadDeadline(time.Now().Add(udpReadDeadline))
		n, src, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-l.stopCh:
				return
			default:
				logger.Warnf("UDP read error on port %d: %v", l.target.Port, err)
				continue
			}
		}

		if n <= 0 || src == nil {
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])
		l.target.AddBytesIn(uint64(n))
		p.maybeLogUDPSrc(l, src.String(), n)

		if err := p.sendUDPData(l.target, payload, src.String()); err != nil {
			logger.Warnf("forward UDP data failed, channel=%s, src=%s, err=%v", l.target.ID, src.String(), err)
		}
	}
}

func (p *UDPProxy) maybeLogUDPSrc(l *udpListener, src string, bytes int) {
	if l == nil || l.target == nil || src == "" {
		return
	}

	now := time.Now()
	shouldLog := false

	l.srcLogMu.Lock()
	lastLogAt, exists := l.srcLastLogTime[src]
	if !exists || now.Sub(lastLogAt) >= udpSrcLogInterval {
		l.srcLastLogTime[src] = now
		shouldLog = true
	}

	if len(l.srcLastLogTime) > 1024 {
		expireBefore := now.Add(-udpSrcLogExpire)
		for addr, ts := range l.srcLastLogTime {
			if ts.Before(expireBefore) {
				delete(l.srcLastLogTime, addr)
			}
		}
	}
	l.srcLogMu.Unlock()

	if shouldLog {
		logger.Infof("forward UDP data, channel=%s, src=%s, bytes=%d", l.target.ID, src, bytes)
	}
}

func (p *UDPProxy) maybeLogUDPReply(l *udpListener, dst string, bytes int) {
	if l == nil || l.target == nil || dst == "" {
		return
	}

	now := time.Now()
	shouldLog := false

	l.replyLogMu.Lock()
	lastLogAt, exists := l.replyLastLogTime[dst]
	if !exists || now.Sub(lastLogAt) >= udpSrcLogInterval {
		l.replyLastLogTime[dst] = now
		shouldLog = true
	}

	if len(l.replyLastLogTime) > 1024 {
		expireBefore := now.Add(-udpSrcLogExpire)
		for addr, ts := range l.replyLastLogTime {
			if ts.Before(expireBefore) {
				delete(l.replyLastLogTime, addr)
			}
		}
	}
	l.replyLogMu.Unlock()

	if shouldLog {
		logger.Infof("forward UDP reply, channel=%s, dst=%s, bytes=%d", l.target.ID, dst, bytes)
	}
}

func (p *UDPProxy) sendUDPData(target *ct.Channel, data []byte, srcAddr string) error {
	if target == nil {
		return fmt.Errorf("udp channel target missing")
	}

	p.mu.RLock()
	tunnel := p.tunnel
	p.mu.RUnlock()
	if tunnel == nil {
		return nil
	}

	return tunnel.SendUDPData(target.SessionID, target.ID, data, srcAddr)
}
