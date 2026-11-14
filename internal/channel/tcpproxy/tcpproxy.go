package tcpproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagRST uint8 = 0x02

	tcpAcceptDeadline      = 1 * time.Second
	tcpClientReadDeadline  = 30 * time.Second
	tcpClientWriteDeadline = 10 * time.Second

	tcpDataChanSize = 100
	tcpReadBufSize  = 32 * 1024

	proxyProtoV2VersionCommand  byte = 0x21 // version 2 + PROXY command
	proxyProtoV2TransportStream byte = 0x01
	proxyProtoV2FamilyUnspec    byte = 0x00
	proxyProtoV2FamilyIPv4      byte = 0x10
	proxyProtoV2FamilyIPv6      byte = 0x20

	// PROXY protocol v2 should be opt-in. Injecting it into generic TCP streams
	// (for example SSH) corrupts payload when backend services do not parse it.
	tcpSendProxyProtocolV2Header = false
)

var proxyProtoV2Signature = [...]byte{
	0x0d, 0x0a, 0x0d, 0x0a,
	0x00, 0x0d, 0x0a, 0x51,
	0x55, 0x49, 0x54, 0x0a,
}

type TCPProxy struct {
	tunnel    ct.TunnelSender
	listeners map[uint16]*tcpListener
	connIndex map[string]*tcpConn
	connCount uint64
	mu        sync.RWMutex
}

type tcpListener struct {
	target   *ct.Channel
	listener net.Listener
	conns    map[string]*tcpConn
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

type tcpConn struct {
	id        string
	conn      net.Conn
	target    *ct.Channel
	dataCh    chan []byte
	doneCh    chan struct{}
	closeOnce sync.Once

	notifyTunnelCloseOnce sync.Once
	createdAt             time.Time
}

func New(tunnel ct.TunnelSender) *TCPProxy {
	return &TCPProxy{
		tunnel:    tunnel,
		listeners: make(map[uint16]*tcpListener),
		connIndex: make(map[string]*tcpConn),
	}
}

func (p *TCPProxy) Type() fbMsg.ChannelType {
	return fbMsg.ChannelTypeTCP
}

func (p *TCPProxy) Start() error {
	return nil
}

func (p *TCPProxy) Stop() error {
	p.mu.Lock()
	listeners := make([]*tcpListener, 0, len(p.listeners))
	for port, l := range p.listeners {
		listeners = append(listeners, l)
		delete(p.listeners, port)
	}
	p.connIndex = make(map[string]*tcpConn)
	p.mu.Unlock()

	for _, l := range listeners {
		p.stopListener(l)
	}
	return nil
}

func (p *TCPProxy) SetTunnel(tunnel ct.TunnelSender) {
	p.mu.Lock()
	p.tunnel = tunnel
	p.mu.Unlock()
}

// --- ChannelRuntime interface ---

func (p *TCPProxy) Upsert(target *ct.Channel, previous *ct.Channel) error {
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

func (p *TCPProxy) Remove(target *ct.Channel) error {
	if p == nil || target == nil {
		return nil
	}
	if target.Port == 0 {
		return nil
	}
	return p.Close(target.Port)
}

func (p *TCPProxy) HandleData(target *ct.Channel, connectionID string, _ uint32, data []byte, flags uint8) error {
	if p == nil || target == nil {
		return nil
	}
	return p.HandleDataByChannel(target.ID, connectionID, data, flags)
}

// --- Listener management ---

func (p *TCPProxy) Listen(target *ct.Channel) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, exists := p.listeners[target.Port]; exists {
		if existing.target != nil && existing.target.ID == target.ID {
			existing.target = target
			logger.Infof("TCP proxy listener updated on port %d, target: %s", target.Port, target.ID)
			return nil
		}
		return fmt.Errorf("port %d already in use", target.Port)
	}

	addr := fmt.Sprintf(":%d", target.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	l := &tcpListener{
		target:   target,
		listener: listener,
		conns:    make(map[string]*tcpConn),
		stopCh:   make(chan struct{}),
	}

	p.listeners[target.Port] = l

	l.wg.Add(1)
	go p.acceptLoop(l)

	logger.Infof("TCP proxy listening on port %d, target: %s", target.Port, target.ID)
	return nil
}

func (p *TCPProxy) Close(port uint16) error {
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

func (p *TCPProxy) HandleDataByChannel(channelID, connectionID string, data []byte, flags uint8) error {
	p.mu.RLock()
	conn := p.connIndex[connectionID]
	p.mu.RUnlock()

	if conn == nil || conn.target == nil || conn.target.ID != channelID {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	if flags&tcpFlagFIN != 0 || flags&tcpFlagRST != 0 {
		conn.close()
		return nil
	}

	if len(data) == 0 {
		return nil
	}

	payload := make([]byte, len(data))
	copy(payload, data)

	select {
	case conn.dataCh <- payload:
	case <-conn.doneCh:
	default:
		logger.Warnf("data channel full, connection: %s", connectionID)
	}

	return nil
}

func (p *TCPProxy) GetActiveConnections(channelID string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, l := range p.listeners {
		if l.target.ID == channelID {
			l.mu.RLock()
			count := len(l.conns)
			l.mu.RUnlock()
			return count
		}
	}
	return 0
}

func (p *TCPProxy) stopListener(l *tcpListener) {
	if l == nil {
		return
	}

	l.stopOnce.Do(func() {
		close(l.stopCh)
		_ = l.listener.Close()

		l.mu.RLock()
		conns := make([]*tcpConn, 0, len(l.conns))
		connIDs := make([]string, 0, len(l.conns))
		for connID, conn := range l.conns {
			conns = append(conns, conn)
			connIDs = append(connIDs, connID)
		}
		l.mu.RUnlock()

		for _, conn := range conns {
			conn.close()
		}

		p.mu.Lock()
		for _, connID := range connIDs {
			delete(p.connIndex, connID)
		}
		p.mu.Unlock()

		l.wg.Wait()
		logger.Infof("TCP proxy stopped on port %d", l.target.Port)
	})
}

func (p *TCPProxy) acceptLoop(l *tcpListener) {
	defer l.wg.Done()

	for {
		select {
		case <-l.stopCh:
			return
		default:
		}

		if tcpLn, ok := l.listener.(*net.TCPListener); ok {
			_ = tcpLn.SetDeadline(time.Now().Add(tcpAcceptDeadline))
		}

		conn, err := l.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-l.stopCh:
				return
			default:
				logger.Errorf("TCP accept error, port: %d, err: %v", l.target.Port, err)
				continue
			}
		}

		l.wg.Add(1)
		go p.handleConnection(l, conn)
	}
}

func (p *TCPProxy) handleConnection(l *tcpListener, conn net.Conn) {
	defer l.wg.Done()

	connID := fmt.Sprintf("tcp-%d-%s", atomic.AddUint64(&p.connCount, 1), uuid.New().String()[:8])
	remoteAddr := ""
	if conn != nil && conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}
	if remoteAddr != "" {
		connID = fmt.Sprintf("%s@%s", connID, remoteAddr)
	}

	tc := &tcpConn{
		id:        connID,
		conn:      conn,
		target:    l.target,
		dataCh:    make(chan []byte, tcpDataChanSize),
		doneCh:    make(chan struct{}),
		createdAt: time.Now(),
	}

	l.mu.Lock()
	l.conns[connID] = tc
	l.mu.Unlock()

	p.mu.Lock()
	p.connIndex[connID] = tc
	p.mu.Unlock()

	l.target.IncrConnections()
	defer l.target.DecrConnections()

	logger.Infof("TCP connection accepted, port: %d, conn: %s, remote: %s",
		l.target.Port, connID, conn.RemoteAddr())

	if tc.target != nil && tc.target.EagerConnectRemote {
		// Server-first protocols (like VNC/RFB) may not send client bytes first.
		// Send an empty packet to trigger the remote local-side dial immediately.
		if err := p.sendTCPData(tc, nil, 0); err != nil {
			logger.Errorf("eager connect notify failed, conn: %s, err: %v", connID, err)
			return
		}
		logger.Debugf("eager connect notify sent, conn: %s, channel: %s", connID, tc.target.ID)
	}

	if tcpSendProxyProtocolV2Header {
		if err := p.sendProxyProtocolV2Header(tc); err != nil {
			logger.Errorf("forward PROXY protocol v2 header failed, conn: %s, err: %v", connID, err)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		p.readFromClient(l, tc)
	}()

	go func() {
		defer wg.Done()
		p.writeToClient(tc)
	}()

	wg.Wait()
	tc.close()

	l.mu.Lock()
	delete(l.conns, connID)
	l.mu.Unlock()

	p.mu.Lock()
	delete(p.connIndex, connID)
	p.mu.Unlock()

	logger.Infof("TCP connection closed, conn: %s", connID)
}

func (p *TCPProxy) readFromClient(l *tcpListener, tc *tcpConn) {
	defer tc.close()

	buf := make([]byte, tcpReadBufSize)

	for {
		select {
		case <-l.stopCh:
			return
		case <-tc.doneCh:
			return
		default:
		}

		_ = tc.conn.SetReadDeadline(time.Now().Add(tcpClientReadDeadline))

		n, err := tc.conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			if err == io.EOF {
				p.notifyTunnelClose(tc, tcpFlagFIN)
			} else {
				logger.Debugf("TCP read error, conn: %s, err: %v", tc.id, err)
				p.notifyTunnelClose(tc, tcpFlagRST)
			}
			return
		}

		if n > 0 {
			tc.target.AddBytesIn(uint64(n))

			data := make([]byte, n)
			copy(data, buf[:n])
			if err := p.sendTCPData(tc, data, 0); err != nil {
				logger.Errorf("forward TCP data failed, conn: %s, err: %v", tc.id, err)
				p.notifyTunnelClose(tc, tcpFlagRST)
				return
			}
		}
	}
}

func (p *TCPProxy) writeToClient(tc *tcpConn) {
	for {
		select {
		case <-tc.doneCh:
			return
		case data := <-tc.dataCh:
			if len(data) > 0 {
				_ = tc.conn.SetWriteDeadline(time.Now().Add(tcpClientWriteDeadline))
				n, err := tc.conn.Write(data)
				if err != nil {
					logger.Debugf("TCP write error, conn: %s, err: %v", tc.id, err)
					p.notifyTunnelClose(tc, tcpFlagRST)
					tc.close()
					return
				}
				tc.target.AddBytesOut(uint64(n))
			}
		}
	}
}

func (p *TCPProxy) sendTCPData(tc *tcpConn, data []byte, flags uint8) error {
	if tc == nil || tc.target == nil {
		return fmt.Errorf("tcp connection target missing")
	}

	p.mu.RLock()
	tunnel := p.tunnel
	p.mu.RUnlock()
	if tunnel == nil {
		return nil
	}

	return tunnel.SendTCPData(tc.target.SessionID, tc.target.ID, tc.id, data, flags)
}

func (p *TCPProxy) notifyTunnelClose(tc *tcpConn, flags uint8) {
	if tc == nil {
		return
	}

	tc.notifyTunnelCloseOnce.Do(func() {
		if err := p.sendTCPData(tc, nil, flags); err != nil {
			logger.Debugf("notify tcp close failed, conn: %s, err: %v", tc.id, err)
		}
	})
}

func (tc *tcpConn) close() {
	if tc == nil {
		return
	}
	tc.closeOnce.Do(func() {
		close(tc.doneCh)
		_ = tc.conn.Close()
	})
}

func (p *TCPProxy) sendProxyProtocolV2Header(tc *tcpConn) error {
	if tc == nil || tc.conn == nil {
		return nil
	}
	header := buildProxyProtocolV2Header(tc.conn.RemoteAddr(), tc.conn.LocalAddr())
	return p.sendTCPData(tc, header, 0)
}

func buildProxyProtocolV2Header(remoteAddr, localAddr net.Addr) []byte {
	header := make([]byte, 16)
	copy(header[:12], proxyProtoV2Signature[:])
	header[12] = proxyProtoV2VersionCommand

	remoteTCP, remoteOK := remoteAddr.(*net.TCPAddr)
	localTCP, localOK := localAddr.(*net.TCPAddr)
	if !remoteOK || !localOK {
		header[13] = proxyProtoV2FamilyUnspec | proxyProtoV2TransportStream
		return header
	}

	remote4 := remoteTCP.IP.To4()
	local4 := localTCP.IP.To4()
	if remote4 != nil && local4 != nil {
		addrPart := make([]byte, 12)
		copy(addrPart[0:4], remote4)
		copy(addrPart[4:8], local4)
		binary.BigEndian.PutUint16(addrPart[8:10], uint16(remoteTCP.Port))
		binary.BigEndian.PutUint16(addrPart[10:12], uint16(localTCP.Port))

		header[13] = proxyProtoV2FamilyIPv4 | proxyProtoV2TransportStream
		binary.BigEndian.PutUint16(header[14:16], uint16(len(addrPart)))
		return append(header, addrPart...)
	}

	remote6 := remoteTCP.IP.To16()
	local6 := localTCP.IP.To16()
	if remote4 == nil && local4 == nil && remote6 != nil && local6 != nil {
		addrPart := make([]byte, 36)
		copy(addrPart[0:16], remote6)
		copy(addrPart[16:32], local6)
		binary.BigEndian.PutUint16(addrPart[32:34], uint16(remoteTCP.Port))
		binary.BigEndian.PutUint16(addrPart[34:36], uint16(localTCP.Port))

		header[13] = proxyProtoV2FamilyIPv6 | proxyProtoV2TransportStream
		binary.BigEndian.PutUint16(header[14:16], uint16(len(addrPart)))
		return append(header, addrPart...)
	}

	header[13] = proxyProtoV2FamilyUnspec | proxyProtoV2TransportStream
	return header
}
