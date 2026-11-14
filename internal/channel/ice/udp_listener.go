package ice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	logger "icool.io/yat/edge/pkg/log"
)

type UDPListener struct {
	conn       *net.UDPConn
	connAlt    *net.UDPConn
	altShared  bool
	controller *Controller
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// udpPacketLen is the wire size of an ICE UDP probe/punch packet:
//
//	magic(4) + type(1) + ufrag(32) + hmac(32) = 69
const udpPacketLen = 69

// computeUDPPacketMAC returns HMAC-SHA256(hex_decode(pwd), magic || type || ufrag).
// If pwd is not valid hex, the raw pwd bytes are used as key (graceful fallback).
func computeUDPPacketMAC(pwd string, magic uint32, pktType byte, ufrag string) []byte {
	key, err := hex.DecodeString(pwd)
	if err != nil || len(key) == 0 {
		key = []byte(pwd)
	}
	h := hmac.New(sha256.New, key)
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	hdr[4] = pktType
	h.Write(hdr[:])
	h.Write([]byte(ufrag))
	return h.Sum(nil)
}

// verifyUDPPacketMAC returns true when receivedMac matches the expected MAC.
func verifyUDPPacketMAC(pwd string, magic uint32, pktType byte, ufrag string, receivedMac []byte) bool {
	if len(receivedMac) != sha256.Size {
		return false
	}
	expected := computeUDPPacketMAC(pwd, magic, pktType, ufrag)
	return hmac.Equal(expected, receivedMac)
}

func chooseUDPNetworkForListen(addr string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return "udp4"
	}
	if strings.HasPrefix(trimmed, ":") {
		return "udp4"
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "udp"
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch host {
	case "", "0.0.0.0":
		return "udp4"
	case "::":
		return "udp6"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return "udp4"
		}
		return "udp6"
	}
	return "udp"
}

func normalizeUDPListenAddrForNetwork(addr, network string) string {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return trimmed
	}
	if network != "udp4" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, ":") {
		return "0.0.0.0" + trimmed
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return trimmed
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return net.JoinHostPort("0.0.0.0", strings.TrimSpace(port))
	}
	return trimmed
}

func listenUDPWithPreferredFamily(addr string) (*net.UDPConn, string, string, error) {
	network := chooseUDPNetworkForListen(addr)
	normalized := normalizeUDPListenAddrForNetwork(addr, network)
	udpAddr, err := net.ResolveUDPAddr(network, normalized)
	if err != nil {
		return nil, network, normalized, fmt.Errorf("resolve udp addr %s (%s): %w", normalized, network, err)
	}
	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, network, normalized, fmt.Errorf("listen udp %s (%s): %w", normalized, network, err)
	}
	return conn, network, normalized, nil
}

func udpTokenPreview(token string) string {
	trimmed := strings.TrimRight(token, " ")
	if trimmed == "" {
		return "<empty>"
	}
	if len(trimmed) > 8 {
		return trimmed[:8] + "..."
	}
	return trimmed
}

func shouldSharePrimaryForAlt(addr string) bool {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, ":") {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, ":")) == "0"
	}
	_, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return false
	}
	return strings.TrimSpace(port) == "0"
}

func NewUDPListener(addr, addrAlt string, controller *Controller) (*UDPListener, error) {
	conn, network, normalized, err := listenUDPWithPreferredFamily(addr)
	if err != nil {
		return nil, err
	}
	logger.Infof("ICE UDP listener bound primary: requested=%s normalized=%s network=%s local=%s", addr, normalized, network, conn.LocalAddr())

	listener := &UDPListener{
		conn:       conn,
		controller: controller,
		stopCh:     make(chan struct{}),
	}

	if shouldSharePrimaryForAlt(addrAlt) {
		listener.altShared = true
		logger.Infof("ICE UDP listener alt: sharing primary socket (requested=%s local=%s)", addrAlt, conn.LocalAddr())
		return listener, nil
	}

	connAlt, networkAlt, normalizedAlt, err := listenUDPWithPreferredFamily(addrAlt)
	if err != nil {
		conn.Close()
		return nil, err
	}
	listener.connAlt = connAlt
	logger.Infof("ICE UDP listener bound alt: requested=%s normalized=%s network=%s local=%s", addrAlt, normalizedAlt, networkAlt, connAlt.LocalAddr())
	return listener, nil
}

func (l *UDPListener) Serve() {
	if l.conn == nil {
		return
	}
	if l.altShared || l.connAlt == nil {
		l.wg.Add(1)
		go l.readLoop(l.conn)
		return
	}
	l.wg.Add(2)
	go l.readLoop(l.conn)
	go l.readLoop(l.connAlt)
}

func (l *UDPListener) Close() {
	close(l.stopCh)
	if l.conn != nil {
		_ = l.conn.Close()
	}
	if l.connAlt != nil && l.connAlt != l.conn {
		_ = l.connAlt.Close()
	}
	l.wg.Wait()
}

func (l *UDPListener) Addr() string {
	return l.conn.LocalAddr().String()
}

func (l *UDPListener) AddrAlt() string {
	if l.connAlt != nil {
		return l.connAlt.LocalAddr().String()
	}
	if l.conn != nil {
		return l.conn.LocalAddr().String()
	}
	return ""
}

func (l *UDPListener) readLoop(conn *net.UDPConn) {
	defer l.wg.Done()
	buf := make([]byte, 1500)

	for {
		select {
		case <-l.stopCh:
			return
		default:
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
				logger.Warnf("ICE UDP read error: %v", err)
				continue
			}
		}

		if n < udpPacketLen { // magic(4) + type(1) + ufrag(32) + hmac(32) = 69
			continue
		}

		magic := binary.BigEndian.Uint32(buf[0:4])
		if magic != UDPMagic {
			continue
		}

		pktType := UDPPacketType(buf[4])
		pktIsAlt := pktType == UDPPacketProbeAlt
		ufrag := string(buf[5:37])
		receivedMac := buf[37:69]

		pwd, ok := l.controller.GetPwdByToken(ufrag)
		if !ok {
			logger.Debugf("ICE UDP drop unknown token from %s (token=%s type=%d alt=%v)", remoteAddr, udpTokenPreview(ufrag), pktType, pktIsAlt)
			continue
		}

		if !verifyUDPPacketMAC(pwd, magic, byte(pktType), ufrag, receivedMac) {
			logger.Warnf("ICE UDP HMAC verify failed from %s (token=%s type=%d alt=%v)", remoteAddr, udpTokenPreview(ufrag), pktType, pktIsAlt)
			continue
		}

		switch pktType {
		case UDPPacketProbe, UDPPacketProbeAlt:
			isAlt := pktType == UDPPacketProbeAlt
			l.controller.OnUDPProbeReceived(ufrag, remoteAddr, isAlt)
			if isAlt {
				logger.Debugf("ICE UDP alt probe from %s (token=%s...)", remoteAddr, ufrag[:8])
			} else {
				logger.Debugf("ICE UDP primary probe from %s (token=%s...)", remoteAddr, ufrag[:8])
			}
		default:
			logger.Debugf("ICE UDP unknown packet type %d from %s", pktType, remoteAddr)
		}
	}
}

func BuildProbePacket(ufrag, pwd string) []byte {
	return buildUDPPacket(UDPPacketProbe, ufrag, pwd)
}

func BuildPunchPacket(ufrag, pwd string) []byte {
	return buildUDPPacket(UDPPacketPunch, ufrag, pwd)
}

func buildUDPPacket(pktType UDPPacketType, ufrag, pwd string) []byte {
	pkt := make([]byte, udpPacketLen)
	binary.BigEndian.PutUint32(pkt[0:4], UDPMagic)
	pkt[4] = byte(pktType)
	copy(pkt[5:37], []byte(fmt.Sprintf("%-32s", ufrag)[:32]))
	mac := computeUDPPacketMAC(pwd, UDPMagic, byte(pktType), string(pkt[5:37]))
	copy(pkt[37:69], mac)
	return pkt
}
