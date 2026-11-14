package ice

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	p2p "icool.io/yat/edge/internal/channel/p2p"
)

type State string

const (
	StateIdle       State = "idle"
	StateGathering  State = "gathering"
	StateChecking   State = "checking"
	StatePunching   State = "punching"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateFallback   State = "fallback"
	StateFailed     State = "failed"
	StateClosed     State = "closed"
)

func (s State) IsTerminal() bool {
	return s == StateConnected || s == StateFallback || s == StateFailed || s == StateClosed
}

type PunchStrategy string

const (
	StrategyStandard    PunchStrategy = "standard"
	StrategyPortPredict PunchStrategy = "port_predict"
	StrategyRelay       PunchStrategy = "relay"
)

type QuicRole string

const (
	QuicRoleServer QuicRole = "server"
	QuicRoleClient QuicRole = "client"
)

const UDPMagic = 0x59415450 // "YATP"

type UDPPacketType byte

const (
	UDPPacketProbe                UDPPacketType = 0x01
	UDPPacketProbeAlt             UDPPacketType = 0x02
	UDPPacketPunch                UDPPacketType = 0x03
	UDPPacketPunchAck             UDPPacketType = 0x04
	UDPPacketProbeFilterChallenge UDPPacketType = 0x05
	UDPPacketProbeFilterAck       UDPPacketType = 0x06
)

const ALPN = "yat-p2p/1"

type Config struct {
	UDPAddr          string        `json:"udp_addr"`
	UDPAddrAlt       string        `json:"udp_addr_alt"`
	AdvertiseHost    string        `json:"advertise_host"`
	PunchAttempts    int           `json:"punch_attempts"`
	PunchInterval    time.Duration `json:"punch_interval"`
	GatherTimeout    time.Duration `json:"gather_timeout"`
	PunchTimeout     time.Duration `json:"punch_timeout"`
	ConnectTimeout   time.Duration `json:"connect_timeout"`
	SessionRetention time.Duration `json:"session_retention"`
}

func DefaultConfig() Config {
	return Config{
		UDPAddr:          ":0",
		UDPAddrAlt:       "",
		PunchAttempts:    10,
		PunchInterval:    50 * time.Millisecond,
		GatherTimeout:    5 * time.Second,
		PunchTimeout:     5 * time.Second,
		ConnectTimeout:   10 * time.Second,
		SessionRetention: 5 * time.Minute,
	}
}

type PeerEndpoint struct {
	SessionID string
	ClientID  string
	UDPAddr   *net.UDPAddr
	NATType   p2p.NATType
}

type PunchResult struct {
	Success          bool
	PeerObservedAddr string
	AttemptsSent     int
	FirstRecvAt      time.Time
	FailureReason    string
}

type QuicConnInfo struct {
	ConnectionID string
	LocalAddr    string
	PeerAddr     string
	RTTMs        uint32
}

type StateDetail struct {
	PunchStrategy PunchStrategy
	NATTypeA      p2p.NATType
	NATTypeB      p2p.NATType
	Error         string
}

type SessionSnapshot struct {
	ID        string        `json:"id"`
	TunnelID  string        `json:"tunnel_id"`
	State     State         `json:"state"`
	Strategy  PunchStrategy `json:"strategy,omitempty"`
	PubNAT    p2p.NATType   `json:"pub_nat,omitempty"`
	ConNAT    p2p.NATType   `json:"con_nat,omitempty"`
	Error     string        `json:"error,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

type ControllerSnapshot struct {
	Sessions    []SessionSnapshot `json:"sessions"`
	ActiveCount int               `json:"active_count"`
	TotalCount  int               `json:"total_count"`
	UDPAddr     string            `json:"udp_addr"`
	UDPAddrAlt  string            `json:"udp_addr_alt"`
}

type ICEStats struct {
	TotalSessions   uint32           `json:"total_sessions"`
	ActiveSessions  uint32           `json:"active_sessions"`
	SessionsByState map[State]uint32 `json:"sessions_by_state"`
	PunchAttempts   uint64           `json:"punch_attempts"`
	PunchSuccesses  uint64           `json:"punch_successes"`
	PunchFailures   uint64           `json:"punch_failures"`
	AvgPunchLatency float64          `json:"avg_punch_latency_ms"`
	AvgAttemptsSent float64          `json:"avg_attempts_sent"`
	AttemptsSamples uint64           `json:"attempts_sent_samples"`
}

func GenerateUfrag() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GeneratePwd() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
