package p2p

import (
	"net"
	"sync"
	"time"
)

type PathType int

const (
	PathUnknown PathType = iota
	PathDirect
	PathRelay
	PathLegacy
)

type SessionStatus int

const (
	SessionStatusNew SessionStatus = iota
	SessionStatusGathering
	SessionStatusPunching
	SessionStatusEstablishing
	SessionStatusConnected
	SessionStatusFailed
	SessionStatusClosed
)

type Session struct {
	ID          string
	NetworkID   string
	InitiatorID string
	PeerA       string
	PeerB       string
	Status      SessionStatus
	PathType    PathType
	PreferredLinks     []string
	AllowRelayFallback bool
	RequireDirect      bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastError          string
}

// NATType NAT type classification
type NATType string

const (
	NATUnknown        NATType = "unknown"
	NATOpen           NATType = "open"
	NATFullCone       NATType = "full_cone"
	NATRestrictedCone NATType = "restricted_cone"
	NATPortRestricted NATType = "port_restricted"
	NATSymmetric      NATType = "symmetric"
)

// ClientInfo holds client network information for P2P negotiation.
type ClientInfo struct {
	ClientID   string  `json:"client_id"`
	LocalAddr  string  `json:"local_addr"`
	PublicAddr string  `json:"public_addr"`
	NATType    NATType `json:"nat_type"`
	RegisterAt time.Time `json:"register_at"`
	LastSeen   time.Time `json:"last_seen"`
	Conn       net.Conn  `json:"-"`
}

// PunchState represents the state of a punch session.
type PunchState int

const (
	PunchStateInit PunchState = iota
	PunchStateExchanging
	PunchStatePunching
	PunchStateSuccess
	PunchStateFailed
	PunchStateRelaying
)

// PunchSession represents a hole-punching session between two peers.
type PunchSession struct {
	ID        string
	ClientA   string
	ClientB   string
	StartTime time.Time
	State     PunchState
	mu        sync.Mutex
}
