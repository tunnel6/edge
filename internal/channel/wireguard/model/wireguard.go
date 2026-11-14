package model

import (
	"database/sql"
	"time"
)

type RelayMode string

const (
	RelayModeDisabled RelayMode = "disabled"
	RelayModeOptional RelayMode = "optional"
	RelayModeForce    RelayMode = "force"
)

// Status
type MemberStatus string

const (
	MemberStatusOnline  MemberStatus = "online"
	MemberStatusOffline MemberStatus = "offline"
)

// Status
type SessionStatus string

const (
	SessionStatusIdle         SessionStatus = "idle"
	SessionStatusGathering    SessionStatus = "gathering"
	SessionStatusPunching     SessionStatus = "punching"
	SessionStatusEstablishing SessionStatus = "establishing"
	SessionStatusConnected    SessionStatus = "connected"
	SessionStatusFailed       SessionStatus = "failed"
	SessionStatusClosed       SessionStatus = "closed"
)

// Type
type PathType string

const (
	PathTypeUnknown PathType = "unknown"
	PathTypeDirect  PathType = "direct"
	PathTypeRelay   PathType = "relay"
)

type WGNetwork struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	NetworkID   string    `gorm:"column:network_id;uniqueIndex;not null"`
	Name        string    `gorm:"column:name;not null"`
	CIDR        string    `gorm:"column:cidr;not null"`
	RelayMode   RelayMode `gorm:"column:relay_mode;default:optional"`
	CreatorID   string    `gorm:"column:creator_id"`
	Description string    `gorm:"column:description"`

	CreatedAt time.Time    `gorm:"column:created_at"`
	UpdatedAt time.Time    `gorm:"column:updated_at"`
	DeletedAt sql.NullTime `gorm:"column:deleted_at;index"`
}

func (WGNetwork) TableName() string {
	return "wg_networks"
}

type WGMember struct {
	ID         int64        `gorm:"column:id;primaryKey;autoIncrement"`
	MemberID   string       `gorm:"column:member_id;uniqueIndex;not null"`
	NetworkID  string       `gorm:"column:network_id;index;not null"`
	ClientID   string       `gorm:"column:client_id;index;not null"`
	AssignedIP string       `gorm:"column:assigned_ip;not null"`
	Status     MemberStatus `gorm:"column:status;default:online"`

	PublicKey string `gorm:"column:public_key"`
	Endpoint  string `gorm:"column:endpoint"`

	JoinedAt   time.Time    `gorm:"column:joined_at"`
	LastSeenAt time.Time    `gorm:"column:last_seen_at"`
	LeftAt     sql.NullTime `gorm:"column:left_at"`
	CreatedAt  time.Time    `gorm:"column:created_at"`
	UpdatedAt  time.Time    `gorm:"column:updated_at"`
	DeletedAt  sql.NullTime `gorm:"column:deleted_at;index"`
}

func (WGMember) TableName() string {
	return "wg_members"
}

type WGSession struct {
	ID          int64         `gorm:"column:id;primaryKey;autoIncrement"`
	SessionID   string        `gorm:"column:session_id;uniqueIndex;not null"`
	NetworkID   string        `gorm:"column:network_id;index;not null"`
	InitiatorID string        `gorm:"column:initiator_id;index;not null"`
	TargetID    string        `gorm:"column:target_id;index;not null"`
	Status      SessionStatus `gorm:"column:status;default:idle"`
	PathType    PathType      `gorm:"column:path_type;default:unknown"`

	InitiatorIP   string `gorm:"column:initiator_ip"`
	TargetIP      string `gorm:"column:target_ip"`
	ConnectedAddr string `gorm:"column:connected_addr"`
	LastError     string `gorm:"column:last_error"`

	CreatedAt      time.Time    `gorm:"column:created_at"`
	UpdatedAt      time.Time    `gorm:"column:updated_at"`
	ConnectedAt    sql.NullTime `gorm:"column:connected_at"`
	DisconnectedAt sql.NullTime `gorm:"column:disconnected_at"`
	DeletedAt      sql.NullTime `gorm:"column:deleted_at;index"`
}

func (WGSession) TableName() string {
	return "wg_sessions"
}

type WGGatherCandidate struct {
	ID         int64  `gorm:"column:id;primaryKey;autoIncrement"`
	SessionID  string `gorm:"column:session_id;index;not null"`
	ClientID   string `gorm:"column:client_id;index;not null"`
	LocalAddrs string `gorm:"column:local_addrs;type:text"`
	PublicAddr string `gorm:"column:public_addr"`
	NATType    uint8  `gorm:"column:nat_type"`

	CreatedAt time.Time `gorm:"column:created_at"`
}

func (WGGatherCandidate) TableName() string {
	return "wg_gather_candidates"
}

type WGPunchResult struct {
	ID            int64  `gorm:"column:id;primaryKey;autoIncrement"`
	SessionID     string `gorm:"column:session_id;index;not null"`
	ClientID      string `gorm:"column:client_id;index;not null"`
	Success       bool   `gorm:"column:success"`
	ConnectedAddr string `gorm:"column:connected_addr"`
	ErrorMessage  string `gorm:"column:error_message"`

	CreatedAt time.Time `gorm:"column:created_at"`
}

func (WGPunchResult) TableName() string {
	return "wg_punch_results"
}
