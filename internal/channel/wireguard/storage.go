package wireguard

import (
	"context"

	"icool.io/yat/edge/internal/channel/wireguard/relay"

	_ "github.com/mattn/go-sqlite3"
)

// Status
// Status

type Snapshot struct {
	Networks []*Network
	Members  []*NetworkMember
}

// Interface
// Interface
type Storage interface {
	SaveNetwork(ctx context.Context, n *Network) error
	DeleteNetwork(ctx context.Context, networkID string) error

	SaveMember(ctx context.Context, m *NetworkMember) error
	UpdateMember(ctx context.Context, m *NetworkMember) error
	DeleteMember(ctx context.Context, memberID string) error

	LoadSnapshot(ctx context.Context) (*Snapshot, error)

	// Peer rate limit persistence.
	SavePeerRateLimit(ctx context.Context, networkID, peerIP string, rate, ceil uint64) error
	DeletePeerRateLimit(ctx context.Context, networkID, peerIP string) error
	DeleteNetworkPeerRateLimits(ctx context.Context, networkID string) error
	LoadPeerRateLimits(ctx context.Context) ([]relay.PeerRateLimitRecord, error)

	// Close 释放底层数据库句柄；命令行工具只读打开后需要显式关闭。
	Close() error
}
