package wireguard

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"icool.io/yat/edge/internal/channel/wireguard/relay"
)

// Interface

type sqliteStorage struct {
	db *sql.DB
}

// Create
func NewSQLiteStorage(dbPath string) (Storage, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("dbPath is empty")
	}

	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_foreign_keys=on", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// Create
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &sqliteStorage{db: db}, nil
}

// Close 关闭底层 *sql.DB。
func (s *sqliteStorage) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Exported text helpers
// 供包外（如 cmd 命令行工具）将枚举转为可读字符串，复用包内已有的映射逻辑。

// RelayModeText 返回 relay 模式的可读字符串（disabled/optional/force）。
func RelayModeText(m RelayMode) string { return relayModeToText(m) }

// MemberStatusText 返回成员状态的可读字符串（online/offline）。
func MemberStatusText(s MemberStatus) string { return memberStatusToText(s) }

// MemberHasRealPublicKey 判断成员是否携带真实 WG 公钥（非 clientId 占位）。
func MemberHasRealPublicKey(m *NetworkMember) bool { return hasRealPublicKey(m) }

// MemberIsOnline 判断成员是否真正在线（Online 状态且携带真实公钥），
// 与读模型 presence 口径一致，供命令行工具展示，避免代加占位成员显示为在线。
func MemberIsOnline(m *NetworkMember) bool { return memberIsOnline(m) }

func initSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS wg_networks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			network_id TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			cidr TEXT NOT NULL,
			relay_mode TEXT NOT NULL,
			creator_id TEXT,
			description TEXT,
			coordinator_edge_id TEXT,
			created_at INTEGER,
			updated_at INTEGER,
			deleted_at INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS wg_members (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			member_id TEXT UNIQUE NOT NULL,
			network_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			hostname TEXT NOT NULL DEFAULT '',
			assigned_ip TEXT NOT NULL,
			status TEXT NOT NULL,
			public_key TEXT,
			endpoint TEXT,
			joined_at INTEGER,
			last_seen_at INTEGER,
			left_at INTEGER,
			created_at INTEGER,
			updated_at INTEGER,
			observed_at INTEGER NOT NULL DEFAULT 0,
			is_relay INTEGER NOT NULL DEFAULT 0,
			lan_endpoint TEXT NOT NULL DEFAULT '',
			path_membership_revoked INTEGER NOT NULL DEFAULT 0,
			deleted_at INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS wg_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT UNIQUE NOT NULL,
			network_id TEXT NOT NULL,
			initiator_id TEXT NOT NULL,
			target_id TEXT NOT NULL,
			status TEXT NOT NULL,
			path_type TEXT NOT NULL,
			initiator_ip TEXT,
			target_ip TEXT,
			connected_addr TEXT,
			last_error TEXT,
			created_at INTEGER,
			updated_at INTEGER,
			connected_at INTEGER,
			disconnected_at INTEGER,
			deleted_at INTEGER
		);`,
		`CREATE TABLE IF NOT EXISTS wg_peer_rate_limits (
			network_id TEXT NOT NULL,
			peer_ip TEXT NOT NULL,
			rate INTEGER NOT NULL,
			ceil INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (network_id, peer_ip)
		);`,
	}

	for _, sqlStmt := range stmts {
		if _, err := db.Exec(sqlStmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	// if _, err := db.Exec(`ALTER TABLE wg_members ADD COLUMN hostname TEXT NOT NULL DEFAULT ''`); err != nil &&
	// 	!strings.Contains(err.Error(), "duplicate column name") {
	// 	return fmt.Errorf("migrate wg_members.hostname: %w", err)
	// }
	// // Older versions populated endpoint from control/session addresses. Without
	// // an observation timestamp those values are not verified WG UDP endpoints.
	// // Relay members instead publish a configured listener and must be retained.
	// if _, err := db.Exec(`UPDATE wg_members SET endpoint = '' WHERE is_relay = 0 AND COALESCE(observed_at, 0) = 0 AND COALESCE(endpoint, '') != ''`); err != nil {
	// 	return fmt.Errorf("clear unverified legacy member endpoints: %w", err)
	// }

	// Migrate: add lan_endpoint column if missing (upgrade from older builds).
	if _, err := db.Exec(`ALTER TABLE wg_members ADD COLUMN lan_endpoint TEXT NOT NULL DEFAULT ''`); err != nil &&
		!strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("migrate wg_members.lan_endpoint: %w", err)
	}

	return migratePathMembershipRevocation(db)
}

// Add and seed in one transaction: a restart must neither lose the initial
// seed nor reapply historical status after a successful explicit rejoin.
func migratePathMembershipRevocation(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin membership revocation migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE wg_members ADD COLUMN path_membership_revoked INTEGER NOT NULL DEFAULT 0`); err != nil {
		if strings.Contains(err.Error(), "duplicate column name") {
			return nil
		}
		return fmt.Errorf("migrate wg_members.path_membership_revoked: %w", err)
	}
	// Current legacy writers collapse leave and temporary absence to "offline".
	// That ambiguous history cannot be recovered. Only explicit status facts
	// from older/imported records qualify; left_at alone may predate a rejoin.
	if _, err := tx.Exec(`UPDATE wg_members SET path_membership_revoked = 1 WHERE LOWER(status) IN ('leaved', 'removed')`); err != nil {
		return fmt.Errorf("seed membership revocation: %w", err)
	}
	return tx.Commit()
}

// Status
func (s *sqliteStorage) LoadSnapshot(ctx context.Context) (*Snapshot, error) {
	snap := &Snapshot{}

	rows, err := s.db.QueryContext(ctx, `SELECT network_id, name, cidr, relay_mode, COALESCE(creator_id, ''), COALESCE(coordinator_edge_id, ''), created_at, updated_at FROM wg_networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("load networks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, name, cidr, relayModeText, creatorID, coordinatorEdgeID string
			createdAt, updatedAt                                        int64
		)
		if err := rows.Scan(&id, &name, &cidr, &relayModeText, &creatorID, &coordinatorEdgeID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan network: %w", err)
		}
		snap.Networks = append(snap.Networks, &Network{
			ID:                id,
			Name:              name,
			CIDR:              cidr,
			CoordinatorEdgeID: coordinatorEdgeID,
			OwnerUserID:       creatorID,
			RelayMode:         textToRelayMode(relayModeText),
			Status:            NetworkStatusActive,
			CreatedAt:         time.Unix(createdAt, 0),
			UpdatedAt:         time.Unix(updatedAt, 0),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT member_id, network_id, client_id, hostname, assigned_ip, status, public_key, endpoint, joined_at, last_seen_at, created_at, updated_at, observed_at, is_relay, lan_endpoint, path_membership_revoked FROM wg_members WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("load members: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			memberID, networkID, clientID, hostname, ip, statusText string
			publicKey, endpoint, lanEndpoint                        sql.NullString
			joinedAt, lastSeenAt, createdAt, updatedAt              int64
			observedAt                                              int64
			isRelay                                                 bool
			pathRevoked                                             bool
		)
		if err := rows.Scan(&memberID, &networkID, &clientID, &hostname, &ip, &statusText, &publicKey, &endpoint, &joinedAt, &lastSeenAt, &createdAt, &updatedAt, &observedAt, &isRelay, &lanEndpoint, &pathRevoked); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		snap.Members = append(snap.Members, &NetworkMember{
			ID:          memberID,
			NetworkID:   networkID,
			ClientID:    clientID,
			HostName:    hostname,
			IP:          ip,
			PublicKey:   publicKey.String,
			Endpoint:    endpoint.String,
			LANEndpoint: lanEndpoint.String,
			ObservedAt:  observationTime(observedAt),
			IsRelay:     isRelay,
			pathRevoked: pathRevoked,
			Status:      textToMemberStatus(statusText),
			CreatedAt:   time.Unix(createdAt, 0),
			UpdatedAt:   time.Unix(updatedAt, 0),
			LastOnline:  time.Unix(lastSeenAt, 0),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Sessions are ephemeral — not loaded from storage.
	// EnsureDirectSessions recreates them after clients reconnect.

	return snap, nil
}

// Interface

// Update
func (s *sqliteStorage) SaveNetwork(ctx context.Context, n *Network) error {
	if n == nil {
		return nil
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_networks (network_id, name, cidr, relay_mode, creator_id, description, coordinator_edge_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, '', ?, ?, ?)
		 ON CONFLICT(network_id) DO UPDATE SET
			name=excluded.name,
			cidr=excluded.cidr,
			relay_mode=excluded.relay_mode,
			creator_id=excluded.creator_id,
			coordinator_edge_id=excluded.coordinator_edge_id,
			updated_at=excluded.updated_at`,
		n.ID, n.Name, n.CIDR, relayModeToText(n.RelayMode), n.OwnerUserID, n.CoordinatorEdgeID, n.CreatedAt.Unix(), n.UpdatedAt.Unix(),
	)
	return err
}

// Delete
func (s *sqliteStorage) DeleteNetwork(ctx context.Context, networkID string) error {
	if networkID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM wg_networks WHERE network_id = ?`, networkID)
	return err
}

// Write
func (s *sqliteStorage) SaveMember(ctx context.Context, m *NetworkMember) error {
	if m == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_members (member_id, network_id, client_id,  hostname, assigned_ip, status, public_key, endpoint, joined_at, last_seen_at, created_at, updated_at, observed_at, is_relay, lan_endpoint, path_membership_revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(member_id) DO UPDATE SET
			status=excluded.status,
			public_key=excluded.public_key,
			endpoint=excluded.endpoint,
			observed_at=excluded.observed_at,
			is_relay=excluded.is_relay,
			last_seen_at=excluded.last_seen_at,
			updated_at=excluded.updated_at,
			lan_endpoint=excluded.lan_endpoint,
			path_membership_revoked=excluded.path_membership_revoked`,
		m.ID, m.NetworkID, m.ClientID, m.HostName, m.IP, memberStatusToText(m.Status),
		m.PublicKey, m.Endpoint,
		m.CreatedAt.Unix(), m.LastOnline.Unix(), m.CreatedAt.Unix(), m.UpdatedAt.Unix(),
		toMillis(m.ObservedAt),
		m.IsRelay,
		m.LANEndpoint,
		m.pathRevoked,
	)
	return err
}

func (s *sqliteStorage) UpdateMember(ctx context.Context, m *NetworkMember) error {
	if m == nil {
		return nil
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE wg_members SET status = ?, public_key = ?, hostname = ?, endpoint = ?, assigned_ip = ?, last_seen_at = ?, updated_at = ?, observed_at = ?, is_relay = ?, lan_endpoint = ?, path_membership_revoked = ?, client_id = ? WHERE member_id = ?`,
		memberStatusToText(m.Status), m.PublicKey, m.HostName, m.Endpoint, m.IP, m.LastOnline.Unix(), m.UpdatedAt.Unix(), toMillis(m.ObservedAt), m.IsRelay, m.LANEndpoint, m.pathRevoked, m.ClientID, m.ID,
	)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return fmt.Errorf("update member %s: %w", m.ID, sql.ErrNoRows)
	}
	return err
}

func observationTime(millis int64) time.Time {
	if millis <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis)
}

func (s *sqliteStorage) DeleteMember(ctx context.Context, memberID string) error {
	if memberID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM wg_members WHERE member_id = ?`, memberID)
	return err
}

// Status

func relayModeToText(m RelayMode) string {
	switch m {
	case RelayModeDisabled:
		return "disabled"
	case RelayModeForce:
		return "force"
	case RelayModeOptional:
		fallthrough
	default:
		return "optional"
	}
}

func memberStatusToText(s MemberStatus) string {
	switch s {
	case MemberStatusOnline:
		return "online"
	case MemberStatusPending, MemberStatusActive, MemberStatusRemoved:
		fallthrough
	default:
		return "offline"
	}
}

// Status

func textToRelayMode(s string) RelayMode {
	switch s {
	case "disabled":
		return RelayModeDisabled
	case "force":
		return RelayModeForce
	case "optional":
		fallthrough
	default:
		return RelayModeOptional
	}
}

func textToMemberStatus(s string) MemberStatus {
	switch s {
	case "online":
		return MemberStatusOnline
	default:
		// Status
		return MemberStatusActive
	}
}

// SavePeerRateLimit upserts a per-peer rate limit record.
func (s *sqliteStorage) SavePeerRateLimit(ctx context.Context, networkID, peerIP string, rate, ceil uint64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_peer_rate_limits (network_id, peer_ip, rate, ceil, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(network_id, peer_ip) DO UPDATE SET
			rate=excluded.rate,
			ceil=excluded.ceil,
			updated_at=excluded.updated_at`,
		networkID, peerIP, rate, ceil, time.Now().Unix(),
	)
	return err
}

// DeletePeerRateLimit removes a per-peer rate limit record.
func (s *sqliteStorage) DeletePeerRateLimit(ctx context.Context, networkID, peerIP string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM wg_peer_rate_limits WHERE network_id = ? AND peer_ip = ?`,
		networkID, peerIP,
	)
	return err
}

// DeleteNetworkPeerRateLimits removes all rate limit records for a network.
func (s *sqliteStorage) DeleteNetworkPeerRateLimits(ctx context.Context, networkID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM wg_peer_rate_limits WHERE network_id = ?`,
		networkID,
	)
	return err
}

// LoadPeerRateLimits returns all persisted rate limit records.
func (s *sqliteStorage) LoadPeerRateLimits(ctx context.Context) ([]relay.PeerRateLimitRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT network_id, peer_ip, rate, ceil, updated_at FROM wg_peer_rate_limits`,
	)
	if err != nil {
		return nil, fmt.Errorf("load peer rate limits: %w", err)
	}
	defer rows.Close()
	var records []relay.PeerRateLimitRecord
	for rows.Next() {
		var r relay.PeerRateLimitRecord
		var updatedAt int64
		if err := rows.Scan(&r.NetworkID, &r.PeerIP, &r.Rate, &r.Ceil, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan peer rate limit: %w", err)
		}
		r.UpdatedAt = time.Unix(updatedAt, 0)
		records = append(records, r)
	}
	return records, rows.Err()
}
