package channel

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	chtype "icool.io/yat/edge/internal/channel/types"
)

// Re-export from types/.
type ChannelRecord = chtype.ChannelRecord

// ChannelStore Channel 持久化存储
type ChannelStore struct {
	db *sql.DB
}

// NewChannelStore 创建 Channel 存储
func NewChannelStore(dbPath string) (*ChannelStore, error) {
	dir := strings.TrimSpace(filepath.Dir(dbPath))
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("ensure channel db dir %s: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	// 创建表
	schema := `
	CREATE TABLE IF NOT EXISTS channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		channel_id TEXT UNIQUE NOT NULL,
		session_id TEXT NOT NULL,
		type INTEGER NOT NULL,
		local_addr TEXT NOT NULL,
		port INTEGER NOT NULL DEFAULT 0,
		subdomain TEXT,
		alias_domain TEXT,
		created_at INTEGER NOT NULL,
		last_active_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_channels_session ON channels(session_id);
	CREATE INDEX IF NOT EXISTS idx_channels_subdomain ON channels(subdomain);
	CREATE INDEX IF NOT EXISTS idx_channels_channel_id ON channels(channel_id);
	`

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	if err := ensureChannelsSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &ChannelStore{db: db}, nil
}

func ensureChannelsSchema(db *sql.DB) error {
	hasAliasDomain, err := hasColumn(db, "channels", "alias_domain")
	if err != nil {
		return fmt.Errorf("check channels.alias_domain: %w", err)
	}
	if !hasAliasDomain {
		if _, err := db.Exec(`ALTER TABLE channels ADD COLUMN alias_domain TEXT`); err != nil {
			return fmt.Errorf("add channels.alias_domain: %w", err)
		}

		hasCustomDomain, err := hasColumn(db, "channels", "custom_domain")
		if err != nil {
			return fmt.Errorf("check channels.custom_domain: %w", err)
		}
		if hasCustomDomain {
			_, err = db.Exec(`
				UPDATE channels
				SET alias_domain = custom_domain
				WHERE (alias_domain IS NULL OR alias_domain = '')
				  AND custom_domain IS NOT NULL
				  AND custom_domain != ''
			`)
			if err != nil {
				return fmt.Errorf("migrate channels.custom_domain -> alias_domain: %w", err)
			}
		}
	}
	hasPort, err := hasColumn(db, "channels", "port")
	if err != nil {
		return fmt.Errorf("check channels.port: %w", err)
	}
	if !hasPort {
		if _, err := db.Exec(`ALTER TABLE channels ADD COLUMN port INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add channels.port: %w", err)
		}
	}

	if err := dropLegacyDomainColumns(db); err != nil {
		return err
	}
	return nil
}

func dropLegacyDomainColumns(db *sql.DB) error {
	hasAssignedDomain, err := hasColumn(db, "channels", "assigned_domain")
	if err != nil {
		return fmt.Errorf("check channels.assigned_domain: %w", err)
	}
	hasRemoteAddr, err := hasColumn(db, "channels", "remote_addr")
	if err != nil {
		return fmt.Errorf("check channels.remote_addr: %w", err)
	}
	if !hasAssignedDomain && !hasRemoteAddr {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin channels schema migration: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.Exec(`
			CREATE TABLE channels_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				channel_id TEXT UNIQUE NOT NULL,
				session_id TEXT NOT NULL,
				type INTEGER NOT NULL,
				local_addr TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 0,
				subdomain TEXT,
				alias_domain TEXT,
				created_at INTEGER NOT NULL,
				last_active_at INTEGER NOT NULL
			)
	`)
	if err != nil {
		return fmt.Errorf("create channels_new: %w", err)
	}

	hasPort, err := hasColumn(db, "channels", "port")
	if err != nil {
		return fmt.Errorf("check channels.port before legacy migration: %w", err)
	}
	copySQL := `
		INSERT INTO channels_new (id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at)
		SELECT id, channel_id, session_id, type, local_addr, 0, subdomain, alias_domain, created_at, last_active_at
		FROM channels
	`
	if hasPort {
		copySQL = `
			INSERT INTO channels_new (id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at)
			SELECT id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at
			FROM channels
		`
	}
	_, err = tx.Exec(copySQL)
	if err != nil {
		return fmt.Errorf("copy channels data: %w", err)
	}

	if _, err = tx.Exec(`DROP TABLE channels`); err != nil {
		return fmt.Errorf("drop old channels table: %w", err)
	}
	if _, err = tx.Exec(`ALTER TABLE channels_new RENAME TO channels`); err != nil {
		return fmt.Errorf("rename channels_new: %w", err)
	}

	if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_channels_session ON channels(session_id)`); err != nil {
		return fmt.Errorf("create idx_channels_session: %w", err)
	}
	if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_channels_subdomain ON channels(subdomain)`); err != nil {
		return fmt.Errorf("create idx_channels_subdomain: %w", err)
	}
	if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_channels_channel_id ON channels(channel_id)`); err != nil {
		return fmt.Errorf("create idx_channels_channel_id: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit channels schema migration: %w", err)
	}
	return nil
}

func hasColumn(db *sql.DB, tableName, columnName string) (bool, error) {
	query := fmt.Sprintf(`SELECT COUNT(1) FROM pragma_table_info('%s') WHERE name = ?`, tableName)
	var count int
	if err := db.QueryRow(query, columnName).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// Save 保存或更新 Channel
func (s *ChannelStore) Save(ctx context.Context, ch *ChannelRecord) error {
	if ch == nil {
		return nil
	}

	result, err := s.db.ExecContext(ctx,
		`INSERT INTO channels (channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(channel_id) DO UPDATE SET
				session_id=excluded.session_id,
				type=excluded.type,
				local_addr=excluded.local_addr,
				port=excluded.port,
				subdomain=excluded.subdomain,
				alias_domain=excluded.alias_domain,
				last_active_at=excluded.last_active_at`,
		ch.ChannelID, ch.SessionID, ch.Type, ch.LocalAddr,
		ch.Port, ch.Subdomain, ch.AliasDomain,
		ch.CreatedAt.Unix(), ch.LastActiveAt.Unix(),
	)
	if err != nil {
		return err
	}
	// 获取自增ID
	if ch.ID == 0 {
		ch.ID, err = result.LastInsertId()
	}
	return err
}

// Get 获取 Channel
func (s *ChannelStore) Get(ctx context.Context, channelID string) (*ChannelRecord, error) {
	var ch ChannelRecord
	var createdAt, lastActiveAt int64

	err := s.db.QueryRowContext(ctx,
		`SELECT id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at
		 FROM channels WHERE channel_id = ?`,
		channelID,
	).Scan(
		&ch.ID, &ch.ChannelID, &ch.SessionID, &ch.Type, &ch.LocalAddr,
		&ch.Port, &ch.Subdomain, &ch.AliasDomain,
		&createdAt, &lastActiveAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ch.CreatedAt = time.Unix(createdAt, 0)
	ch.LastActiveAt = time.Unix(lastActiveAt, 0)

	return &ch, nil
}

// GetBySubdomain 根据 subdomain 获取 Channel
func (s *ChannelStore) GetBySubdomain(ctx context.Context, subdomain string) (*ChannelRecord, error) {
	var ch ChannelRecord
	var createdAt, lastActiveAt int64

	err := s.db.QueryRowContext(ctx,
		`SELECT id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at
		 FROM channels WHERE subdomain = ? ORDER BY last_active_at DESC LIMIT 1`,
		subdomain,
	).Scan(
		&ch.ID, &ch.ChannelID, &ch.SessionID, &ch.Type, &ch.LocalAddr,
		&ch.Port, &ch.Subdomain, &ch.AliasDomain,
		&createdAt, &lastActiveAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ch.CreatedAt = time.Unix(createdAt, 0)
	ch.LastActiveAt = time.Unix(lastActiveAt, 0)

	return &ch, nil
}

// Delete 删除 Channel
func (s *ChannelStore) Delete(ctx context.Context, channelID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM channels WHERE channel_id = ?`, channelID)
	return err
}

// UpdateActivity 更新最后活跃时间
func (s *ChannelStore) UpdateActivity(ctx context.Context, channelID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE channels SET last_active_at = ? WHERE channel_id = ?`,
		time.Now().Unix(), channelID,
	)
	return err
}

// Close 关闭数据库
func (s *ChannelStore) Close() error {
	return s.db.Close()
}

// List 获取所有 Channel
func (s *ChannelStore) List(ctx context.Context) ([]*ChannelRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, channel_id, session_id, type, local_addr, port, subdomain, alias_domain, created_at, last_active_at
		 FROM channels ORDER BY last_active_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var channels []*ChannelRecord
	for rows.Next() {
		var ch ChannelRecord
		var createdAt, lastActiveAt int64

		if err := rows.Scan(
			&ch.ID, &ch.ChannelID, &ch.SessionID, &ch.Type, &ch.LocalAddr,
			&ch.Port, &ch.Subdomain, &ch.AliasDomain,
			&createdAt, &lastActiveAt,
		); err != nil {
			return nil, err
		}

		ch.CreatedAt = time.Unix(createdAt, 0)
		ch.LastActiveAt = time.Unix(lastActiveAt, 0)
		channels = append(channels, &ch)
	}

	return channels, rows.Err()
}

// DeleteInactiveBefore 删除指定时间之前未活跃的 Channel
func (s *ChannelStore) DeleteInactiveBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM channels WHERE last_active_at < ?`,
		before.Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
