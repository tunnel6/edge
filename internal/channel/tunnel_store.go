package channel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// TunnelDefinitionRecord stores edge-coordinated tunnel metadata.
// The record is scoped by owner + edge + tunnel id.
type TunnelDefinitionRecord struct {
	ID          int64
	EdgeID      string
	OwnerUserID string
	TunnelID    string
	Name        string
	AppID       string
	Protocol    string
	IntentJSON  string
	ConfigJSON  string
	RuntimeJSON string
	// RemoteURL 是 yat-fe 由 AppRemoteAddressResolver 计算的业务入口地址快照。
	// 主要供 edge 管理员通过 CLI 查看 tunnel 对外的实际地址，不地业务追踪。
	RemoteURL      string
	State          string
	ActorRole      uint8
	ActorSessionID string
	ActorDeviceID  string
	Version        int64
	Revision       int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

// TunnelDefinitionStore persists edge-coordinated tunnel definitions.
type TunnelDefinitionStore struct {
	db *sql.DB
}

func NewTunnelDefinitionStore(dbPath string) (*TunnelDefinitionStore, error) {
	dir := strings.TrimSpace(filepath.Dir(dbPath))
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("ensure tunnel db dir %s: %w", dir, err)
		}
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS tunnel_definitions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		edge_id TEXT NOT NULL,
		owner_user_id TEXT NOT NULL,
		tunnel_id TEXT NOT NULL,
		name TEXT NOT NULL,
		app_id TEXT NOT NULL,
		protocol TEXT NOT NULL,
		intent_json TEXT NOT NULL DEFAULT '{}',
		config_json TEXT NOT NULL DEFAULT '{}',
		runtime_json TEXT NOT NULL DEFAULT '{}',
		state TEXT NOT NULL DEFAULT 'inactive',
		actor_role INTEGER NOT NULL DEFAULT 0,
		actor_session_id TEXT NOT NULL DEFAULT '',
		actor_device_id TEXT NOT NULL DEFAULT '',
		version INTEGER NOT NULL DEFAULT 1,
		revision INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		deleted_at INTEGER
	);
	CREATE TABLE IF NOT EXISTS tunnel_definition_meta (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		current_revision INTEGER NOT NULL DEFAULT 0
	);
	INSERT OR IGNORE INTO tunnel_definition_meta(id, current_revision) VALUES (1, 0);
	`

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create tunnel_definitions schema: %w", err)
	}
	if err := ensureTunnelDefinitionsSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &TunnelDefinitionStore{db: db}, nil
}

func ensureTunnelDefinitionsSchema(db *sql.DB) error {
	columns := []struct {
		name string
		ddl  string
	}{
		{name: "edge_id", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN edge_id TEXT NOT NULL DEFAULT ''`},
		{name: "runtime_json", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN runtime_json TEXT NOT NULL DEFAULT '{}'`},
		{name: "state", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN state TEXT NOT NULL DEFAULT 'inactive'`},
		{name: "version", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN version INTEGER NOT NULL DEFAULT 1`},
		{name: "revision", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN revision INTEGER NOT NULL DEFAULT 0`},
		{name: "deleted_at", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN deleted_at INTEGER`},
		{name: "actor_role", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN actor_role INTEGER NOT NULL DEFAULT 0`},
		{name: "actor_session_id", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN actor_session_id TEXT NOT NULL DEFAULT ''`},
		{name: "actor_device_id", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN actor_device_id TEXT NOT NULL DEFAULT ''`},
		{name: "remote_url", ddl: `ALTER TABLE tunnel_definitions ADD COLUMN remote_url TEXT NOT NULL DEFAULT ''`},
	}

	revisionAdded := false
	for _, column := range columns {
		exists, err := hasColumn(db, "tunnel_definitions", column.name)
		if err != nil {
			return fmt.Errorf("check tunnel_definitions.%s: %w", column.name, err)
		}
		if exists {
			continue
		}
		if _, err := db.Exec(column.ddl); err != nil {
			return fmt.Errorf("add tunnel_definitions.%s: %w", column.name, err)
		}
		if column.name == "revision" {
			revisionAdded = true
		}
	}

	if _, err := db.Exec(`
		UPDATE tunnel_definitions
		SET owner_user_id = 'unknown'
		WHERE TRIM(owner_user_id) = ''
	`); err != nil {
		return fmt.Errorf("normalize tunnel_definitions.owner_user_id: %w", err)
	}

	if _, err := db.Exec(`
		DELETE FROM tunnel_definitions
		WHERE id NOT IN (
			SELECT id FROM (
				SELECT MAX(id) AS id
				FROM tunnel_definitions
				GROUP BY owner_user_id, edge_id, tunnel_id
			)
		)
	`); err != nil {
		return fmt.Errorf("deduplicate tunnel_definitions by owner+edge+tunnel: %w", err)
	}

	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_scope
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_scope: %w", err)
	}
	if _, err := db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnel_definitions_scope
			ON tunnel_definitions(owner_user_id, edge_id, tunnel_id)
	`); err != nil {
		return fmt.Errorf("create idx_tunnel_definitions_scope: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_owner
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_owner: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_edge_owner
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_edge_owner: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_owner_revision
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_owner_revision: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_edge_owner_revision
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_edge_owner_revision: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_owner_edge
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_owner_edge: %w", err)
	}
	if _, err := db.Exec(`
		DROP INDEX IF EXISTS idx_tunnel_definitions_owner_edge_revision
	`); err != nil {
		return fmt.Errorf("drop idx_tunnel_definitions_owner_edge_revision: %w", err)
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_tunnel_definitions_edge
			ON tunnel_definitions(edge_id, deleted_at, updated_at DESC)
	`); err != nil {
		return fmt.Errorf("create idx_tunnel_definitions_edge: %w", err)
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_tunnel_definitions_edge_revision
			ON tunnel_definitions(edge_id, revision ASC)
	`); err != nil {
		return fmt.Errorf("create idx_tunnel_definitions_edge_revision: %w", err)
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_tunnel_definitions_owner_edge
			ON tunnel_definitions(owner_user_id, edge_id, deleted_at, updated_at DESC)
	`); err != nil {
		return fmt.Errorf("create idx_tunnel_definitions_owner_edge: %w", err)
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_tunnel_definitions_owner_edge_revision
			ON tunnel_definitions(owner_user_id, edge_id, revision ASC)
	`); err != nil {
		return fmt.Errorf("create idx_tunnel_definitions_owner_edge_revision: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tunnel_definition_meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			current_revision INTEGER NOT NULL DEFAULT 0
		)
	`); err != nil {
		return fmt.Errorf("create tunnel_definition_meta schema: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO tunnel_definition_meta(id, current_revision) VALUES (1, 0)`); err != nil {
		return fmt.Errorf("seed tunnel_definition_meta: %w", err)
	}

	if revisionAdded {
		if _, err := db.Exec(`UPDATE tunnel_definitions SET revision = id WHERE revision = 0`); err != nil {
			return fmt.Errorf("backfill tunnel_definitions.revision: %w", err)
		}
	}

	var maxRevision int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(revision), 0) FROM tunnel_definitions`).Scan(&maxRevision); err != nil {
		return fmt.Errorf("query tunnel_definitions max revision: %w", err)
	}
	if _, err := db.Exec(`
		UPDATE tunnel_definition_meta
		SET current_revision = CASE
			WHEN current_revision < ? THEN ?
			ELSE current_revision
		END
		WHERE id = 1
	`, maxRevision, maxRevision); err != nil {
		return fmt.Errorf("align tunnel_definition_meta.current_revision: %w", err)
	}
	return nil
}

func normalizeJSON(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func normalizeState(value string) string {
	state := strings.TrimSpace(strings.ToLower(value))
	if state == "" {
		return "inactive"
	}
	return state
}

func normalizeStoredActorRole(role uint8) uint8 {
	switch role {
	case 1, 2, 3:
		return role
	default:
		return 0
	}
}

// ResolveTunnelRemoteURL returns the persisted remote URL for tunnel metadata.
// Priority:
// 1) Explicit remote_url field.
// 2) runtime_json snapshot fields (remoteUrl / remote_url / bestUrl / best_url).
func ResolveTunnelRemoteURL(remoteURL, runtimeJSON string) string {
	if direct := strings.TrimSpace(remoteURL); direct != "" {
		return direct
	}

	payload := strings.TrimSpace(runtimeJSON)
	if payload == "" || payload == "{}" {
		return ""
	}

	var runtime struct {
		RemoteURL    string `json:"remoteUrl"`
		RemoteURLAlt string `json:"remote_url"`
		BestURL      string `json:"bestUrl"`
		BestURLAlt   string `json:"best_url"`
	}
	if err := json.Unmarshal([]byte(payload), &runtime); err != nil {
		return ""
	}

	for _, candidate := range []string{
		runtime.RemoteURL,
		runtime.RemoteURLAlt,
		runtime.BestURL,
		runtime.BestURLAlt,
	} {
		if normalized := strings.TrimSpace(candidate); normalized != "" {
			return normalized
		}
	}
	return ""
}

func (s *TunnelDefinitionStore) Upsert(ctx context.Context, rec *TunnelDefinitionRecord) error {
	if rec == nil {
		return nil
	}

	rec.EdgeID = strings.TrimSpace(rec.EdgeID)
	rec.OwnerUserID = strings.TrimSpace(rec.OwnerUserID)
	rec.TunnelID = strings.TrimSpace(rec.TunnelID)
	rec.Name = strings.TrimSpace(rec.Name)
	rec.AppID = strings.TrimSpace(rec.AppID)
	rec.Protocol = strings.TrimSpace(strings.ToLower(rec.Protocol))

	if rec.EdgeID == "" || rec.TunnelID == "" {
		return fmt.Errorf("edge_id/tunnel_id are required")
	}
	if rec.OwnerUserID == "" {
		return fmt.Errorf("owner_user_id is required")
	}
	if rec.Name == "" || rec.AppID == "" || rec.Protocol == "" {
		return fmt.Errorf("name/app_id/protocol are required")
	}

	rec.IntentJSON = normalizeJSON(rec.IntentJSON, "{}")
	rec.ConfigJSON = normalizeJSON(rec.ConfigJSON, "{}")
	rec.RuntimeJSON = normalizeJSON(rec.RuntimeJSON, "{}")
	rec.RemoteURL = ResolveTunnelRemoteURL(rec.RemoteURL, rec.RuntimeJSON)
	rec.State = normalizeState(rec.State)
	rec.ActorRole = normalizeStoredActorRole(rec.ActorRole)
	rec.ActorSessionID = strings.TrimSpace(rec.ActorSessionID)
	rec.ActorDeviceID = strings.TrimSpace(rec.ActorDeviceID)

	return s.withTx(ctx, func(tx *sql.Tx) error {
		nextRevision, err := s.nextRevisionTx(ctx, tx)
		if err != nil {
			return err
		}

		now := time.Now().UnixMilli()
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = time.UnixMilli(now)
		}
		rec.UpdatedAt = time.UnixMilli(now)

		version := rec.Version
		if version <= 0 {
			version = 1
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO tunnel_definitions (
				edge_id, owner_user_id, tunnel_id, name, app_id, protocol,
				intent_json, config_json, runtime_json, state,
				actor_role, actor_session_id, actor_device_id,
				version, revision, created_at, updated_at, deleted_at, remote_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
			ON CONFLICT(owner_user_id, edge_id, tunnel_id) DO UPDATE SET
				name = excluded.name,
				app_id = excluded.app_id,
				protocol = excluded.protocol,
				intent_json = excluded.intent_json,
				config_json = excluded.config_json,
				runtime_json = excluded.runtime_json,
				state = excluded.state,
				actor_role = excluded.actor_role,
				actor_session_id = excluded.actor_session_id,
				actor_device_id = excluded.actor_device_id,
				remote_url = CASE
					WHEN TRIM(excluded.remote_url) = '' THEN tunnel_definitions.remote_url
					ELSE excluded.remote_url
				END,
				version = tunnel_definitions.version + 1,
				revision = excluded.revision,
				updated_at = excluded.updated_at,
				deleted_at = NULL
		`,
			rec.EdgeID, rec.OwnerUserID, rec.TunnelID, rec.Name, rec.AppID, rec.Protocol,
			rec.IntentJSON, rec.ConfigJSON, rec.RuntimeJSON, rec.State,
			rec.ActorRole, rec.ActorSessionID, rec.ActorDeviceID, version,
			nextRevision, rec.CreatedAt.UnixMilli(), rec.UpdatedAt.UnixMilli(), rec.RemoteURL,
		)
		if err != nil {
			return err
		}
		return s.hydrateMetaTx(ctx, tx, rec)
	})
}

func (s *TunnelDefinitionStore) hydrateMeta(ctx context.Context, rec *TunnelDefinitionRecord) error {
	return s.hydrateMetaTx(ctx, nil, rec)
}

func (s *TunnelDefinitionStore) hydrateMetaTx(ctx context.Context, tx *sql.Tx, rec *TunnelDefinitionRecord) error {
	query := `
		SELECT id, version, revision, created_at, updated_at, deleted_at
		FROM tunnel_definitions
		WHERE owner_user_id = ? AND edge_id = ? AND tunnel_id = ?
	`

	var row *sql.Row
	if tx != nil {
		row = tx.QueryRowContext(ctx, query, rec.OwnerUserID, rec.EdgeID, rec.TunnelID)
	} else {
		row = s.db.QueryRowContext(ctx, query, rec.OwnerUserID, rec.EdgeID, rec.TunnelID)
	}

	var createdAtMs int64
	var updatedAtMs int64
	var deletedAt sql.NullInt64
	if err := row.Scan(&rec.ID, &rec.Version, &rec.Revision, &createdAtMs, &updatedAtMs, &deletedAt); err != nil {
		return err
	}

	rec.CreatedAt = time.UnixMilli(createdAtMs)
	rec.UpdatedAt = time.UnixMilli(updatedAtMs)
	rec.DeletedAt = nil
	if deletedAt.Valid {
		ts := time.UnixMilli(deletedAt.Int64)
		rec.DeletedAt = &ts
	}
	return nil
}

func (s *TunnelDefinitionStore) Get(
	ctx context.Context,
	ownerUserID string,
	edgeID string,
	tunnelID string,
) (*TunnelDefinitionRecord, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	edgeID = strings.TrimSpace(edgeID)
	tunnelID = strings.TrimSpace(tunnelID)
	if ownerUserID == "" || edgeID == "" || tunnelID == "" {
		return nil, nil
	}

	query := `
		SELECT id, edge_id, owner_user_id, tunnel_id, name, app_id, protocol,
			   intent_json, config_json, runtime_json, state,
			   actor_role, actor_session_id, actor_device_id,
			   version, revision,
			   created_at, updated_at, deleted_at, COALESCE(remote_url, '') AS remote_url
		FROM tunnel_definitions
		WHERE owner_user_id = ? AND edge_id = ? AND tunnel_id = ?
		LIMIT 1
	`
	return s.getOne(ctx, query, ownerUserID, edgeID, tunnelID)
}

// UpdateRuntimeSnapshotByEdgeAndTunnel updates runtime_json/state for all active
// records under the same edge+tunnel across owners. It is used by edge runtime
// projection and intentionally does not bump definition revision/version.
func (s *TunnelDefinitionStore) UpdateRuntimeSnapshotByEdgeAndTunnel(
	ctx context.Context,
	edgeID string,
	tunnelID string,
	runtimeJSON string,
	state string,
) (int64, error) {
	edgeID = strings.TrimSpace(edgeID)
	tunnelID = strings.TrimSpace(tunnelID)
	if edgeID == "" || tunnelID == "" {
		return 0, nil
	}

	runtimeJSON = normalizeJSON(runtimeJSON, "{}")
	state = normalizeState(state)
	updatedAt := time.Now().UnixMilli()

	result, err := s.db.ExecContext(
		ctx,
		`
		UPDATE tunnel_definitions
		SET runtime_json = ?, state = ?, updated_at = ?
		WHERE edge_id = ? AND tunnel_id = ? AND deleted_at IS NULL
		`,
		runtimeJSON,
		state,
		updatedAt,
		edgeID,
		tunnelID,
	)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rows, nil
}

func (s *TunnelDefinitionStore) ListByEdge(
	ctx context.Context,
	edgeID string,
	includeDeleted bool,
) ([]*TunnelDefinitionRecord, error) {
	edgeID = strings.TrimSpace(edgeID)
	if edgeID == "" {
		return []*TunnelDefinitionRecord{}, nil
	}

	query := `
		SELECT id, edge_id, owner_user_id, tunnel_id, name, app_id, protocol,
			   intent_json, config_json, runtime_json, state,
			   actor_role, actor_session_id, actor_device_id,
			   version, revision,
			   created_at, updated_at, deleted_at, COALESCE(remote_url, '') AS remote_url
		FROM tunnel_definitions
		WHERE edge_id = ?
	`
	if !includeDeleted {
		query += " AND deleted_at IS NULL"
	}
	query += " ORDER BY updated_at DESC"

	return s.list(ctx, query, edgeID)
}

func (s *TunnelDefinitionStore) CountActiveByEdge(ctx context.Context, edgeID string) (int, error) {
	edgeID = strings.TrimSpace(edgeID)
	if edgeID == "" {
		return 0, nil
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM tunnel_definitions
		WHERE edge_id = ? AND deleted_at IS NULL
	`, edgeID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *TunnelDefinitionStore) CountActiveByEdgeAndOwner(
	ctx context.Context,
	edgeID string,
	ownerUserID string,
) (int, error) {
	edgeID = strings.TrimSpace(edgeID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if edgeID == "" || ownerUserID == "" {
		return 0, nil
	}
	var count int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM tunnel_definitions
		WHERE edge_id = ? AND owner_user_id = ? AND deleted_at IS NULL
	`, edgeID, ownerUserID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *TunnelDefinitionStore) SoftDelete(
	ctx context.Context,
	ownerUserID string,
	edgeID string,
	tunnelID string,
	actorRole uint8,
	actorSessionID string,
	actorDeviceID string,
) (bool, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	edgeID = strings.TrimSpace(edgeID)
	tunnelID = strings.TrimSpace(tunnelID)
	actorRole = normalizeStoredActorRole(actorRole)
	actorSessionID = strings.TrimSpace(actorSessionID)
	actorDeviceID = strings.TrimSpace(actorDeviceID)
	if ownerUserID == "" || edgeID == "" || tunnelID == "" {
		return false, fmt.Errorf("owner_user_id/edge_id/tunnel_id are required")
	}

	changed := false
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var activeCount int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(1) FROM tunnel_definitions
			WHERE owner_user_id = ? AND edge_id = ? AND tunnel_id = ? AND deleted_at IS NULL
		`, ownerUserID, edgeID, tunnelID).Scan(&activeCount); err != nil {
			return err
		}
		if activeCount == 0 {
			return nil
		}

		nextRevision, err := s.nextRevisionTx(ctx, tx)
		if err != nil {
			return err
		}

		now := time.Now().UnixMilli()
		result, err := tx.ExecContext(ctx, `
			UPDATE tunnel_definitions
			SET deleted_at = ?, updated_at = ?, state = 'stopped',
				actor_role = CASE WHEN ? = 0 THEN actor_role ELSE ? END,
				actor_session_id = CASE WHEN TRIM(?) = '' THEN actor_session_id ELSE ? END,
				actor_device_id = CASE WHEN TRIM(?) = '' THEN actor_device_id ELSE ? END,
				version = version + 1,
				revision = ?
			WHERE owner_user_id = ? AND edge_id = ? AND tunnel_id = ? AND deleted_at IS NULL
		`,
			now,
			now,
			actorRole, actorRole,
			actorSessionID, actorSessionID,
			actorDeviceID, actorDeviceID,
			nextRevision,
			ownerUserID,
			edgeID,
			tunnelID,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		changed = affected > 0
		return nil
	})
	return changed, err
}

func (s *TunnelDefinitionStore) PurgeDeletedBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM tunnel_definitions
		WHERE deleted_at IS NOT NULL AND deleted_at < ?
	`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *TunnelDefinitionStore) Close() error {
	return s.db.Close()
}

func (s *TunnelDefinitionStore) CurrentRevision(ctx context.Context) (uint64, error) {
	var revision uint64
	if err := s.db.QueryRowContext(ctx, `
		SELECT current_revision
		FROM tunnel_definition_meta
		WHERE id = 1
	`).Scan(&revision); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return revision, nil
}

func (s *TunnelDefinitionStore) CurrentRevisionByOwnerAndEdge(
	ctx context.Context,
	ownerUserID string,
	edgeID string,
) (uint64, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	edgeID = strings.TrimSpace(edgeID)
	if ownerUserID == "" || edgeID == "" {
		return 0, nil
	}

	var revision uint64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(revision), 0)
		FROM tunnel_definitions
		WHERE owner_user_id = ? AND edge_id = ?
	`, ownerUserID, edgeID).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

func (s *TunnelDefinitionStore) ListChanges(
	ctx context.Context,
	ownerUserID string,
	edgeID string,
	sinceRevision uint64,
	limit uint32,
	includeDeleted bool,
) ([]*TunnelDefinitionRecord, uint64, bool, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	edgeID = strings.TrimSpace(edgeID)
	if ownerUserID == "" || edgeID == "" {
		return []*TunnelDefinitionRecord{}, sinceRevision, false, nil
	}

	pageSize := normalizeSyncLimit(limit)
	query := `
		SELECT id, edge_id, owner_user_id, tunnel_id, name, app_id, protocol,
			   intent_json, config_json, runtime_json, state,
			   actor_role, actor_session_id, actor_device_id,
			   version, revision,
			   created_at, updated_at, deleted_at, COALESCE(remote_url, '') AS remote_url
		FROM tunnel_definitions
		WHERE owner_user_id = ? AND edge_id = ? AND revision > ?
	`
	if !includeDeleted {
		query += " AND deleted_at IS NULL"
	}
	query += " ORDER BY revision ASC LIMIT ?"

	rows, err := s.db.QueryContext(ctx, query, ownerUserID, edgeID, sinceRevision, int(pageSize)+1)
	if err != nil {
		return nil, sinceRevision, false, err
	}
	defer rows.Close()

	changes := make([]*TunnelDefinitionRecord, 0, pageSize)
	for rows.Next() {
		rec, err := scanTunnelDefinitionRecord(rows)
		if err != nil {
			return nil, sinceRevision, false, err
		}
		changes = append(changes, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, sinceRevision, false, err
	}

	hasMore := len(changes) > int(pageSize)
	if hasMore {
		changes = changes[:pageSize]
	}

	nextRevision := sinceRevision
	if n := len(changes); n > 0 {
		nextRevision = uint64(changes[n-1].Revision)
	}
	if !hasMore {
		currentRevision, err := s.CurrentRevisionByOwnerAndEdge(ctx, ownerUserID, edgeID)
		if err != nil {
			return nil, sinceRevision, false, err
		}
		if currentRevision > nextRevision {
			nextRevision = currentRevision
		}
	}

	return changes, nextRevision, hasMore, nil
}

func (s *TunnelDefinitionStore) getOne(
	ctx context.Context,
	query string,
	args ...interface{},
) (*TunnelDefinitionRecord, error) {
	row := s.db.QueryRowContext(ctx, query, args...)
	rec, err := scanTunnelDefinitionRecord(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *TunnelDefinitionStore) list(
	ctx context.Context,
	query string,
	args ...interface{},
) ([]*TunnelDefinitionRecord, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]*TunnelDefinitionRecord, 0)
	for rows.Next() {
		rec, err := scanTunnelDefinitionRecord(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}

	return result, rows.Err()
}

func (s *TunnelDefinitionStore) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *TunnelDefinitionStore) nextRevisionTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	if _, err := tx.ExecContext(ctx, `
		UPDATE tunnel_definition_meta
		SET current_revision = current_revision + 1
		WHERE id = 1
	`); err != nil {
		return 0, err
	}

	var revision int64
	if err := tx.QueryRowContext(ctx, `
		SELECT current_revision
		FROM tunnel_definition_meta
		WHERE id = 1
	`).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

type sqlScanner interface {
	Scan(dest ...interface{}) error
}

func scanTunnelDefinitionRecord(scanner sqlScanner) (*TunnelDefinitionRecord, error) {
	rec := &TunnelDefinitionRecord{}
	var createdAtMs int64
	var updatedAtMs int64
	var deletedAt sql.NullInt64

	err := scanner.Scan(
		&rec.ID,
		&rec.EdgeID,
		&rec.OwnerUserID,
		&rec.TunnelID,
		&rec.Name,
		&rec.AppID,
		&rec.Protocol,
		&rec.IntentJSON,
		&rec.ConfigJSON,
		&rec.RuntimeJSON,
		&rec.State,
		&rec.ActorRole,
		&rec.ActorSessionID,
		&rec.ActorDeviceID,
		&rec.Version,
		&rec.Revision,
		&createdAtMs,
		&updatedAtMs,
		&deletedAt,
		&rec.RemoteURL,
	)
	if err != nil {
		return nil, err
	}

	rec.CreatedAt = time.UnixMilli(createdAtMs)
	rec.UpdatedAt = time.UnixMilli(updatedAtMs)
	if deletedAt.Valid {
		ts := time.UnixMilli(deletedAt.Int64)
		rec.DeletedAt = &ts
	}
	return rec, nil
}

func normalizeSyncLimit(limit uint32) uint32 {
	const (
		defaultLimit = 200
		maxLimit     = 1000
	)

	if limit == 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}
