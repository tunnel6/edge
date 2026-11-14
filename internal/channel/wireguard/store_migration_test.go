package wireguard

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestLegacyMemberSchemaRestoresRelayIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE wg_members (
		member_id TEXT UNIQUE NOT NULL, network_id TEXT NOT NULL,
		client_id TEXT NOT NULL, assigned_ip TEXT NOT NULL, status TEXT NOT NULL,
		public_key TEXT, endpoint TEXT, joined_at INTEGER, last_seen_at INTEGER,
		left_at INTEGER, created_at INTEGER, updated_at INTEGER, deleted_at INTEGER
	)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"relay-net", "client-b"} {
		_, err = db.Exec(`INSERT INTO wg_members
		(member_id,network_id,client_id,assigned_ip,status,public_key,endpoint,joined_at,last_seen_at,created_at,updated_at)
		VALUES (?, 'net', ?, '10.24.0.2', 'online', 'pub', '198.51.100.1:12345', 1, 1, 1, 1)`, id, id)
		if err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewSQLiteStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*sqliteStorage).Close()
	if err := initSchema(store.(*sqliteStorage).db); err != nil {
		t.Fatalf("migration is not idempotent: %v", err)
	}
	snapshot, err := store.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Members) != 2 {
		t.Fatalf("members = %d", len(snapshot.Members))
	}
	for _, member := range snapshot.Members {
		if member.IsRelay != (member.ID == "relay-net") {
			t.Fatalf("wrong relay identity: %+v", member)
		}
		if !member.ObservedAt.IsZero() {
			t.Fatal("migration invented observation time")
		}
		if member.IsRelay && member.Endpoint != "198.51.100.1:12345" {
			t.Fatal("migration cleared configured relay listener")
		}
		if !member.IsRelay && member.Endpoint != "" {
			t.Fatal("migration retained an unverified legacy endpoint")
		}
		if err := store.UpdateMember(context.Background(), member); err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := store.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range reloaded.Members {
		if member.IsRelay != (member.ID == "relay-net") {
			t.Fatalf("lost relay identity: %+v", member)
		}
	}
}
