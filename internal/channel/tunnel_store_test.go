package channel

import (
	"context"
	"path/filepath"
	"testing"
)

func TestResolveTunnelRemoteURL(t *testing.T) {
	tests := []struct {
		name        string
		remoteURL   string
		runtimeJSON string
		want        string
	}{
		{
			name:        "prefer explicit remote url",
			remoteURL:   "https://explicit.example.com",
			runtimeJSON: `{"remoteUrl":"https://runtime.example.com"}`,
			want:        "https://explicit.example.com",
		},
		{
			name:        "extract remoteUrl from runtime",
			remoteURL:   "",
			runtimeJSON: `{"remoteUrl":"https://runtime.example.com"}`,
			want:        "https://runtime.example.com",
		},
		{
			name:        "extract snake remote_url from runtime",
			remoteURL:   "",
			runtimeJSON: `{"remote_url":"https://runtime.example.com"}`,
			want:        "https://runtime.example.com",
		},
		{
			name:        "extract bestUrl from runtime",
			remoteURL:   "",
			runtimeJSON: `{"bestUrl":"https://best.example.com"}`,
			want:        "https://best.example.com",
		},
		{
			name:        "invalid runtime json",
			remoteURL:   "",
			runtimeJSON: `{"remoteUrl":`,
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveTunnelRemoteURL(tt.remoteURL, tt.runtimeJSON)
			if got != tt.want {
				t.Fatalf("ResolveTunnelRemoteURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTunnelDefinitionStoreUpsert_PreservesExistingRemoteURLWhenIncomingEmpty(t *testing.T) {
	store, err := NewTunnelDefinitionStore(filepath.Join(t.TempDir(), "tunnels.db"))
	if err != nil {
		t.Fatalf("NewTunnelDefinitionStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	edgeID := "edge-1"
	tunnelID := "tunnel-1"

	initial := &TunnelDefinitionRecord{
		EdgeID:      edgeID,
		OwnerUserID: "user-1",
		TunnelID:    tunnelID,
		Name:        "demo",
		AppID:       "app-http-proxy",
		Protocol:    "http",
		IntentJSON:  "{}",
		ConfigJSON:  "{}",
		RuntimeJSON: `{"remoteUrl":"https://runtime.example.com"}`,
		State:       "active",
	}
	if err := store.Upsert(ctx, initial); err != nil {
		t.Fatalf("initial Upsert failed: %v", err)
	}

	first, err := store.Get(ctx, "user-1", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get after initial Upsert failed: %v", err)
	}
	if first == nil {
		t.Fatalf("Get after initial Upsert returned nil")
	}
	if first.RemoteURL != "https://runtime.example.com" {
		t.Fatalf("expected first remote_url %q, got %q", "https://runtime.example.com", first.RemoteURL)
	}

	// simulate a later upsert whose runtime payload does not carry remoteUrl
	next := &TunnelDefinitionRecord{
		EdgeID:      edgeID,
		OwnerUserID: "user-1",
		TunnelID:    tunnelID,
		Name:        "demo",
		AppID:       "app-http-proxy",
		Protocol:    "http",
		IntentJSON:  "{}",
		ConfigJSON:  "{}",
		RuntimeJSON: `{"status":"inactive"}`,
		State:       "inactive",
		RemoteURL:   "",
	}
	if err := store.Upsert(ctx, next); err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}

	got, err := store.Get(ctx, "user-1", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get after second Upsert failed: %v", err)
	}
	if got == nil {
		t.Fatalf("Get after second Upsert returned nil")
	}
	if got.RemoteURL != "https://runtime.example.com" {
		t.Fatalf("expected preserved remote_url %q, got %q", "https://runtime.example.com", got.RemoteURL)
	}
}

func TestTunnelDefinitionStoreUpsert_RequiresOwner(t *testing.T) {
	store, err := NewTunnelDefinitionStore(filepath.Join(t.TempDir(), "tunnels.db"))
	if err != nil {
		t.Fatalf("NewTunnelDefinitionStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	err = store.Upsert(context.Background(), &TunnelDefinitionRecord{
		EdgeID:      "edge-1",
		OwnerUserID: "",
		TunnelID:    "tunnel-1",
		Name:        "demo",
		AppID:       "app-http-proxy",
		Protocol:    "http",
		IntentJSON:  "{}",
		ConfigJSON:  "{}",
		RuntimeJSON: "{}",
		State:       "active",
	})
	if err == nil {
		t.Fatalf("expected owner_user_id validation error")
	}
}

func TestTunnelDefinitionStoreOwnerScopeIsolation(t *testing.T) {
	store, err := NewTunnelDefinitionStore(filepath.Join(t.TempDir(), "tunnels.db"))
	if err != nil {
		t.Fatalf("NewTunnelDefinitionStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	edgeID := "edge-1"
	tunnelID := "same-tunnel-id"

	ownerA := &TunnelDefinitionRecord{
		EdgeID:      edgeID,
		OwnerUserID: "owner-a",
		TunnelID:    tunnelID,
		Name:        "owner-a-name",
		AppID:       "app-http-proxy",
		Protocol:    "http",
		IntentJSON:  "{}",
		ConfigJSON:  "{}",
		RuntimeJSON: "{}",
		State:       "active",
	}
	if err := store.Upsert(ctx, ownerA); err != nil {
		t.Fatalf("owner A Upsert failed: %v", err)
	}

	ownerB := &TunnelDefinitionRecord{
		EdgeID:      edgeID,
		OwnerUserID: "owner-b",
		TunnelID:    tunnelID,
		Name:        "owner-b-name",
		AppID:       "app-http-proxy",
		Protocol:    "http",
		IntentJSON:  "{}",
		ConfigJSON:  "{}",
		RuntimeJSON: "{}",
		State:       "active",
	}
	if err := store.Upsert(ctx, ownerB); err != nil {
		t.Fatalf("owner B Upsert failed: %v", err)
	}

	gotA, err := store.Get(ctx, "owner-a", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get owner A failed: %v", err)
	}
	if gotA == nil || gotA.Name != "owner-a-name" {
		t.Fatalf("owner A record mismatch: %#v", gotA)
	}

	gotB, err := store.Get(ctx, "owner-b", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get owner B failed: %v", err)
	}
	if gotB == nil || gotB.Name != "owner-b-name" {
		t.Fatalf("owner B record mismatch: %#v", gotB)
	}

	changesA, nextA, hasMoreA, err := store.ListChanges(ctx, "owner-a", edgeID, 0, 50, true)
	if err != nil {
		t.Fatalf("ListChanges owner A failed: %v", err)
	}
	if hasMoreA {
		t.Fatalf("expected hasMoreA=false")
	}
	if len(changesA) != 1 || changesA[0].OwnerUserID != "owner-a" {
		t.Fatalf("unexpected owner A changes: %#v", changesA)
	}
	if nextA != uint64(changesA[0].Revision) {
		t.Fatalf("owner A next revision mismatch: got=%d want=%d", nextA, changesA[0].Revision)
	}

	changed, err := store.SoftDelete(ctx, "owner-a", edgeID, tunnelID, 1, "session-a", "device-a")
	if err != nil {
		t.Fatalf("SoftDelete owner A failed: %v", err)
	}
	if !changed {
		t.Fatalf("expected owner A soft delete changed=true")
	}

	stillB, err := store.Get(ctx, "owner-b", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get owner B after owner A delete failed: %v", err)
	}
	if stillB == nil {
		t.Fatalf("owner B record missing after owner A delete")
	}
	if stillB.DeletedAt != nil {
		t.Fatalf("owner B record should stay active after owner A delete")
	}
}

func TestTunnelDefinitionStoreUpdateRuntimeSnapshotByEdgeAndTunnel(t *testing.T) {
	store, err := NewTunnelDefinitionStore(filepath.Join(t.TempDir(), "tunnels.db"))
	if err != nil {
		t.Fatalf("NewTunnelDefinitionStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	edgeID := "edge-1"
	tunnelID := "tunnel-1"

	records := []*TunnelDefinitionRecord{
		{
			EdgeID:      edgeID,
			OwnerUserID: "owner-a",
			TunnelID:    tunnelID,
			Name:        "demo-a",
			AppID:       "app-http-proxy",
			Protocol:    "tcp",
			IntentJSON:  "{}",
			ConfigJSON:  "{}",
			RuntimeJSON: `{"old":"a"}`,
			State:       "inactive",
		},
		{
			EdgeID:      edgeID,
			OwnerUserID: "owner-b",
			TunnelID:    tunnelID,
			Name:        "demo-b",
			AppID:       "app-http-proxy",
			Protocol:    "tcp",
			IntentJSON:  "{}",
			ConfigJSON:  "{}",
			RuntimeJSON: `{"old":"b"}`,
			State:       "inactive",
		},
		{
			EdgeID:      edgeID,
			OwnerUserID: "owner-a",
			TunnelID:    "another-tunnel",
			Name:        "demo-c",
			AppID:       "app-http-proxy",
			Protocol:    "tcp",
			IntentJSON:  "{}",
			ConfigJSON:  "{}",
			RuntimeJSON: `{"old":"c"}`,
			State:       "inactive",
		},
	}
	for _, rec := range records {
		if err := store.Upsert(ctx, rec); err != nil {
			t.Fatalf("Upsert %s/%s failed: %v", rec.OwnerUserID, rec.TunnelID, err)
		}
	}

	rows, err := store.UpdateRuntimeSnapshotByEdgeAndTunnel(
		ctx,
		edgeID,
		tunnelID,
		`{"peers":[{"id":"ice:tunnel-1:1"}]}`,
		"active",
	)
	if err != nil {
		t.Fatalf("UpdateRuntimeSnapshotByEdgeAndTunnel failed: %v", err)
	}
	if rows != 2 {
		t.Fatalf("expected 2 updated rows for same edge+tunnel, got %d", rows)
	}

	gotA, err := store.Get(ctx, "owner-a", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get owner-a failed: %v", err)
	}
	if gotA == nil || gotA.State != "active" || gotA.RuntimeJSON != `{"peers":[{"id":"ice:tunnel-1:1"}]}` {
		t.Fatalf("owner-a runtime snapshot mismatch: %#v", gotA)
	}

	gotB, err := store.Get(ctx, "owner-b", edgeID, tunnelID)
	if err != nil {
		t.Fatalf("Get owner-b failed: %v", err)
	}
	if gotB == nil || gotB.State != "active" || gotB.RuntimeJSON != `{"peers":[{"id":"ice:tunnel-1:1"}]}` {
		t.Fatalf("owner-b runtime snapshot mismatch: %#v", gotB)
	}

	other, err := store.Get(ctx, "owner-a", edgeID, "another-tunnel")
	if err != nil {
		t.Fatalf("Get unaffected tunnel failed: %v", err)
	}
	if other == nil {
		t.Fatalf("expected unaffected tunnel record")
	}
	if other.RuntimeJSON != `{"old":"c"}` || other.State != "inactive" {
		t.Fatalf("unrelated tunnel should not be updated: %#v", other)
	}
}
