package wireguard

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkStorageRoundTripsDeviceOwnership(t *testing.T) {
	store, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "networks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.(*sqliteStorage).Close()
	ctx := context.Background()
	created := time.Unix(1700000000, 0)
	network := &Network{
		ID: "device-owned", Name: "Local network", CIDR: "10.24.0.0/24",
		OwnerUserID: "device:paired-device", CoordinatorEdgeID: "paired-edge",
		RelayMode: RelayModeOptional, CreatedAt: created, UpdatedAt: created,
	}
	if err := store.SaveNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	network.Name = "Updated network"
	network.UpdatedAt = created.Add(time.Hour)
	if err := store.SaveNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.LoadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Networks) != 1 {
		t.Fatalf("networks = %d, want 1", len(snapshot.Networks))
	}
	got := snapshot.Networks[0]
	if got.Name != network.Name || got.OwnerUserID != network.OwnerUserID ||
		got.CoordinatorEdgeID != network.CoordinatorEdgeID || got.CIDR != network.CIDR ||
		got.RelayMode != network.RelayMode || !got.CreatedAt.Equal(created) ||
		!got.UpdatedAt.Equal(network.UpdatedAt) {
		t.Fatalf("stored network changed identity or content: %+v", got)
	}
}
