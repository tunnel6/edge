package channel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
)

func TestChannelStoreSave_UpdatesTypeOnConflict(t *testing.T) {
	store, err := NewChannelStore(filepath.Join(t.TempDir(), "channels.db"))
	if err != nil {
		t.Fatalf("NewChannelStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	channelID := "tunnel-1:tcp-main"

	initial := &ChannelRecord{
		ChannelID:    channelID,
		SessionID:    "session-1",
		Type:         fbMsg.ChannelTypeUDP,
		LocalAddr:    "127.0.0.1:22",
		Port:         31001,
		Subdomain:    "",
		AliasDomain:  "",
		CreatedAt:    time.Now().Add(-time.Minute),
		LastActiveAt: time.Now().Add(-time.Minute),
	}
	if err := store.Save(ctx, initial); err != nil {
		t.Fatalf("initial Save failed: %v", err)
	}

	updated := &ChannelRecord{
		ChannelID:    channelID,
		SessionID:    "session-2",
		Type:         fbMsg.ChannelTypeTCP,
		LocalAddr:    "127.0.0.1:2222",
		Port:         32002,
		Subdomain:    "",
		AliasDomain:  "",
		CreatedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}
	if err := store.Save(ctx, updated); err != nil {
		t.Fatalf("updated Save failed: %v", err)
	}

	got, err := store.Get(ctx, channelID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if got == nil {
		t.Fatalf("Get returned nil")
	}

	if got.Type != fbMsg.ChannelTypeTCP {
		t.Fatalf("expected type TCP(%d), got %d", fbMsg.ChannelTypeTCP, got.Type)
	}
	if got.SessionID != "session-2" {
		t.Fatalf("expected session_id session-2, got %s", got.SessionID)
	}
	if got.LocalAddr != "127.0.0.1:2222" {
		t.Fatalf("expected local_addr 127.0.0.1:2222, got %s", got.LocalAddr)
	}
	if got.Port != 32002 {
		t.Fatalf("expected port 32002, got %d", got.Port)
	}
}
