package server

import (
	"testing"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
)

type stubStatusSource struct {
	status *channel.EdgeServiceStatus
}

func (s *stubStatusSource) GetStatus() *channel.EdgeServiceStatus {
	return s.status
}

func TestStatusManagerAdapterGetStatusMapsChannelFields(t *testing.T) {
	src := &stubStatusSource{
		status: &channel.EdgeServiceStatus{
			EdgeID:      "edge-1",
			Online:      true,
			Uptime:      123,
			LastUpdated: 456,
			Targets: []channel.TargetInfo{
				{
					ID:             "tun-1:tcp",
					Type:           "TCP",
					SessionID:      "sess-1",
					UserID:         "user-1",
					DeviceID:       "dev-1",
					ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
					ActorSessionID: "actor-sess-1",
					ActorDeviceID:  "actor-dev-1",
					Domain:         "tcp.edge.example.com",
					Subdomain:      "tcp",
					AliasDomain:    "db.example.com",
					Port:           32000,
					LocalAddr:      "127.0.0.1:3306",
					State:          "active",
					BytesIn:        100,
					BytesOut:       200,
					Connections:    3,
					ActiveConns:    2,
					Requests:       5,
					CreatedAt:      111,
					ChannelKey:     "db",
					Protocol:       "tcp",
					LinkType:       "p2p",
					RemoteEndpoint: "tcp.edge.example.com:32000",
				},
			},
			Stats: channel.ServiceStats{
				TotalSessions:    10,
				ActiveSessions:   2,
				TotalTargets:     20,
				ActiveTargets:    5,
				TotalBytesIn:     1000,
				TotalBytesOut:    2000,
				TotalConnections: 30,
				TotalRequests:    40,
				TotalErrors:      1,
			},
		},
	}

	adapter := &statusManagerAdapter{source: src}
	got := adapter.GetStatus()
	if got == nil {
		t.Fatalf("expected status, got nil")
	}

	if got.EdgeID != "edge-1" || !got.Online || got.Uptime != 123 || got.LastUpdated != 456 {
		t.Fatalf("status header mismatch: %+v", got)
	}

	if len(got.Channels) != 1 {
		t.Fatalf("channel count mismatch: got=%d want=1", len(got.Channels))
	}

	ch := got.Channels[0]
	if ch.ID != "tun-1:tcp" {
		t.Fatalf("channel id mismatch: got=%q", ch.ID)
	}
	if ch.Type != uint8(fbMsg.ChannelTypeTCP) {
		t.Fatalf("channel type mismatch: got=%d want=%d", ch.Type, uint8(fbMsg.ChannelTypeTCP))
	}
	if ch.ActorRole != uint8(fbMsg.TunnelActorRoleCONSUMER) {
		t.Fatalf("actor role mismatch: got=%d want=%d", ch.ActorRole, uint8(fbMsg.TunnelActorRoleCONSUMER))
	}
	if ch.Subdomain != "tcp" || ch.ChannelKey != "db" || ch.Protocol != "tcp" {
		t.Fatalf("channel identity fields mismatch: %+v", ch)
	}
	if ch.LinkType != "p2p" || ch.RemoteEndpoint != "tcp.edge.example.com:32000" {
		t.Fatalf("channel path fields mismatch: link=%q remote=%q", ch.LinkType, ch.RemoteEndpoint)
	}
	if ch.State != "active" || ch.ActiveConns != 2 || ch.Connections != 3 {
		t.Fatalf("channel runtime fields mismatch: state=%q active=%d total=%d", ch.State, ch.ActiveConns, ch.Connections)
	}

	if got.Stats.TotalChannels != 20 || got.Stats.ActiveChannels != 5 {
		t.Fatalf("stats channel counters mismatch: %+v", got.Stats)
	}
	if got.Stats.TotalErrors != 1 || got.Stats.TotalConnections != 30 || got.Stats.TotalRequests != 40 {
		t.Fatalf("stats totals mismatch: %+v", got.Stats)
	}
}

func TestStatusManagerAdapterGetStatusNilSafety(t *testing.T) {
	adapter := &statusManagerAdapter{}
	if got := adapter.GetStatus(); got != nil {
		t.Fatalf("expected nil status for nil source")
	}

	adapter = &statusManagerAdapter{source: &stubStatusSource{status: nil}}
	if got := adapter.GetStatus(); got != nil {
		t.Fatalf("expected nil status for nil upstream status")
	}
}
