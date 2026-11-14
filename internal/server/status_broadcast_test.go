package server

import (
	"reflect"
	"testing"

	"icool.io/yat/edge/internal/channel"
	"icool.io/yat/edge/pkg/config"
)

func TestPeriodicBroadcastRetainsConfiguredCapabilities(t *testing.T) {
	hub := NewPushBroadcaster(8)
	server := &Server{broadcaster: hub, config: &config.Config{Proxy: config.ProxyConfig{
		HTTP: &config.HTTPProxyConfig{Enabled: true, Port: 18080, HTTPSPort: 18443},
		TCP:  &config.TCPProxyConfig{Enabled: true, PortMin: 22000, PortMax: 23000},
	}}}
	events, _ := hub.Subscribe("test-session", 1, nil)
	server.broadcastStatusToSessions(&channel.EdgeServiceStatus{EdgeID: "edge-a", Online: true, LastUpdated: 1_700_000_000})
	select {
	case event := <-events:
		if event.projectEdgeStatus == nil {
			t.Fatal("broadcast bypassed the per-session status projection")
		}
		status := event.projectEdgeStatus(&Session{ID: "test-session", UserID: "device:test", DeviceID: "test"})
		if status.Timestamp != 1_700_000_000_000 {
			t.Fatalf("replayed snapshot timestamp changed: %d", status.Timestamp)
		}
		if !reflect.DeepEqual(status.SupportedProtocols, []string{"http", "https", "tcp"}) {
			t.Fatalf("periodic push lost capabilities: %v", status.SupportedProtocols)
		}
		if status.PortUsage.HTTPPort != 18080 || status.PortUsage.HTTPSPort != 18443 || status.PortUsage.TCPRange != "22000-23000" {
			t.Fatalf("periodic push lost configured ports: %+v", status.PortUsage)
		}
	default:
		t.Fatal("no periodic status published")
	}
}
