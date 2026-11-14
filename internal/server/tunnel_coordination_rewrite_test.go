package server

import (
	"encoding/json"
	"testing"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	"icool.io/yat/edge/internal/channel"
)

func requirePeerSessionsPayload(t *testing.T, payload map[string]any, wantCount int) {
	t.Helper()

	if got := int(payload["peerSessionsVersion"].(float64)); got != 2 {
		t.Fatalf("peerSessionsVersion = %d, want 2", got)
	}
	sessions, ok := payload["peerSessions"].([]any)
	if !ok {
		t.Fatalf("peerSessions type = %T, want []any", payload["peerSessions"])
	}
	if len(sessions) != wantCount {
		t.Fatalf("peerSessions length = %d, want %d", len(sessions), wantCount)
	}
}

func requireObservedConsumerDataPath(
	t *testing.T,
	sessionItems []any,
) (map[string]any, map[string]any, map[string]any) {
	t.Helper()

	if len(sessionItems) != 1 {
		t.Fatalf("session count = %d, want 1", len(sessionItems))
	}
	sessionObj, ok := sessionItems[0].(map[string]any)
	if !ok {
		t.Fatalf("session item type = %T, want map[string]any", sessionItems[0])
	}
	consumers, ok := sessionObj["consumers"].([]any)
	if !ok {
		t.Fatalf("consumers type = %T, want []any", sessionObj["consumers"])
	}
	if len(consumers) != 1 {
		t.Fatalf("consumer count = %d, want 1", len(consumers))
	}
	consumerObj, ok := consumers[0].(map[string]any)
	if !ok {
		t.Fatalf("consumer item type = %T, want map[string]any", consumers[0])
	}
	dataPath, ok := consumerObj["dataPath"].(map[string]any)
	if !ok {
		t.Fatalf("dataPath type = %T, want map[string]any", consumerObj["dataPath"])
	}
	return sessionObj, consumerObj, dataPath
}

func TestRewritePeerSessionsInJSONPathRewritesTopLevelObject(t *testing.T) {
	raw := `{"peerSessions":[{"id":"legacy"}],"peerSessionsVersion":1}`

	rewritten, changed := rewritePeerSessionsInJSONPath(raw, nil, nil)
	if !changed {
		t.Fatal("expected top-level peerSessions rewrite to report changed")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(rewritten), &payload); err != nil {
		t.Fatalf("unmarshal rewritten payload: %v", err)
	}

	requirePeerSessionsPayload(t, payload, 0)
}

func TestRewritePeerSessionsInJSONPathRewritesNestedRuntimeObject(t *testing.T) {
	raw := `{"runtime":{"peerSessions":[{"id":"legacy"}],"peerSessionsVersion":1},"name":"demo"}`

	rewritten, changed := rewritePeerSessionsInJSONPath(raw, nil, nil, "runtime")
	if !changed {
		t.Fatal("expected nested runtime peerSessions rewrite to report changed")
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(rewritten), &payload); err != nil {
		t.Fatalf("unmarshal rewritten payload: %v", err)
	}

	runtimePayload, ok := payload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("runtime type = %T, want map[string]any", payload["runtime"])
	}
	requirePeerSessionsPayload(t, runtimePayload, 0)
}

func TestRewritePeerSessionsInJSONPathSkipsMissingNestedObject(t *testing.T) {
	raw := `{"name":"demo"}`

	rewritten, changed := rewritePeerSessionsInJSONPath(raw, nil, nil, "runtime")
	if changed {
		t.Fatal("expected missing runtime object to skip rewrite")
	}
	if rewritten != raw {
		t.Fatalf("rewritten payload changed unexpectedly: %q", rewritten)
	}
}

func TestBuildObservedPeerSessionsV2PrefersEdgeDirectEndpoint(t *testing.T) {
	observed := []channel.TunnelObservedChannel{
		{
			ChannelID:      "tun-1:publisher:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			ActorRole:      uint8(fbMsg.TunnelActorRolePUBLISHER),
			SessionID:      "transport-pub",
			ActorSessionID: "publisher-session",
			ActorDeviceID:  "device-publisher",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "p2p",
			RemoteEndpoint: "198.51.100.10:51820",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
	}

	sessionItems := buildObservedPeerSessionsV2(observed, map[string]string{
		"consumer-session": "203.0.113.20:6000",
	})
	sessionObj, consumerObj, dataPath := requireObservedConsumerDataPath(t, sessionItems)

	if got := consumerObj["state"]; got != "active" {
		t.Fatalf("consumer state = %v, want active", got)
	}
	if got := dataPath["type"]; got != "p2p" {
		t.Fatalf("dataPath.type = %v, want p2p", got)
	}
	if got := dataPath["pathKind"]; got != "direct" {
		t.Fatalf("dataPath.pathKind = %v, want direct", got)
	}
	if got, ok := dataPath["linkTypes"].([]any); !ok || len(got) != 1 || got[0] != "p2p" {
		t.Fatalf("dataPath.linkTypes = %v, want [p2p]", dataPath["linkTypes"])
	}
	if got := dataPath["state"]; got != "connected" {
		t.Fatalf("dataPath.state = %v, want connected", got)
	}
	if got := dataPath["endpoint"]; got != "203.0.113.20:6000" {
		t.Fatalf("dataPath.endpoint = %v, want edge-observed direct endpoint", got)
	}
	if got := sessionObj["id"]; got != "publisher-session" {
		t.Fatalf("session id = %v, want publisher-session", got)
	}
}

func TestBuildObservedPeerSessionsV2DowngradesDirectPathWithoutObservedEndpoint(t *testing.T) {
	observed := []channel.TunnelObservedChannel{
		{
			ChannelID:      "tun-1:publisher:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			ActorRole:      uint8(fbMsg.TunnelActorRolePUBLISHER),
			SessionID:      "transport-pub",
			ActorSessionID: "publisher-session",
			ActorDeviceID:  "device-publisher",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "wireguard",
			RemoteEndpoint: "198.51.100.10:51820",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
	}

	sessionObj, consumerObj, dataPath := requireObservedConsumerDataPath(t, buildObservedPeerSessionsV2(observed, nil))

	if got := consumerObj["state"]; got != "negotiating" {
		t.Fatalf("consumer state = %v, want negotiating", got)
	}
	if got := dataPath["type"]; got != "wireguard" {
		t.Fatalf("dataPath.type = %v, want wireguard", got)
	}
	if got := dataPath["pathKind"]; got != "direct" {
		t.Fatalf("dataPath.pathKind = %v, want direct", got)
	}
	if got, ok := dataPath["linkTypes"].([]any); !ok || len(got) != 1 || got[0] != "wireguard" {
		t.Fatalf("dataPath.linkTypes = %v, want [wireguard]", dataPath["linkTypes"])
	}
	if got := dataPath["state"]; got != "negotiating" {
		t.Fatalf("dataPath.state = %v, want negotiating", got)
	}
	if _, exists := dataPath["endpoint"]; exists {
		t.Fatalf("dataPath.endpoint should be omitted when edge direct endpoint is unavailable, got %v", dataPath["endpoint"])
	}

	summary, ok := sessionObj["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary type = %T, want map[string]any", sessionObj["summary"])
	}
	if got, ok := summary["state"].(string); !ok || got != "negotiating" {
		t.Fatalf("summary.state = %v, want negotiating", summary["state"])
	}
	if got, ok := summary["connectedCount"].(int); !ok || got != 0 {
		t.Fatalf("summary.connectedCount = %v, want 0", summary["connectedCount"])
	}
	if got, ok := summary["negotiatingCount"].(int); !ok || got != 1 {
		t.Fatalf("summary.negotiatingCount = %v, want 1", summary["negotiatingCount"])
	}
}

func TestBuildObservedPeerSessionsV2KeepsMixedRelayCanonicalWithEdgeDirectEndpoint(t *testing.T) {
	observed := []channel.TunnelObservedChannel{
		{
			ChannelID:      "tun-1:publisher:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			RemoteEndpoint: "relay.edge.example.com:32001",
			ActorRole:      uint8(fbMsg.TunnelActorRolePUBLISHER),
			SessionID:      "transport-pub",
			ActorSessionID: "publisher-session",
			ActorDeviceID:  "device-publisher",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			RemoteEndpoint: "relay.edge.example.com:32001",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer-relay",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:udp-main",
			ChannelKey:     "udp-main",
			LinkType:       "wireguard",
			RemoteEndpoint: "198.51.100.10:51820",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer-direct",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
	}

	sessionObj, consumerObj, dataPath := requireObservedConsumerDataPath(t, buildObservedPeerSessionsV2(observed, map[string]string{
		"consumer-session": "203.0.113.20:6000",
	}))

	if got := consumerObj["state"]; got != "active" {
		t.Fatalf("consumer state = %v, want active", got)
	}
	if got := dataPath["type"]; got != "relay" {
		t.Fatalf("dataPath.type = %v, want relay", got)
	}
	if got := dataPath["pathKind"]; got != "mixed" {
		t.Fatalf("dataPath.pathKind = %v, want mixed", got)
	}
	if got, ok := dataPath["linkTypes"].([]any); !ok || len(got) != 2 || got[0] != "relay" || got[1] != "wireguard" {
		t.Fatalf("dataPath.linkTypes = %v, want [relay wireguard]", dataPath["linkTypes"])
	}
	if got := dataPath["state"]; got != "connected" {
		t.Fatalf("dataPath.state = %v, want connected", got)
	}
	if got := dataPath["endpoint"]; got != "203.0.113.20:6000" {
		t.Fatalf("dataPath.endpoint = %v, want edge-observed direct endpoint", got)
	}
	channelEndpoints, ok := dataPath["channelEndpoints"].(map[string]any)
	if !ok {
		t.Fatalf("dataPath.channelEndpoints type = %T, want map[string]any", dataPath["channelEndpoints"])
	}
	if got := channelEndpoints["tcp-main"]; got != "relay.edge.example.com:32001" {
		t.Fatalf("channelEndpoints[tcp-main] = %v, want relay.edge.example.com:32001", got)
	}
	if _, exists := channelEndpoints["udp-main"]; exists {
		t.Fatalf("channelEndpoints should omit direct-like udp-main entry, got %v", channelEndpoints["udp-main"])
	}

	summary, ok := sessionObj["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary type = %T, want map[string]any", sessionObj["summary"])
	}
	if got, ok := summary["state"].(string); !ok || got != "active" {
		t.Fatalf("summary.state = %v, want active", summary["state"])
	}
	if got, ok := summary["connectedCount"].(int); !ok || got != 1 {
		t.Fatalf("summary.connectedCount = %v, want 1", summary["connectedCount"])
	}
}

func TestBuildObservedPeerSessionsV2KeepsMixedRelayConnectedWithoutObservedDirectEndpoint(t *testing.T) {
	observed := []channel.TunnelObservedChannel{
		{
			ChannelID:      "tun-1:publisher:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			RemoteEndpoint: "relay.edge.example.com:32001",
			ActorRole:      uint8(fbMsg.TunnelActorRolePUBLISHER),
			SessionID:      "transport-pub",
			ActorSessionID: "publisher-session",
			ActorDeviceID:  "device-publisher",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:tcp-main",
			ChannelKey:     "tcp-main",
			LinkType:       "relay",
			RemoteEndpoint: "relay.edge.example.com:32001",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer-relay",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
		{
			ChannelID:      "tun-1:consumer:udp-main",
			ChannelKey:     "udp-main",
			LinkType:       "p2p",
			RemoteEndpoint: "198.51.100.10:51820",
			ActorRole:      uint8(fbMsg.TunnelActorRoleCONSUMER),
			SessionID:      "transport-consumer-direct",
			ActorSessionID: "consumer-session",
			ActorDeviceID:  "device-consumer",
			State:          "active",
		},
	}

	sessionObj, consumerObj, dataPath := requireObservedConsumerDataPath(t, buildObservedPeerSessionsV2(observed, nil))

	if got := consumerObj["state"]; got != "active" {
		t.Fatalf("consumer state = %v, want active", got)
	}
	if got := dataPath["type"]; got != "relay" {
		t.Fatalf("dataPath.type = %v, want relay", got)
	}
	if got := dataPath["pathKind"]; got != "mixed" {
		t.Fatalf("dataPath.pathKind = %v, want mixed", got)
	}
	if got := dataPath["state"]; got != "connected" {
		t.Fatalf("dataPath.state = %v, want connected", got)
	}
	if _, exists := dataPath["endpoint"]; exists {
		t.Fatalf("dataPath.endpoint should be omitted without observed direct endpoint, got %v", dataPath["endpoint"])
	}
	channelEndpoints, ok := dataPath["channelEndpoints"].(map[string]any)
	if !ok {
		t.Fatalf("dataPath.channelEndpoints type = %T, want map[string]any", dataPath["channelEndpoints"])
	}
	if got := channelEndpoints["tcp-main"]; got != "relay.edge.example.com:32001" {
		t.Fatalf("channelEndpoints[tcp-main] = %v, want relay.edge.example.com:32001", got)
	}

	summary, ok := sessionObj["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary type = %T, want map[string]any", sessionObj["summary"])
	}
	if got, ok := summary["state"].(string); !ok || got != "active" {
		t.Fatalf("summary.state = %v, want active", summary["state"])
	}
	if got, ok := summary["negotiatingCount"].(int); !ok || got != 0 {
		t.Fatalf("summary.negotiatingCount = %v, want 0", summary["negotiatingCount"])
	}
}

func TestRewriteTunnelPeerSessionsFromEdgeObservationClearsStaleSessionsWithoutObservedChannels(t *testing.T) {
	server := &Server{
		channelMgr: &channel.ChannelManager{},
	}
	rec := &channel.TunnelDefinitionRecord{
		TunnelID:    "tun-1",
		RuntimeJSON: `{"peerSessions":[{"id":"legacy"}],"peerSessionsVersion":1}`,
		ConfigJSON:  `{"runtime":{"peerSessions":[{"id":"legacy"}],"peerSessionsVersion":1}}`,
	}

	changed := server.rewriteTunnelPeerSessionsFromEdgeObservation(rec)
	if !changed {
		t.Fatal("expected stale peerSessions to be cleared when edge has no observed channels")
	}

	var runtimePayload map[string]any
	if err := json.Unmarshal([]byte(rec.RuntimeJSON), &runtimePayload); err != nil {
		t.Fatalf("unmarshal runtime payload: %v", err)
	}
	requirePeerSessionsPayload(t, runtimePayload, 0)

	var configPayload map[string]any
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &configPayload); err != nil {
		t.Fatalf("unmarshal config payload: %v", err)
	}
	runtimeConfig, ok := configPayload["runtime"].(map[string]any)
	if !ok {
		t.Fatalf("config runtime type = %T, want map[string]any", configPayload["runtime"])
	}
	requirePeerSessionsPayload(t, runtimeConfig, 0)
}
