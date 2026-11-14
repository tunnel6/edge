package server

import (
	"strings"
	"testing"

	"icool.io/yat/edge/pkg/config"
)

func TestNewServerReturnsErrorWhenCertificateBundleIsNil(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Channel.DomainConfig = *config.NewDomainConfig(cfg.GetDataDir())
	config.NormalizeConfig(cfg)

	_, err := NewServer(cfg, nil)
	if err == nil {
		t.Fatal("expected error for nil certificate bundle")
	}
	if !strings.Contains(err.Error(), "certificate bundle is nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveWireGuardRelaySettingsFallsBackToNodePublicAddress(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Node.PublicAddress = "edge.example.com"
	cfg.Proxy.WireGuard.RelayEnabled = true
	cfg.Proxy.WireGuard.InterfacePrefix = "wg-yat0"
	cfg.Proxy.WireGuard.ListenPortBase = 58021
	cfg.Proxy.WireGuard.KeyDir = "/var/lib/edge/wireguard"
	cfg.Proxy.WireGuard.PublicEndpoint = ""

	relayEnabled, interfacePrefix, listenPortBase, keyDir, publicEndpoint, _, _, _ :=
		resolveWireGuardRelaySettings(cfg, defaultServerOptions())

	if !relayEnabled {
		t.Fatal("expected relay to remain enabled")
	}
	if interfacePrefix != "wg-yat0" {
		t.Fatalf("interfacePrefix = %q, want %q", interfacePrefix, "wg-yat0")
	}
	if listenPortBase != 58021 {
		t.Fatalf("listenPortBase = %d, want %d", listenPortBase, 58021)
	}
	if keyDir != "/var/lib/edge/wireguard" {
		t.Fatalf("keyDir = %q, want %q", keyDir, "/var/lib/edge/wireguard")
	}
	if publicEndpoint != "edge.example.com" {
		t.Fatalf("publicEndpoint = %q, want node public address fallback", publicEndpoint)
	}
}

func TestResolveWireGuardRelaySettingsPrefersExplicitPublicEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Node.PublicAddress = "edge.example.com"
	cfg.Proxy.WireGuard.RelayEnabled = true
	cfg.Proxy.WireGuard.PublicEndpoint = "wg.example.com"

	override := "override.example.com"
	opts := defaultServerOptions()
	opts.nodePublicAddress = &override

	_, _, _, _, publicEndpoint, _, _, _ := resolveWireGuardRelaySettings(cfg, opts)
	if publicEndpoint != "wg.example.com" {
		t.Fatalf("publicEndpoint = %q, want explicit wireguard endpoint", publicEndpoint)
	}
}
