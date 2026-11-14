package cmd

import (
	"testing"

	"icool.io/yat/edge/pkg/config"
)

func TestManagementOverridesDeploymentBeforeCertificateBootstrap(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Node.PublicAddress = "old.example.test"
	managed, err := config.DecodeManagementConfig([]byte(`{"node":{"public_address":"saved.example.test"},"channel":{"custom_domain":"saved.example.test"},"tunnel":{"limits":{"max_total":0}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveManagementConfig(cfg.GetDataDir(), managed); err != nil {
		t.Fatal(err)
	}
	cfg.Tunnel.Limits.MaxTotal = 9
	edge, err := NewEdgeServer(cfg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if edge.config.Node.PublicAddress != "saved.example.test" || edge.config.Channel.GetCustomDomain() != "saved.example.test" || edge.config.GetTunnelMaxTotal() != 0 {
		t.Fatal("certificate bootstrap would use old deployment configuration")
	}
}
