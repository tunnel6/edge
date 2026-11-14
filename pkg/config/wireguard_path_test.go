package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestWireGuardPathConfigurationIsExplicitAndDecodesDurations(t *testing.T) {
	defaults := DefaultConfig()
	if defaults.Proxy.WireGuard != nil && defaults.Proxy.WireGuard.PathCoordination != nil {
		t.Fatal("default configuration enables WG path authority")
	}
	// Fixture values exercise the YAML contract, not recommended live budgets.
	// Removed phase/retry/window keys in an existing config are ignored by YAML.
	const raw = `proxy:
  wireguard:
    enabled: true
    path_coordination:
      transaction_timeout: 45s
      phases:
        prepare: 1s
        activate: 2s
        apply: 3s
        verify: 4s
        reconcile: 5s
      registry_members: 8
      max_pairs: 8
      control_burst: 64
      control_window: 6s
      retry_interval: 100ms
      max_reconcile_attempts: 2
      tick_interval: 400ms
`
	if err := yaml.Unmarshal([]byte(raw), defaults); err != nil {
		t.Fatal(err)
	}
	c := defaults.Proxy.WireGuard.PathCoordination
	if c == nil {
		t.Fatal("missing path coordination configuration", c)
	}
	for name, values := range map[string][2]time.Duration{
		"transaction": {c.TransactionTimeout, 45 * time.Second},
		"prepare":     {c.Phases.Prepare, time.Second},
		"apply":       {c.Phases.Apply, 3 * time.Second},
		"tick":        {c.TickInterval, 400 * time.Millisecond},
	} {
		if values[0] != values[1] {
			t.Errorf("%s: got %s, want %s", name, values[0], values[1])
		}
	}
	if c.RegistryMembers != 8 || c.MaxPairs != 8 || c.ControlBurst != 64 {
		t.Fatal("resource limits did not survive YAML decoding", c)
	}
	if err := yaml.Unmarshal([]byte("proxy:\n  wireguard:\n    path_coordination:\n      tick_interval: invalid\n"), &Config{}); err == nil {
		t.Fatal("invalid duration was silently accepted")
	}
}
