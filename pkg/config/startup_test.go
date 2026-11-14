package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeStartupParams(t *testing.T, raw string) StartupParams {
	t.Helper()
	var sp StartupParams
	if err := json.Unmarshal([]byte(raw), &sp); err != nil {
		t.Fatalf("unmarshal startup params: %v", err)
	}
	return sp
}

func TestStartupParamsApplyToNodeScope(t *testing.T) {
	t.Run("applies node scope to config node type", func(t *testing.T) {
		sp := decodeStartupParams(t, `{
			"data_dir": "./test-data",
			"node": {"scope": "public"},
			"tunnel": {"listen": "0.0.0.0:9000"}
		}`)
		if err := sp.Validate(); err != nil {
			t.Fatalf("Validate returned error: %v", err)
		}

		cfg := &Config{}
		cfg.Node.Type = "private"
		sp.ApplyTo(cfg)

		if cfg.Node.Type != "public" {
			t.Fatalf("node type mismatch: got=%q want=%q", cfg.Node.Type, "public")
		}
	})

	t.Run("accepts legacy node type alias", func(t *testing.T) {
		sp := decodeStartupParams(t, `{
			"data_dir": "./test-data",
			"node": {"type": "shared"},
			"tunnel": {"listen": "0.0.0.0:9000"}
		}`)
		if err := sp.Validate(); err != nil {
			t.Fatalf("Validate returned error: %v", err)
		}

		cfg := &Config{}
		cfg.Node.Type = "private"
		sp.ApplyTo(cfg)

		if cfg.Node.Type != "shared" {
			t.Fatalf("node type mismatch: got=%q want=%q", cfg.Node.Type, "shared")
		}
	})
}

func TestStartupParamsValidateNodeScope(t *testing.T) {
	t.Run("rejects invalid node scope", func(t *testing.T) {
		sp := decodeStartupParams(t, `{
			"data_dir": "./test-data",
			"node": {"scope": "official"},
			"tunnel": {"listen": "0.0.0.0:9000"}
		}`)

		err := sp.Validate()
		if err == nil {
			t.Fatalf("expected validation error")
		}
		if !strings.Contains(err.Error(), "invalid node.scope") {
			t.Fatalf("validation error mismatch: %v", err)
		}
	})

	t.Run("rejects conflicting node scope and type", func(t *testing.T) {
		sp := decodeStartupParams(t, `{
			"data_dir": "./test-data",
			"node": {"scope": "public", "type": "private"},
			"tunnel": {"listen": "0.0.0.0:9000"}
		}`)

		err := sp.Validate()
		if err == nil {
			t.Fatalf("expected validation error")
		}
		if !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("validation error mismatch: %v", err)
		}
	})
}
