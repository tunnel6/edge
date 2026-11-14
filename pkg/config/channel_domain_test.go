package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPRequiresBaseDomain(t *testing.T) {
	for _, domain := range []string{"", "*.files.example.com", "https://files.example.com", "files.example.com:443", "127.0.0.1", "files..example.com"} {
		t.Run(domain, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Channel.SetAssignedDomain(domain)
			if err := cfg.ValidateChannelDomain(); err == nil {
				t.Fatal("expected domain validation error")
			}
			cfg.Proxy.HTTP.Enabled = false
			if err := cfg.ValidateChannelDomain(); err != nil {
				t.Fatalf("non-HTTP deployment: %v", err)
			}
		})
	}
}

func TestBaseDomainLoadsFromYAMLAndStartupJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nchannel:\n  base_domain: Files.Example.com.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateChannelDomain(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Channel.GetAssignedDomain(); got != "files.example.com" {
		t.Fatalf("YAML domain: %q", got)
	}
	sp := decodeStartupParams(t, `{"tunnel":{"listen":"0.0.0.0:9000"},"channel":{"base_domain":"Other.Example.com.","https":{"certificate_source":"upload"}}}`)
	sp.ApplyTo(cfg)
	if err := cfg.ValidateChannelDomain(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Channel.GetAssignedDomain(); got != "other.example.com" {
		t.Fatalf("JSON domain: %q", got)
	}
	if cfg.Proxy.HTTP.CertificateSource != "upload" {
		t.Fatal("certificate source was lost")
	}
	if got, err := LoadAssignedDomain(dir); err != nil || got != "other.example.com" {
		t.Fatalf("persisted domain %q: %v", got, err)
	}
}

func TestInvalidBaseDomainDoesNotReplacePersistedDomain(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Channel.DomainConfig = *NewDomainConfig(dir)
	cfg.Channel.SetAssignedDomain("files.example.com")
	cfg.Channel.BaseDomain = "https://invalid.example.com"
	if err := cfg.ValidateChannelDomain(); err == nil {
		t.Fatal("expected validation error")
	}
	if got, err := LoadAssignedDomain(dir); err != nil || got != "files.example.com" {
		t.Fatalf("invalid configuration replaced persisted domain: %q, %v", got, err)
	}
}
