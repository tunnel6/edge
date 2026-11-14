package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Config
type Config struct {
	managementMu sync.RWMutex
	Node         NodeConfig    `yaml:"node"`
	DataDir      string        `yaml:"data_dir"`
	Tunnel       TunnelConfig  `yaml:"tunnel"`
	Proxy        ProxyConfig   `yaml:"proxy"`
	Channel      ChannelConfig `yaml:"channel"`
	Log          LogConfig     `yaml:"log"`
	Pair         PairConfig    `yaml:"pair"` // Standalone pairing configuration
}

// PairConfig pairing configuration (mTLS tunnel mode)
type PairConfig struct {
	Role  string `yaml:"role"`  // owner or device (default)
	Token string `yaml:"token"` // Pre-configured pairing token (one-time use)
}

// Config
type NodeConfig struct {
	Name          string `yaml:"name"`
	ID            string `yaml:"id"` // Parse
	Zone          string `yaml:"zone"`
	Type          string `yaml:"type"` // public/private/shared
	PublicAddress string `yaml:"public_address"`
}

// Config
type TunnelConfig struct {
	Listen         string        `yaml:"listen"`
	MaxSessions    int           `yaml:"max_sessions"`
	SessionTimeout time.Duration `yaml:"session_timeout"`
	Limits         TunnelLimits  `yaml:"limits"`
	TLS            TLSConfig     `yaml:"tls"` // Config
}

type TunnelLimits struct {
	MaxPerSession int `yaml:"max_per_session"`
	MaxTotal      int `yaml:"max_total"`
}

// Config
type TLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	CA      string `yaml:"ca"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

// Config
type ProxyConfig struct {
	HTTP      *HTTPProxyConfig      `yaml:"http"`
	TCP       *TCPProxyConfig       `yaml:"tcp"`
	UDP       *UDPProxyConfig       `yaml:"udp"`
	WireGuard *WireGuardProxyConfig `yaml:"wireguard"`
	ICE       *ICEConfig            `yaml:"ice"`
}

type LogConfig struct {
	// Output supports: console, file.
	Output string `yaml:"output"`
	// File is used when output=file.
	File string `yaml:"file"`
	// Level supports: debug, info, warn, error, fatal, panic.
	Level string `yaml:"level"`
}

// Config
type ChannelConfig struct {
	BaseDomain            string           `yaml:"base_domain"`
	CustomDomain          string           `yaml:"custom_domain"` // custom domain (用于 yaml 解析，运行时使用 GetCustomDomain())
	AliasDomainPolicy     string           `yaml:"alias_domain_policy"`
	MaxChannelsPerUser    int              `yaml:"max_channels_per_user"`
	MaxBandwidthMbps      int              `yaml:"max_bandwidth_mbps"`
	MaxChannelsPerSession int              `yaml:"max_channels_pre_session"`
	MaxTotalChannels      int              `yaml:"max_total_channels"`
	P2P                   ChannelP2PConfig `yaml:"p2p"`
	DomainConfig
}

type ChannelP2PConfig struct {
	Enabled *bool  `yaml:"enabled"`
	UDPAddr string `yaml:"udp_addr"`
}

// AliasDomainPolicy values
const (
	AliasDomainPolicyDisabled = "disabled"
	AliasDomainPolicyOptional = "optional"
	AliasDomainPolicyRequired = "required"
)

// NormalizeAliasDomainPolicy 规范化 policy 字符串，未识别或为空时回退到 optional。
func NormalizeAliasDomainPolicy(policy string) string {
	switch strings.TrimSpace(strings.ToLower(policy)) {
	case AliasDomainPolicyDisabled:
		return AliasDomainPolicyDisabled
	case AliasDomainPolicyRequired:
		return AliasDomainPolicyRequired
	case AliasDomainPolicyOptional, "":
		return AliasDomainPolicyOptional
	default:
		return AliasDomainPolicyOptional
	}
}

// GetAliasDomainPolicy 返回规范化后的 policy，始终返回 disabled/optional/required 之一。
func (c *ChannelConfig) GetAliasDomainPolicy() string {
	if c == nil {
		return AliasDomainPolicyOptional
	}
	return NormalizeAliasDomainPolicy(c.AliasDomainPolicy)
}

// Config
type HTTPProxyConfig struct {
	CertificateSource string        `yaml:"certificate_source"` // dns01 (default) or upload
	Enabled           bool          `yaml:"enabled"`
	Port              uint16        `yaml:"port"`
	HTTPSPort         uint16        `yaml:"https_port"`
	Addr              string        `yaml:"addr"`
	Timeout           time.Duration `yaml:"timeout"`
	Buffer            string        `yaml:"buffer"`
	BufferLock        bool          `yaml:"buffer_lock"`
	EagerStart        bool          `yaml:"eager_start"`
	// Local-only: used by edge runtime, not reported via node.ServiceConfig.
	HTTPSServerCert string `yaml:"https_server_cert"`
	// Local-only: used by edge runtime, not reported via node.ServiceConfig.
	HTTPSServerKey string `yaml:"https_server_key"`
}

type TCPProxyConfig struct {
	Enabled bool   `yaml:"enabled"`
	PortMin uint16 `yaml:"port_min"`
	PortMax uint16 `yaml:"port_max"`
}

type UDPProxyConfig struct {
	Enabled bool   `yaml:"enabled"`
	PortMin uint16 `yaml:"port_min"`
	PortMax uint16 `yaml:"port_max"`
}

// Config
type WireGuardProxyConfig struct {
	PathCoordination  *WireGuardPathConfig `yaml:"path_coordination,omitempty"`
	Enabled           bool                 `yaml:"enabled"`
	Interface         string               `yaml:"interface"`
	Subnet            string               `yaml:"subnet"`
	InterfacePrefix   string               `yaml:"interface_prefix"`
	ListenPortBase    int                  `yaml:"listen_port_base"`
	KeyDir            string               `yaml:"key_dir"`
	PublicEndpoint    string               `yaml:"public_endpoint"`
	RelayEnabled      bool                 `yaml:"relay_enabled"`
	ForwarderStrategy string               `yaml:"forwarder_strategy"` // kernel | ebpf
	DefaultPeerRate   uint64               `yaml:"default_peer_rate"`  // bytes/sec, 0 = no limit
	DefaultPeerCeil   uint64               `yaml:"default_peer_ceil"`  // bytes/sec, 0 = same as rate
}

type ICEConfig struct {
	Enabled    bool   `yaml:"enabled"`
	UDPAddr    string `yaml:"udp_addr"`
	UDPAddrAlt string `yaml:"udp_addr_alt"`
}

// Method

// Get
func DefaultDataDir() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/edge"
	}

	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".edge")
	}

	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" {
		return filepath.Join(home, ".edge")
	}

	return "./data"
}

// Get
func (c *Config) GetDataDir() string {
	if c.DataDir != "" {
		return c.DataDir
	}
	return DefaultDataDir()
}

// GetCertDir is kept for backward compatibility.
func (c *Config) GetCertDir() string {
	return c.GetDataDir()
}

// Config
func DefaultConfig() *Config {
	return &Config{
		Node: NodeConfig{
			ID:   "", // Parse
			Zone: "default",
			Type: "private",
		},
		DataDir: DefaultDataDir(),
		Tunnel: TunnelConfig{
			Listen:         "0.0.0.0:9000",
			MaxSessions:    1000,
			SessionTimeout: 5 * time.Minute,
			Limits: TunnelLimits{
				MaxPerSession: 0,
				MaxTotal:      0,
			},
			TLS: TLSConfig{
				Enabled: true,
			},
		},
		Proxy: ProxyConfig{
			HTTP: &HTTPProxyConfig{
				Enabled:         true,
				Port:            80,
				HTTPSPort:       443,
				Addr:            "",
				Timeout:         30 * time.Second,
				Buffer:          "16K",
				BufferLock:      false,
				EagerStart:      false,
				HTTPSServerCert: "",
				HTTPSServerKey:  "",
			},
			WireGuard: &WireGuardProxyConfig{
				Enabled:         false,
				Interface:       "wg0",
				Subnet:          "10.0.0.1/24",
				InterfacePrefix: "wg-yat0",
				ListenPortBase:  58021,
				RelayEnabled:    false,
			},
			ICE: &ICEConfig{
				Enabled: false,
			},
			TCP: &TCPProxyConfig{
				Enabled: true,
				PortMin: 30000,
				PortMax: 40000,
			},
			UDP: &UDPProxyConfig{
				Enabled: true,
				PortMin: 30000,
				PortMax: 40000,
			},
		},
		Channel: ChannelConfig{
			MaxChannelsPerUser:    10,
			MaxChannelsPerSession: 10,
			MaxBandwidthMbps:      100,
			MaxTotalChannels:      1000,
		},
		Log: LogConfig{
			// Keep empty to let each runtime command decide its own default.
			Output: "",
			File:   "",
		},
	}
}

// Config
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Get
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.Channel.DomainConfig = *NewDomainConfig(cfg.GetDataDir())
	cfg.Channel.LoadFromLocal()
	// 同步 yaml 中的 CustomDomain 到 DomainConfig
	if cfg.Channel.CustomDomain != "" {
		cfg.Channel.SetCustomDomain(cfg.Channel.CustomDomain)
	}

	// Parse
	if cfg.Node.ID == "" {
		dataDir := cfg.GetDataDir()
		if id, err := LoadEdgeID(dataDir); err == nil {
			cfg.Node.ID = id
		}
	}

	// Config
	NormalizeConfig(cfg)
	return cfg, nil
}

// Config
func NormalizeConfig(cfg *Config) {
	// Config
	dataDir := cfg.GetDataDir()
	if cfg.DataDir == "" {
		cfg.DataDir = dataDir
	}

	if cfg.Tunnel.TLS.CA == "" {
		cfg.Tunnel.TLS.CA = filepath.Join(dataDir, "root-ca.crt")
	}
	if cfg.Tunnel.TLS.Cert == "" {
		cfg.Tunnel.TLS.Cert = filepath.Join(dataDir, "edge-tls.crt")
	}
	if cfg.Tunnel.TLS.Key == "" {
		cfg.Tunnel.TLS.Key = filepath.Join(dataDir, "edge-tls.key")
	}

	if cfg.Proxy.HTTP == nil {
		cfg.Proxy.HTTP = &HTTPProxyConfig{}
	}
	if cfg.Proxy.TCP == nil {
		cfg.Proxy.TCP = &TCPProxyConfig{}
	}
	if cfg.Proxy.UDP == nil {
		cfg.Proxy.UDP = &UDPProxyConfig{}
	}
	if cfg.Proxy.WireGuard == nil {
		cfg.Proxy.WireGuard = &WireGuardProxyConfig{}
	}
	if cfg.Proxy.ICE == nil {
		cfg.Proxy.ICE = &ICEConfig{}
	}
	if cfg.Channel.P2P.Enabled != nil {
		cfg.Proxy.ICE.Enabled = *cfg.Channel.P2P.Enabled
	}
	if strings.TrimSpace(cfg.Channel.P2P.UDPAddr) != "" {
		cfg.Proxy.ICE.UDPAddr = strings.TrimSpace(cfg.Channel.P2P.UDPAddr)
		if cfg.Channel.P2P.Enabled == nil {
			cfg.Proxy.ICE.Enabled = true
		}
	}
	if cfg.Tunnel.Limits.MaxPerSession < 0 {
		cfg.Tunnel.Limits.MaxPerSession = 0
	}
	if cfg.Tunnel.Limits.MaxTotal < 0 {
		cfg.Tunnel.Limits.MaxTotal = 0
	}
	cfg.Proxy.HTTP.Addr = strings.TrimSpace(cfg.Proxy.HTTP.Addr)
	cfg.Log.Output = strings.TrimSpace(cfg.Log.Output)
	cfg.Log.File = strings.TrimSpace(cfg.Log.File)
	cfg.Log.Level = strings.TrimSpace(cfg.Log.Level)
}

func normalizeTunnelLimit(v int) int {
	if v <= 0 {
		return 0
	}
	return v
}

// GetTunnelMaxPerSession returns max tunnel definitions per user session.
// A value of 0 means unlimited.
func (c *Config) GetTunnelMaxPerSession() int {
	if c == nil {
		return 0
	}
	c.managementMu.RLock()
	defer c.managementMu.RUnlock()
	return normalizeTunnelLimit(c.Tunnel.Limits.MaxPerSession)
}

// GetTunnelMaxTotal returns max tunnel definitions for current edge.
// A value of 0 means unlimited.
func (c *Config) GetTunnelMaxTotal() int {
	if c == nil {
		return 0
	}
	c.managementMu.RLock()
	defer c.managementMu.RUnlock()
	return normalizeTunnelLimit(c.Tunnel.Limits.MaxTotal)
}

// Config
func LoadTLSConfig(tlsCfg TLSConfig, isServer bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Verify
	if isServer {
		// Verify
		config.ClientAuth = tls.RequireAndVerifyClientCert
		// Verify
	}

	return config, nil
}

const edgeIDFile = "edge-id"
const assignedDomainFile = "assigned-domain"

// Read
func LoadEdgeID(dataDir string) (string, error) {
	path := filepath.Join(dataDir, edgeIDFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func SaveEdgeID(dataDir, edgeID string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, edgeIDFile)
	return os.WriteFile(path, []byte(edgeID), 0644)
}

// LoadAssignedDomain 从证书目录加载持久化的 AssignedDomain
func LoadAssignedDomain(dataDir string) (string, error) {
	path := filepath.Join(dataDir, assignedDomainFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// SaveAssignedDomain 将 AssignedDomain 持久化到证书目录
func SaveAssignedDomain(dataDir, assignedDomain string) error {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, assignedDomainFile)
	return os.WriteFile(path, []byte(assignedDomain), 0644)
}
