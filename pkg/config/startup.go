package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Parse
// Config
type StartupParams struct {
	Node struct {
		PublicAddress string `json:"public_address"`
		Scope         string `json:"scope"`
		Type          string `json:"type"`
	} `json:"node"`
	Tunnel struct {
		Listen      string `json:"listen"`
		MaxSessions uint32 `json:"max_sessions"`
		Limits      struct {
			MaxPerSession *uint32 `json:"max_per_session"`
			MaxTotal      *uint32 `json:"max_total"`
		} `json:"limits"`
		TLS struct {
			CA   string `json:"ca"`
			Cert string `json:"cert"`
			Key  string `json:"key"`
		} `json:"tls"`
	} `json:"tunnel"`
	Channel struct {
		BaseDomain        string `json:"base_domain,omitempty"`
		CustomDomain      string `json:"custom_domain"`
		AliasDomainPolicy string `json:"alias_domain_policy"`
		HTTP              struct {
			Enable     *bool          `json:"enable"`
			Port       uint16         `json:"port"`
			Addr       string         `json:"addr"`
			Timeout    DurationString `json:"timeout"`
			Buffer     string         `json:"buffer"`
			BufferLock *bool          `json:"buffer_lock"`
			EagerStart *bool          `json:"eager_start"`
		} `json:"http"`
		HTTPS struct {
			Port              *uint16 `json:"port"`
			CertificateSource string  `json:"certificate_source,omitempty"`
		} `json:"https"`
		TCP struct {
			Enable  *bool  `json:"enable"`
			PortMin uint16 `json:"port_min"`
			PortMax uint16 `json:"port_max"`
		} `json:"tcp"`
		UDP struct {
			Enable  *bool  `json:"enable"`
			PortMin uint16 `json:"port_min"`
			PortMax uint16 `json:"port_max"`
		} `json:"udp"`
		WireGuard struct {
			Enable         *bool  `json:"enable"`
			RelayEnabled   *bool  `json:"relay_enabled,omitempty"`
			PublicEndpoint string `json:"public_endpoint,omitempty"`
		} `json:"wireguard"`
		P2P struct {
			UDPAddr *string `json:"udp_addr"`
		} `json:"p2p"`
	} `json:"channel"`
	Server struct {
		Capabilities struct {
			AutoEnable *bool `json:"auto_enable"`
			P2P        *bool `json:"p2p,omitempty"`
		} `json:"capabilities"`
	} `json:"server"`
}

type DurationString time.Duration

func (d *DurationString) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = DurationString(time.Duration(value))
		return nil
	case string:
		s := strings.TrimSpace(value)
		if s == "" {
			*d = 0
			return nil
		}
		dd, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = DurationString(dd)
		return nil
	default:
		return fmt.Errorf("invalid duration: %v", v)
	}
}

// Verify
func (sp *StartupParams) Validate() error {
	if sp.Tunnel.Listen == "" {
		return fmt.Errorf("startup config: tunnel.listen is required")
	}
	if _, _, err := net.SplitHostPort(sp.Tunnel.Listen); err != nil {
		return fmt.Errorf("startup config: invalid tunnel.listen: %w", err)
	}

	if sp.Channel.HTTP.Enable != nil && *sp.Channel.HTTP.Enable && sp.Channel.HTTP.Port == 0 {
		return fmt.Errorf("startup config: channel.http.port is required when channel.http.enable is true")
	}
	if sp.Channel.HTTP.Buffer != "" {
		if _, err := ParseByteSize(sp.Channel.HTTP.Buffer); err != nil {
			return fmt.Errorf("startup config: invalid channel.http.buffer: %w", err)
		}
	}
	if (sp.Channel.TCP.PortMin != 0 || sp.Channel.TCP.PortMax != 0) && sp.Channel.TCP.PortMin > sp.Channel.TCP.PortMax {
		return fmt.Errorf("startup config: invalid channel.tcp port range")
	}
	if (sp.Channel.UDP.PortMin != 0 || sp.Channel.UDP.PortMax != 0) && sp.Channel.UDP.PortMin > sp.Channel.UDP.PortMax {
		return fmt.Errorf("startup config: invalid channel.udp port range")
	}
	if sp.Channel.AliasDomainPolicy != "" {
		switch strings.ToLower(strings.TrimSpace(sp.Channel.AliasDomainPolicy)) {
		case AliasDomainPolicyDisabled, AliasDomainPolicyOptional, AliasDomainPolicyRequired:
		default:
			return fmt.Errorf("startup config: invalid channel.alias_domain_policy: %q (expected disabled/optional/required)", sp.Channel.AliasDomainPolicy)
		}
	}
	if _, err := sp.normalizedNodeScope(); err != nil {
		return err
	}
	return nil
}

// Start
func (sp *StartupParams) ApplyTo(cfg *Config) {
	if cfg == nil {
		return
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

	if sp.Node.PublicAddress != "" {
		cfg.Node.PublicAddress = sp.Node.PublicAddress
	}
	if nodeType, err := sp.normalizedNodeScope(); err == nil && nodeType != "" {
		cfg.Node.Type = nodeType
	}

	cfg.Tunnel.Listen = sp.Tunnel.Listen
	if sp.Tunnel.MaxSessions != 0 {
		cfg.Tunnel.MaxSessions = int(sp.Tunnel.MaxSessions)
	}
	if sp.Tunnel.TLS.CA != "" {
		cfg.Tunnel.TLS.CA = sp.Tunnel.TLS.CA
	}
	if sp.Tunnel.TLS.Cert != "" {
		cfg.Tunnel.TLS.Cert = sp.Tunnel.TLS.Cert
	}
	if sp.Tunnel.TLS.Key != "" {
		cfg.Tunnel.TLS.Key = sp.Tunnel.TLS.Key
	}
	if sp.Tunnel.Limits.MaxPerSession != nil {
		cfg.Tunnel.Limits.MaxPerSession = int(*sp.Tunnel.Limits.MaxPerSession)
	}
	if sp.Tunnel.Limits.MaxTotal != nil {
		cfg.Tunnel.Limits.MaxTotal = int(*sp.Tunnel.Limits.MaxTotal)
	}

	if sp.Channel.HTTP.Port != 0 {
		cfg.Proxy.HTTP.Port = sp.Channel.HTTP.Port
	}
	if sp.Channel.HTTPS.Port != nil {
		cfg.Proxy.HTTP.HTTPSPort = *sp.Channel.HTTPS.Port
	}
	if sp.Channel.HTTPS.CertificateSource != "" {
		cfg.Proxy.HTTP.CertificateSource = sp.Channel.HTTPS.CertificateSource
	}
	if sp.Channel.TCP.PortMin != 0 {
		cfg.Proxy.TCP.PortMin = sp.Channel.TCP.PortMin
	}
	if sp.Channel.TCP.PortMax != 0 {
		cfg.Proxy.TCP.PortMax = sp.Channel.TCP.PortMax
	}
	if sp.Channel.UDP.PortMin != 0 {
		cfg.Proxy.UDP.PortMin = sp.Channel.UDP.PortMin
	}
	if sp.Channel.UDP.PortMax != 0 {
		cfg.Proxy.UDP.PortMax = sp.Channel.UDP.PortMax
	}
	if sp.Channel.HTTP.Enable != nil {
		cfg.Proxy.HTTP.Enabled = *sp.Channel.HTTP.Enable
	}
	if sp.Channel.HTTP.Addr != "" {
		cfg.Proxy.HTTP.Addr = sp.Channel.HTTP.Addr
	}
	if time.Duration(sp.Channel.HTTP.Timeout) != 0 {
		cfg.Proxy.HTTP.Timeout = time.Duration(sp.Channel.HTTP.Timeout)
	}
	if sp.Channel.HTTP.Buffer != "" {
		cfg.Proxy.HTTP.Buffer = sp.Channel.HTTP.Buffer
	}
	if sp.Channel.HTTP.BufferLock != nil {
		cfg.Proxy.HTTP.BufferLock = *sp.Channel.HTTP.BufferLock
	}
	if sp.Channel.HTTP.EagerStart != nil {
		cfg.Proxy.HTTP.EagerStart = *sp.Channel.HTTP.EagerStart
	}
	if sp.Channel.TCP.Enable != nil {
		cfg.Proxy.TCP.Enabled = *sp.Channel.TCP.Enable
	}
	if sp.Channel.UDP.Enable != nil {
		cfg.Proxy.UDP.Enabled = *sp.Channel.UDP.Enable
	} else if sp.Channel.UDP.PortMin != 0 || sp.Channel.UDP.PortMax != 0 {
		cfg.Proxy.UDP.Enabled = true
	}
	if sp.Channel.WireGuard.Enable != nil {
		cfg.Proxy.WireGuard.Enabled = *sp.Channel.WireGuard.Enable
	}
	if sp.Channel.WireGuard.RelayEnabled != nil {
		cfg.Proxy.WireGuard.RelayEnabled = *sp.Channel.WireGuard.RelayEnabled
	}
	if endpoint := strings.TrimSpace(sp.Channel.WireGuard.PublicEndpoint); endpoint != "" {
		cfg.Proxy.WireGuard.PublicEndpoint = endpoint
	}
	if sp.Channel.P2P.UDPAddr != nil {
		udpAddr := strings.TrimSpace(*sp.Channel.P2P.UDPAddr)
		cfg.Proxy.ICE.UDPAddr = udpAddr
		if udpAddr != "" {
			cfg.Proxy.ICE.Enabled = true
		}
	}
	if sp.Server.Capabilities.P2P != nil {
		cfg.Proxy.ICE.Enabled = *sp.Server.Capabilities.P2P
	}
	if sp.Channel.CustomDomain != "" {
		cfg.Channel.SetCustomDomain(sp.Channel.CustomDomain)
	}
	if sp.Channel.BaseDomain != "" {
		cfg.Channel.BaseDomain = normalizeDomain(sp.Channel.BaseDomain)
	}
	if sp.Channel.AliasDomainPolicy != "" {
		cfg.Channel.AliasDomainPolicy = NormalizeAliasDomainPolicy(sp.Channel.AliasDomainPolicy)
	}
}

func (sp *StartupParams) normalizedNodeScope() (string, error) {
	if sp == nil {
		return "", nil
	}

	scopeRaw := strings.TrimSpace(sp.Node.Scope)
	typeRaw := strings.TrimSpace(sp.Node.Type)
	scope, scopeOK := normalizeStartupNodeScope(scopeRaw)
	nodeType, typeOK := normalizeStartupNodeScope(typeRaw)

	if scopeRaw != "" && !scopeOK {
		return "", fmt.Errorf("startup config: invalid node.scope: %q (expected private/public/shared)", sp.Node.Scope)
	}
	if typeRaw != "" && !typeOK {
		return "", fmt.Errorf("startup config: invalid node.type: %q (expected private/public/shared)", sp.Node.Type)
	}
	if scopeOK && typeOK && scope != nodeType {
		return "", fmt.Errorf("startup config: node.scope %q conflicts with node.type %q", sp.Node.Scope, sp.Node.Type)
	}
	if scopeOK {
		return scope, nil
	}
	if typeOK {
		return nodeType, nil
	}
	return "", nil
}

func normalizeStartupNodeScope(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", false
	case "private":
		return "private", true
	case "public":
		return "public", true
	case "shared":
		return "shared", true
	default:
		return "", false
	}
}
