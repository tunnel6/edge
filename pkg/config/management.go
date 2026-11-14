package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
)

const ManagementConfigFile = "edge-management.json"

// ManagementConfig is the owner-editable subset. It deliberately excludes
// controller addresses, identity, TLS keys, enrollment secrets and data paths.
// Pointers distinguish an omitted field from an explicit zero/false/empty value.
type ManagementConfig struct {
	Node struct {
		Name          *string `json:"name,omitempty"`
		Region        *string `json:"region,omitempty"`
		PublicAddress *string `json:"public_address,omitempty"`
	} `json:"node"`
	Tunnel struct {
		Limits struct {
			MaxPerSession *uint32 `json:"max_per_session,omitempty"`
			MaxTotal      *uint32 `json:"max_total,omitempty"`
		} `json:"limits"`
	} `json:"tunnel"`
	Channel struct {
		CustomDomain      *string `json:"custom_domain,omitempty"`
		AliasDomainPolicy *string `json:"alias_domain_policy,omitempty"`
		HTTP              struct {
			Enable    *bool   `json:"enable,omitempty"`
			Port      *uint16 `json:"port,omitempty"`
			HTTPSPort *uint16 `json:"https_port,omitempty"`
		} `json:"http"`
		TCP struct {
			Enable  *bool   `json:"enable,omitempty"`
			PortMin *uint16 `json:"port_min,omitempty"`
			PortMax *uint16 `json:"port_max,omitempty"`
		} `json:"tcp"`
		UDP struct {
			Enable  *bool   `json:"enable,omitempty"`
			PortMin *uint16 `json:"port_min,omitempty"`
			PortMax *uint16 `json:"port_max,omitempty"`
		} `json:"udp"`
		WireGuard struct {
			Enable *bool   `json:"enable,omitempty"`
			Subnet *string `json:"subnet,omitempty"`
		} `json:"wireguard"`
	} `json:"channel"`
	Server struct {
		Capabilities struct {
			AutoEnable *bool `json:"auto_enable,omitempty"`
			P2P        *bool `json:"p2p,omitempty"`
		} `json:"capabilities"`
	} `json:"server"`
}

func DecodeManagementConfig(raw []byte) (*ManagementConfig, error) {
	var result ManagementConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("management config must be a JSON object")
	}
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("invalid management config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("management config must contain one JSON object")
	}
	return &result, nil
}

func mergeManagementObjects(base, patch map[string]any) {
	for key, value := range patch {
		if nested, ok := value.(map[string]any); ok {
			current, _ := base[key].(map[string]any)
			if current == nil {
				current = map[string]any{}
			}
			mergeManagementObjects(current, nested)
			base[key] = current
		} else {
			base[key] = value
		}
	}
}

func (m *ManagementConfig) Merge(patch *ManagementConfig) *ManagementConfig {
	baseJSON, _ := json.Marshal(m)
	patchJSON, _ := json.Marshal(patch)
	var base, changes map[string]any
	_ = json.Unmarshal(baseJSON, &base)
	_ = json.Unmarshal(patchJSON, &changes)
	mergeManagementObjects(base, changes)
	merged, _ := json.Marshal(base)
	var result ManagementConfig
	_ = json.Unmarshal(merged, &result)
	return &result
}

func (m *ManagementConfig) Validate() error {
	for _, limit := range []*uint32{m.Tunnel.Limits.MaxPerSession, m.Tunnel.Limits.MaxTotal} {
		if limit != nil && uint64(*limit) > uint64(^uint(0)>>1) {
			return fmt.Errorf("tunnel limit exceeds platform integer range")
		}
	}
	if p := m.Channel.AliasDomainPolicy; p != nil && *p != "disabled" && *p != "optional" && *p != "required" {
		return fmt.Errorf("invalid alias domain policy")
	}
	if m.Channel.HTTP.Enable != nil && *m.Channel.HTTP.Enable && m.Channel.HTTP.Port != nil && *m.Channel.HTTP.Port == 0 {
		return fmt.Errorf("HTTP port must be between 1 and 65535")
	}
	for _, ports := range []struct {
		enabled  *bool
		min, max *uint16
	}{
		{m.Channel.TCP.Enable, m.Channel.TCP.PortMin, m.Channel.TCP.PortMax},
		{m.Channel.UDP.Enable, m.Channel.UDP.PortMin, m.Channel.UDP.PortMax},
	} {
		if ports.enabled != nil && *ports.enabled && ports.min != nil && ports.max != nil && (*ports.min == 0 || *ports.min > *ports.max) {
			return fmt.Errorf("invalid proxy port range")
		}
	}
	if m.Channel.WireGuard.Enable != nil && *m.Channel.WireGuard.Enable && m.Channel.WireGuard.Subnet != nil {
		if _, _, err := net.ParseCIDR(*m.Channel.WireGuard.Subnet); err != nil {
			return fmt.Errorf("invalid WireGuard subnet: %w", err)
		}
	}
	return nil
}

func managementPtr[T any](value T) *T { return &value }

func (c *Config) ManagementSnapshot() *ManagementConfig {
	m := &ManagementConfig{}
	if c.Node.Name != "" {
		m.Node.Name = managementPtr(c.Node.Name)
	}
	m.Node.Region = managementPtr(c.Node.Zone)
	m.Node.PublicAddress = managementPtr(c.Node.PublicAddress)
	m.Tunnel.Limits.MaxPerSession = managementPtr(uint32(c.GetTunnelMaxPerSession()))
	m.Tunnel.Limits.MaxTotal = managementPtr(uint32(c.GetTunnelMaxTotal()))
	m.Channel.CustomDomain = managementPtr(c.Channel.GetCustomDomain())
	m.Channel.AliasDomainPolicy = managementPtr(c.Channel.GetAliasDomainPolicy())
	if p := c.Proxy.HTTP; p != nil {
		m.Channel.HTTP.Enable, m.Channel.HTTP.Port, m.Channel.HTTP.HTTPSPort = managementPtr(p.Enabled), managementPtr(p.Port), managementPtr(p.HTTPSPort)
	}
	if p := c.Proxy.TCP; p != nil {
		m.Channel.TCP.Enable, m.Channel.TCP.PortMin, m.Channel.TCP.PortMax = managementPtr(p.Enabled), managementPtr(p.PortMin), managementPtr(p.PortMax)
	}
	if p := c.Proxy.UDP; p != nil {
		m.Channel.UDP.Enable, m.Channel.UDP.PortMin, m.Channel.UDP.PortMax = managementPtr(p.Enabled), managementPtr(p.PortMin), managementPtr(p.PortMax)
	}
	if p := c.Proxy.WireGuard; p != nil {
		m.Channel.WireGuard.Enable, m.Channel.WireGuard.Subnet = managementPtr(p.Enabled), managementPtr(p.Subnet)
	}
	if p := c.Proxy.ICE; p != nil {
		m.Server.Capabilities.P2P = managementPtr(p.Enabled)
	}
	return m
}

// ApplyLive changes only fields whose consumers support live updates.
func (m *ManagementConfig) ApplyLive(c *Config) {
	c.managementMu.Lock()
	defer c.managementMu.Unlock()
	if v := m.Tunnel.Limits.MaxPerSession; v != nil {
		c.Tunnel.Limits.MaxPerSession = int(*v)
	}
	if v := m.Tunnel.Limits.MaxTotal; v != nil {
		c.Tunnel.Limits.MaxTotal = int(*v)
	}
}

// ApplyAtStartup runs after deployment/CLI options and before listeners start.
func (m *ManagementConfig) ApplyAtStartup(c *Config) {
	m.ApplyLive(c)
	if v := m.Node.Name; v != nil {
		c.Node.Name = *v
	}
	if v := m.Node.Region; v != nil {
		c.Node.Zone = *v
	}
	if v := m.Node.PublicAddress; v != nil {
		c.Node.PublicAddress = *v
	}
	if v := m.Channel.CustomDomain; v != nil {
		c.Channel.SetCustomDomain(*v)
	}
	if v := m.Channel.AliasDomainPolicy; v != nil {
		c.Channel.AliasDomainPolicy = *v
	}
	if c.Proxy.HTTP == nil {
		c.Proxy.HTTP = &HTTPProxyConfig{}
	}
	if c.Proxy.TCP == nil {
		c.Proxy.TCP = &TCPProxyConfig{}
	}
	if c.Proxy.UDP == nil {
		c.Proxy.UDP = &UDPProxyConfig{}
	}
	if c.Proxy.WireGuard == nil {
		c.Proxy.WireGuard = &WireGuardProxyConfig{}
	}
	if c.Proxy.ICE == nil {
		c.Proxy.ICE = &ICEConfig{}
	}
	if v := m.Channel.HTTP.Enable; v != nil {
		c.Proxy.HTTP.Enabled = *v
	}
	if v := m.Channel.HTTP.Port; v != nil {
		c.Proxy.HTTP.Port = *v
		c.Proxy.HTTP.Addr = fmt.Sprintf(":%d", *v)
	}
	if v := m.Channel.HTTP.HTTPSPort; v != nil {
		c.Proxy.HTTP.HTTPSPort = *v
	}
	if v := m.Channel.TCP.Enable; v != nil {
		c.Proxy.TCP.Enabled = *v
	}
	if v := m.Channel.TCP.PortMin; v != nil {
		c.Proxy.TCP.PortMin = *v
	}
	if v := m.Channel.TCP.PortMax; v != nil {
		c.Proxy.TCP.PortMax = *v
	}
	if v := m.Channel.UDP.Enable; v != nil {
		c.Proxy.UDP.Enabled = *v
	}
	if v := m.Channel.UDP.PortMin; v != nil {
		c.Proxy.UDP.PortMin = *v
	}
	if v := m.Channel.UDP.PortMax; v != nil {
		c.Proxy.UDP.PortMax = *v
	}
	if v := m.Channel.WireGuard.Enable; v != nil {
		c.Proxy.WireGuard.Enabled = *v
	}
	if v := m.Channel.WireGuard.Subnet; v != nil {
		c.Proxy.WireGuard.Subnet = *v
	}
	if v := m.Server.Capabilities.P2P; v != nil {
		c.Proxy.ICE.Enabled = *v
	}
}

func (m *ManagementConfig) RestartRequired(current *ManagementConfig) bool {
	next := current.Merge(m)
	// Limits are already applied; all other changes affect startup components.
	next.Tunnel = current.Tunnel
	return !reflect.DeepEqual(next, current)
}

func LoadManagementConfig(dataDir string) (*ManagementConfig, error) {
	raw, err := os.ReadFile(filepath.Join(dataDir, ManagementConfigFile))
	if errors.Is(err, os.ErrNotExist) {
		return &ManagementConfig{}, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := DecodeManagementConfig(raw)
	if err != nil {
		return nil, err
	}
	return m, m.Validate()
}

// SaveManagementConfig replaces a private file atomically; failure never
// acknowledges a saved configuration or changes the in-memory limits.
func SaveManagementConfig(dataDir string, m *ManagementConfig) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dataDir, ".edge-management-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dataDir, ManagementConfigFile))
}
