package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"icool.io/yat/edge/internal/server"
	"icool.io/yat/edge/pkg/config"
	logger "icool.io/yat/edge/pkg/log"
)

const startupConfigCacheFile = ".edge_startup.json"

type cachedConfig struct {
	ConfigB64  string `json:"config_b64,omitempty"`
	ConfigJSON string `json:"config_json,omitempty"`
	PairToken  string `json:"pair_token,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

func boolPtr(v bool) *bool {
	return &v
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func nonNegativeUint32Ptr(v int) *uint32 {
	if v <= 0 {
		return uint32Ptr(0)
	}
	return uint32Ptr(uint32(v))
}

func applyStartupConfigFromFlags(cmd *cobra.Command, cfg *config.Config) (*config.StartupParams, []server.ServerOption, error) {
	if cmd == nil || cfg == nil {
		return nil, nil, nil
	}

	hasB64 := cmd.Flags().Changed("startup.config_b64") && strings.TrimSpace(startupConfigB64) != ""
	hasJSON := cmd.Flags().Changed("startup.config_json") && strings.TrimSpace(startupConfigJSON) != ""

	// 1. If there are new parameters, parse and save to cache
	if hasB64 || hasJSON {
		if hasB64 && hasJSON {
			return nil, nil, fmt.Errorf("only one of startup.config_b64 or startup.config_json can be set")
		}

		// Save cache
		cache := &cachedConfig{
			PairToken: os.Getenv("PAIR_TOKEN"),
			UpdatedAt: time.Now().Format(time.RFC3339),
		}
		if hasB64 {
			cache.ConfigB64 = strings.TrimSpace(startupConfigB64)
		} else {
			cache.ConfigJSON = strings.TrimSpace(startupConfigJSON)
		}

		if err := saveStartupCache(cache); err != nil {
			logger.Warnf("failed to save startup config cache: %v", err)
		} else {
			logger.Info("startup config cached to local file")
		}
	} else {
		// 2. If no new parameters, try to read from cache
		cache, err := loadStartupCache()
		if err == nil && cache != nil {
			logger.Info("loading startup config from local cache")

			// Restore environment variables (if not currently set)
			if os.Getenv("PAIR_TOKEN") == "" && cache.PairToken != "" {
				os.Setenv("PAIR_TOKEN", cache.PairToken)
				logger.Info("restored PAIR_TOKEN from cache")
			}

			// Restore parameters
			if cache.ConfigB64 != "" {
				startupConfigB64 = cache.ConfigB64
				hasB64 = true
			} else if cache.ConfigJSON != "" {
				startupConfigJSON = cache.ConfigJSON
				hasJSON = true
			}
		}
	}

	if !hasB64 && !hasJSON {
		return nil, nil, nil
	}

	var raw []byte
	if hasB64 {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(startupConfigB64))
		if err != nil {
			return nil, nil, fmt.Errorf("decode startup.config_b64: %w", err)
		}
		raw = b
	} else {
		raw = []byte(startupConfigJSON)
	}

	var sp config.StartupParams
	if err := json.Unmarshal(raw, &sp); err != nil {
		return nil, nil, fmt.Errorf("parse startup config: %w", err)
	}
	// ---------------------------------------------------------
	// Priority override: CLI > Env > JSON
	// ---------------------------------------------------------

	// 1. Environment Variables (Environment > JSON)
	if v := os.Getenv("TUNNEL_LISTEN"); v != "" {
		sp.Tunnel.Listen = v
	}
	if v := os.Getenv("PUBLIC_ADDRESS"); v != "" {
		sp.Node.PublicAddress = v
	}

	// 2. CLI Flags (CLI > Env > JSON)
	if cmd.Flags().Changed("tunnel.listen") {
		sp.Tunnel.Listen = listen
	}
	if cmd.Flags().Changed("tunnel.max_sessions") {
		sp.Tunnel.MaxSessions = uint32(maxSessions)
	}
	if cmd.Flags().Changed("tunnel.tls.ca") {
		sp.Tunnel.TLS.CA = tlsCA
	}
	if cmd.Flags().Changed("tunnel.tls.cert") {
		sp.Tunnel.TLS.Cert = tlsCert
	}
	if cmd.Flags().Changed("tunnel.tls.key") {
		sp.Tunnel.TLS.Key = tlsKey
	}
	if cmd.Flags().Changed("public") {
		sp.Node.PublicAddress = publicAddr
	}

	// Channel HTTP
	if cmd.Flags().Changed("channel.base_domain") {
		sp.Channel.BaseDomain = channelBaseDomain
	}
	if cmd.Flags().Changed("channel.https.certificate_source") {
		sp.Channel.HTTPS.CertificateSource = channelCertificateSource
	}
	if cmd.Flags().Changed("channel.http.enable") {
		sp.Channel.HTTP.Enable = boolPtr(httpProxyEnabled)
	}
	if cmd.Flags().Changed("channel.http.port") {
		sp.Channel.HTTP.Port = channelHTTPPort
	}
	if cmd.Flags().Changed("channel.https.port") {
		sp.Channel.HTTPS.Port = uint16Ptr(channelHTTPSPort)
	}
	if cmd.Flags().Changed("domain") {
		sp.Channel.CustomDomain = customDomain
	}
	if cmd.Flags().Changed("channel.alias_domain_policy") {
		sp.Channel.AliasDomainPolicy = aliasDomainPolicy
	}
	if cmd.Flags().Changed("channel.http.addr") {
		sp.Channel.HTTP.Addr = httpProxyAddr
	}
	if cmd.Flags().Changed("channel.http.timeout") {
		sp.Channel.HTTP.Timeout = config.DurationString(httpProxyTimeout)
	}
	if cmd.Flags().Changed("channel.http.buffer") {
		sp.Channel.HTTP.Buffer = channelHTTPBuffer
	}
	if cmd.Flags().Changed("channel.http.buffer.lock") {
		sp.Channel.HTTP.BufferLock = boolPtr(channelHTTPBufferLock)
	}
	if cmd.Flags().Changed("channel.http.eager_start") {
		sp.Channel.HTTP.EagerStart = boolPtr(eagerStartHTTPProxy)
	}

	// Channel TCP
	if cmd.Flags().Changed("channel.tcp.enable") {
		sp.Channel.TCP.Enable = boolPtr(tcpProxyEnabled)
	}
	if cmd.Flags().Changed("channel.tcp.port_min") {
		sp.Channel.TCP.PortMin = tcpPortMin
	}
	if cmd.Flags().Changed("channel.tcp.port_max") {
		sp.Channel.TCP.PortMax = tcpPortMax
	}

	// Channel UDP
	if cmd.Flags().Changed("channel.udp.port_min") {
		sp.Channel.UDP.PortMin = udpPortMin
	}
	if cmd.Flags().Changed("channel.udp.port_max") {
		sp.Channel.UDP.PortMax = udpPortMax
	}
	if cmd.Flags().Changed("channel.udp.enable") {
		sp.Channel.UDP.Enable = boolPtr(udpProxyEnabled)
	}

	// Tunnel definition limits
	if cmd.Flags().Changed("tunnel.limits.max_per_session") {
		sp.Tunnel.Limits.MaxPerSession = nonNegativeUint32Ptr(maxTunnelsPerSession)
	}
	if cmd.Flags().Changed("tunnel.limits.max_total") {
		sp.Tunnel.Limits.MaxTotal = nonNegativeUint32Ptr(maxTunnelsTotal)
	}

	// WireGuard
	if cmd.Flags().Changed("channel.wireguard.enable") {
		sp.Channel.WireGuard.Enable = boolPtr(wireGuardEnabled)
	}
	if cmd.Flags().Changed("channel.wireguard.relay_enabled") {
		sp.Channel.WireGuard.RelayEnabled = boolPtr(wireGuardRelayEnabled)
	}
	if cmd.Flags().Changed("channel.wireguard.public_endpoint") {
		sp.Channel.WireGuard.PublicEndpoint = strings.TrimSpace(wireGuardPublicEndpoint)
	}
	if cmd.Flags().Changed("channel.p2p.udp_addr") {
		addr := strings.TrimSpace(p2pUDPAddr)
		sp.Channel.P2P.UDPAddr = stringPtr(addr)
	}

	// Server Capabilities
	if cmd.Flags().Changed("server.capabilities.auto_enable") {
		sp.Server.Capabilities.AutoEnable = boolPtr(autoEnableCapabilities)
	}
	if cmd.Flags().Changed("server.capabilities.p2p") {
		sp.Server.Capabilities.P2P = boolPtr(p2pEnabled)
	}

	// ---------------------------------------------------------
	// Public Address Resolution (Interactive if needed)
	// ---------------------------------------------------------
	// First apply sp to cfg, so that resolvePublicAddress can use values from sp
	sp.ApplyTo(cfg)

	if err := cfg.ValidateChannelDomain(); err != nil {
		return nil, nil, err
	}
	resolvedAddr, err := resolvePublicAddress(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve public address: %w", err)
	}

	if resolvedAddr != "" {
		cfg.Node.PublicAddress = resolvedAddr
		// If resolved address is different from sp (e.g., obtained via interactive input), update sp
		if sp.Node.PublicAddress != resolvedAddr {
			sp.Node.PublicAddress = resolvedAddr
			// Mark cache update needed (even if no other flag changed)
			hasB64 = true // Variables
		}
	}

	// If parameters were overridden, need to sync update cache
	// Re-encode to Base64 and update startupConfigB64 (if using b64 mode)
	// Or update startupConfigJSON (if using json mode)
	if hasB64 || hasJSON {
		updatedRaw, err := json.Marshal(sp)
		if err == nil {
			cache := &cachedConfig{
				PairToken: os.Getenv("PAIR_TOKEN"),
				UpdatedAt: time.Now().Format(time.RFC3339),
			}

			// If in B64 mode, update ConfigB64
			if hasB64 {
				cache.ConfigB64 = base64.StdEncoding.EncodeToString(updatedRaw)
				// Update local variable to ensure subsequent use of latest value
				startupConfigB64 = cache.ConfigB64
			} else {
				// If in JSON mode, update ConfigJSON
				cache.ConfigJSON = string(updatedRaw)
				// Update local variable
				startupConfigJSON = cache.ConfigJSON
			}

			// Save updated cache
			if err := saveStartupCache(cache); err != nil {
				logger.Warnf("failed to update startup config cache: %v", err)
			} else {
				logger.Debug("startup config cache updated with overridden values")
			}
		} else {
			logger.Warnf("failed to marshal updated startup config: %v", err)
		}
	}

	if err := sp.Validate(); err != nil {
		return nil, nil, err
	}

	sp.ApplyTo(cfg)

	// Apply PAIR_TOKEN from environment variable (set by install.sh)
	if v := os.Getenv("PAIR_TOKEN"); v != "" {
		cfg.Pair.Token = strings.TrimSpace(v)
		cfg.Pair.Role = "owner"
		logger.Infof("pair token set from PAIR_TOKEN env var")
	}

	opts := startupConfigToServerOptions(&sp)
	return &sp, opts, nil
}

func saveStartupCache(cache *cachedConfig) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(startupConfigCacheFile, data, 0600)
}

func loadStartupCache() (*cachedConfig, error) {
	data, err := os.ReadFile(startupConfigCacheFile)
	if err != nil {
		return nil, err
	}
	var cache cachedConfig
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

func startupConfigToServerOptions(sp *config.StartupParams) []server.ServerOption {
	opts := make([]server.ServerOption, 0, 12)

	if sp.Channel.HTTP.Enable != nil {
		opts = append(opts, server.WithHTTPProxyEnabled(*sp.Channel.HTTP.Enable))
	}
	if sp.Channel.HTTP.Port != 0 {
		opts = append(opts, server.WithRegistryHTTPPort(sp.Channel.HTTP.Port))
	}
	if sp.Channel.HTTPS.Port != nil {
		opts = append(opts, server.WithRegistryHTTPSPort(*sp.Channel.HTTPS.Port))
	}
	if sp.Channel.HTTP.Addr != "" {
		opts = append(opts, server.WithHTTPProxyAddr(sp.Channel.HTTP.Addr))
	}
	if time.Duration(sp.Channel.HTTP.Timeout) != 0 {
		opts = append(opts, server.WithHTTPProxyTimeout(time.Duration(sp.Channel.HTTP.Timeout)))
	}
	if sp.Channel.HTTP.Buffer != "" {
		size, err := config.ParseByteSize(sp.Channel.HTTP.Buffer)
		if err != nil {
			logger.Warnf("ignore invalid startup channel.http.buffer=%q: %v", sp.Channel.HTTP.Buffer, err)
		} else {
			opts = append(opts, server.WithHTTPBufferSize(size))
		}
	}
	if sp.Channel.HTTP.BufferLock != nil {
		opts = append(opts, server.WithHTTPBufferLock(*sp.Channel.HTTP.BufferLock))
	}
	if sp.Channel.HTTP.EagerStart != nil {
		opts = append(opts, server.WithEagerStartHTTPProxy(*sp.Channel.HTTP.EagerStart))
	}

	if sp.Channel.TCP.Enable != nil {
		opts = append(opts, server.WithTCPProxyEnabled(*sp.Channel.TCP.Enable))
	}
	if sp.Channel.UDP.Enable != nil {
		opts = append(opts, server.WithUDPProxyEnabled(*sp.Channel.UDP.Enable))
	}
	if sp.Channel.TCP.PortMin != 0 || sp.Channel.TCP.PortMax != 0 {
		opts = append(opts, server.WithTCPPortRange(sp.Channel.TCP.PortMin, sp.Channel.TCP.PortMax))
	}
	if sp.Channel.UDP.PortMin != 0 || sp.Channel.UDP.PortMax != 0 {
		opts = append(opts, server.WithUDPPortRange(sp.Channel.UDP.PortMin, sp.Channel.UDP.PortMax))
	}
	if sp.Node.PublicAddress != "" {
		opts = append(opts, server.WithNodePublicAddress(sp.Node.PublicAddress))
	}

	if sp.Channel.WireGuard.Enable != nil {
		opts = append(opts, server.WithWireGuardEnabled(*sp.Channel.WireGuard.Enable))
	}
	if sp.Channel.P2P.UDPAddr != nil && strings.TrimSpace(*sp.Channel.P2P.UDPAddr) != "" {
		opts = append(opts, server.WithP2PUDPAddr(strings.TrimSpace(*sp.Channel.P2P.UDPAddr)))
	}
	if sp.Server.Capabilities.AutoEnable != nil {
		opts = append(opts, server.WithAutoEnableFromCapabilities(*sp.Server.Capabilities.AutoEnable))
	}
	if sp.Server.Capabilities.P2P != nil {
		opts = append(opts, server.WithP2PEnabled(*sp.Server.Capabilities.P2P))
	}

	return opts
}
