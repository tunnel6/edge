package relay

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"strings"
)

const (
	// Linux IFNAMSIZ is 16 including the trailing NUL byte, so the visible
	// interface name must fit in 15 characters.
	maxLinuxInterfaceNameLen = 15
	interfaceHashLen         = 6
)

// Config holds the relay manager configuration.
type Config struct {
	// InterfacePrefix is the prefix for WG interface names.
	// Actual name: {prefix}-{compact-network-id}, capped to Linux's 15-char limit.
	InterfacePrefix string

	// ListenPortBase is the starting UDP port for WG interfaces.
	// Each network gets ListenPortBase + offset.
	ListenPortBase int

	// KeyDir is the directory for persisting WG keypairs.
	// Each network gets a keypair file: {KeyDir}/{networkID}.key
	KeyDir string

	// PublicEndpoint is the edge's public IP/hostname for clients to reach.
	// If empty, clients must resolve the host from the Edge public directory.
	PublicEndpoint string

	// ObserveInterval is how often to poll peer endpoints (seconds).
	ObserveInterval int

	// HeartbeatTimeout is the number of seconds since the last WireGuard
	// handshake before a peer is considered offline. boringtun rekey cycle:
	// REJECT_AFTER_TIME(180s) + next PK(25s) + 1 RTT ≈ 210s peak.
	// Default 300s = 210s peak + 90s margin (tolerates 1 missed rekey).
	HeartbeatTimeout int

	// ForbiddenSubnets holds local physical subnets scanned at startup.
	// User-provided CIDRs that overlap with these subnets are rejected.
	ForbiddenSubnets []net.IPNet

	// ForwarderStrategy selects the same-interface forwarding strategy.
	// Valid values: "kernel" (default), "ebpf".
	ForwarderStrategy ForwarderStrategy

	// DefaultPeerRate is the default guaranteed bandwidth (bytes/sec)
	// applied to every peer on network creation. Zero means no limit.
	DefaultPeerRate uint64

	// DefaultPeerCeil is the default max burst bandwidth (bytes/sec)
	// applied together with DefaultPeerRate. Zero defaults to DefaultPeerRate.
	DefaultPeerCeil uint64
}

// NormalizePublicHost accepts the deployment's host, host:port or URL, while
// the actual WG/relay UDP port always comes from the network runtime.
func NormalizePublicHost(value string) (string, error) {
	host := strings.TrimSpace(value)
	if host == "" {
		return "", nil
	}
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			return "", fmt.Errorf("invalid WireGuard public address %q", value)
		}
		host = parsed.Hostname()
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", fmt.Errorf("WireGuard public address must be a reachable unicast host: %q", value)
		}
		return ip.String(), nil
	}
	if len(host) > 253 {
		return "", fmt.Errorf("WireGuard public hostname is too long")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid WireGuard public hostname %q", value)
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("invalid WireGuard public hostname %q", value)
			}
		}
	}
	return host, nil
}

func DefaultConfig() *Config {
	return &Config{
		InterfacePrefix:  "wg-yat0",
		ListenPortBase:   58021,
		KeyDir:           "",
		ObserveInterval:  5,
		HeartbeatTimeout: 300,
	}
}

func (c *Config) InterfaceName(networkID string) string {
	prefix := normalizeInterfaceToken(c.InterfacePrefix)
	if prefix == "" {
		prefix = normalizeInterfaceToken(DefaultConfig().InterfacePrefix)
	}
	if prefix == "" {
		prefix = "wg"
	}

	maxPrefixLen := maxLinuxInterfaceNameLen - 1 - interfaceHashLen
	if len(prefix) > maxPrefixLen {
		prefix = prefix[:maxPrefixLen]
	}

	suffixBudget := maxLinuxInterfaceNameLen - len(prefix) - 1
	suffix := compactIdentifier(networkID, suffixBudget)
	if suffix == "" {
		return prefix
	}
	return prefix + "-" + suffix
}

func relayMemberID(networkID string) string {
	return "relay-" + compactIdentifier(networkID, 8)
}

func compactIdentifier(raw string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}

	token := normalizeInterfaceToken(raw)
	if token == "" {
		token = "net"
	}
	if len(token) <= maxLen {
		return token
	}

	hash := stableHexHash(raw)
	if maxLen <= interfaceHashLen {
		return hash[:maxLen]
	}

	headLen := maxLen - interfaceHashLen
	if headLen > len(token) {
		headLen = len(token)
	}
	return token[:headLen] + hash[:interfaceHashLen]
}

func normalizeInterfaceToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(trimmed))
	lastDash := false
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	return strings.Trim(b.String(), "-")
}

func stableHexHash(raw string) string {
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(raw))
	return fmt.Sprintf("%08x", sum.Sum32())
}
