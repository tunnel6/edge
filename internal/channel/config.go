package channel

import (
	"time"

	"icool.io/yat/edge/internal/channel/ice"
	"icool.io/yat/edge/pkg/config"
)

// Config holds all configuration for the ChannelManager.
type Config struct {
	// Registry config
	HTTPPort             int
	HTTPSPort            int
	MaxTargetsPerSession int
	MaxTargets           int

	// Resource config - AssignedDomain 已移至 DomainProvider
	DomainProvider DomainProvider
	TCPPortMin     int
	TCPPortMax     int
	UDPPortMin     int
	UDPPortMax     int

	// Proxy specific
	HTTPProxyEnabled          bool
	HTTPProxyAddr             string
	HTTPProxyTimeout          time.Duration
	HTTPBufferSize            int
	HTTPBufferLock            bool
	EagerStartHTTPProxy       bool
	TCPProxyEnabled           bool
	UDPProxyEnabled           bool
	WireGuardEnabled          bool
	WireGuardPathCoordination *config.WireGuardPathConfig
	// WireGuardRelayEnabled controls business relay forwarding only. The Edge
	// WireGuard observation runtime is initialized independently on Linux so
	// disabled networks can still learn client UDP endpoints.
	WireGuardRelayEnabled      bool
	WireGuardInterfacePrefix   string
	WireGuardListenPortBase    int
	WireGuardKeyDir            string
	WireGuardPublicEndpoint    string
	WireGuardForwarderStrategy string // "kernel" | "ebpf"
	WireGuardDefaultPeerRate   uint64 // bytes/sec, 0 = no limit
	WireGuardDefaultPeerCeil   uint64 // bytes/sec, 0 = same as rate

	// Status Manager
	EdgeID      string
	OwnerUserID string
	StatusDir   string

	// AliasDomainPolicy controls whether channels may/must provide an alias_domain.
	// Valid values: "disabled" | "optional" | "required" (empty defaults to optional).
	AliasDomainPolicy string

	// ICE P2P hole-punching
	ICEConfig *ice.Config
}
