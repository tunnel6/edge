package server

import "time"

type serverOptions struct {
	httpProxyEnabled           bool
	httpProxyEnabledSet        bool
	tcpProxyEnabled            bool
	tcpProxyEnabledSet         bool
	udpProxyEnabled            bool
	udpProxyEnabledSet         bool
	wireGuardEnabled           bool
	wireGuardEnabledSet        bool
	eagerStartHTTPProxy        bool
	eagerStartHTTPProxySet     bool
	autoEnableFromCapabilities bool

	resourceTCPPortMin *uint16
	resourceTCPPortMax *uint16
	resourceUDPPortMin *uint16
	resourceUDPPortMax *uint16

	registryHTTPPort             *uint16
	registryHTTPSPort            *uint16
	registryMaxTargetsPerSession *int
	registryMaxTargets           *int

	httpProxyAddr    *string
	httpProxyTimeout *time.Duration
	httpBufferSize   *int
	httpBufferLock   *bool

	nodePublicAddress *string
	p2pEnabled        bool
	p2pEnabledSet     bool
	p2pUDPAddr        *string
}

type ServerOption func(*serverOptions)

func defaultServerOptions() serverOptions {
	return serverOptions{
		httpProxyEnabled:           true,
		tcpProxyEnabled:            true,
		udpProxyEnabled:            true,
		wireGuardEnabled:           true,
		eagerStartHTTPProxy:        false,
		autoEnableFromCapabilities: true,
	}
}

func WithHTTPProxyEnabled(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.httpProxyEnabled = enabled
		o.httpProxyEnabledSet = true
	}
}

func WithTCPProxyEnabled(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.tcpProxyEnabled = enabled
		o.tcpProxyEnabledSet = true
	}
}

func WithUDPProxyEnabled(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.udpProxyEnabled = enabled
		o.udpProxyEnabledSet = true
	}
}

func WithWireGuardEnabled(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.wireGuardEnabled = enabled
		o.wireGuardEnabledSet = true
	}
}

func WithEagerStartHTTPProxy(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.eagerStartHTTPProxy = enabled
		o.eagerStartHTTPProxySet = true
	}
}

func WithAutoEnableFromCapabilities(enabled bool) ServerOption {
	return func(o *serverOptions) { o.autoEnableFromCapabilities = enabled }
}

func WithTCPPortRange(min, max uint16) ServerOption {
	return func(o *serverOptions) {
		o.resourceTCPPortMin = &min
		o.resourceTCPPortMax = &max
	}
}

func WithUDPPortRange(min, max uint16) ServerOption {
	return func(o *serverOptions) {
		o.resourceUDPPortMin = &min
		o.resourceUDPPortMax = &max
	}
}

func WithRegistryHTTPPort(port uint16) ServerOption {
	return func(o *serverOptions) { o.registryHTTPPort = &port }
}

func WithRegistryHTTPSPort(port uint16) ServerOption {
	return func(o *serverOptions) { o.registryHTTPSPort = &port }
}

func WithRegistryLimits(maxTargetsPerSession, maxTargets int) ServerOption {
	return func(o *serverOptions) {
		o.registryMaxTargetsPerSession = &maxTargetsPerSession
		o.registryMaxTargets = &maxTargets
	}
}

func WithHTTPProxyAddr(addr string) ServerOption {
	return func(o *serverOptions) { o.httpProxyAddr = &addr }
}

func WithHTTPProxyTimeout(timeout time.Duration) ServerOption {
	return func(o *serverOptions) { o.httpProxyTimeout = &timeout }
}

func WithHTTPBufferSize(size int) ServerOption {
	return func(o *serverOptions) { o.httpBufferSize = &size }
}

func WithHTTPBufferLock(lock bool) ServerOption {
	return func(o *serverOptions) { o.httpBufferLock = &lock }
}

func WithNodePublicAddress(addr string) ServerOption {
	return func(o *serverOptions) { o.nodePublicAddress = &addr }
}

func WithP2PEnabled(enabled bool) ServerOption {
	return func(o *serverOptions) {
		o.p2pEnabled = enabled
		o.p2pEnabledSet = true
	}
}

func WithP2PUDPAddr(addr string) ServerOption {
	return func(o *serverOptions) { o.p2pUDPAddr = &addr }
}
