package httpproxy

import (
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "icool.io/yat/edge/internal/channel/types"
)

// HTTPProxy implements ct.ChannelRuntime, ct.ChannelCreateAckBuilder,
// ct.Service, and ct.HTTPProxyConfigurator for HTTP/HTTPS channels.
type HTTPProxy struct {
	addr           string
	httpPort       uint16
	httpsPort      uint16
	httpsAddr      string
	domainProvider ct.DomainProvider
	timeout        time.Duration

	targets          map[string]*ct.Channel // alias_domain -> target
	subdomainTargets map[string]*ct.Channel // subdomain -> target

	connections sync.Map // connectionID -> *httpConnection

	tunnel ct.TunnelSender

	httpServer                *http.Server
	httpsServer               *http.Server
	running                   bool
	httpBufferSize            int
	httpBufferLock            bool
	onHTTPSDomainRequest      func(aliasDomain, assignedDomain string)
	acmeHTTP01Handler         http.Handler
	acmeTLSALPN01CertResolver func(hello *tls.ClientHelloInfo) (*tls.Certificate, bool)
	tlsCertResolver           func(serverName string) (*tls.Certificate, error)
	mu                        sync.RWMutex
}

type httpConnection struct {
	connectionID string
	channelID    string
	sessionID    string
	dataCh       chan []byte
	finished     chan struct{}
	w            http.ResponseWriter
}

// Config for constructing an HTTPProxy.
type Config struct {
	Addr           string
	HTTPPort       uint16
	HTTPSPort      uint16
	HTTPSAddr      string
	DomainProvider ct.DomainProvider
	Timeout        time.Duration
	HTTPBufferSize int
	HTTPBufferLock bool
	Tunnel         ct.TunnelSender
}

// New creates an HTTPProxy.
func New(config *Config) *HTTPProxy {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	return &HTTPProxy{
		addr:             config.Addr,
		httpPort:         config.HTTPPort,
		httpsPort:        config.HTTPSPort,
		httpsAddr:        config.HTTPSAddr,
		domainProvider:   config.DomainProvider,
		timeout:          config.Timeout,
		httpBufferSize:   config.HTTPBufferSize,
		httpBufferLock:   config.HTTPBufferLock,
		tunnel:           config.Tunnel,
		targets:          make(map[string]*ct.Channel),
		subdomainTargets: make(map[string]*ct.Channel),
	}
}

// SetTunnel sets the tunnel sender (post-construction wiring).
func (p *HTTPProxy) SetTunnel(tunnel ct.TunnelSender) {
	p.mu.Lock()
	p.tunnel = tunnel
	p.mu.Unlock()
}

// SetDomainProvider sets the domain provider (for hot-switch scenarios).
func (p *HTTPProxy) SetDomainProvider(dp ct.DomainProvider) {
	p.mu.Lock()
	p.domainProvider = dp
	p.mu.Unlock()
}

func (p *HTTPProxy) getAssignedDomain() string {
	p.mu.RLock()
	dp := p.domainProvider
	p.mu.RUnlock()
	if dp == nil {
		return ""
	}
	return normalizeDomain(dp.GetAssignedDomain())
}

func (p *HTTPProxy) getCustomDomain() string {
	p.mu.RLock()
	dp := p.domainProvider
	p.mu.RUnlock()
	if dp == nil {
		return ""
	}
	return normalizeDomain(dp.GetCustomDomain())
}

// normalizeDomain lowercases, trims, and removes trailing dot.
func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// extractSubdomain extracts the first label from a domain.
func extractSubdomain(domain string) string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return ""
	}
	if idx := strings.Index(domain, "."); idx > 0 {
		return domain[:idx]
	}
	return domain
}

