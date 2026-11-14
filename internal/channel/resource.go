package channel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var subdomainRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$`)

type ResourcePool struct {
	// Config
	tcpPortMin uint16
	tcpPortMax uint16
	udpPortMin uint16
	udpPortMax uint16

	tcpUsed map[uint16]bool
	udpUsed map[uint16]bool
	tcpNext uint16
	udpNext uint16

	// Domain - 通过 DomainProvider 获取，不持有副本
	domainProvider DomainProvider
	allocated      map[string]bool
	aliasedDomains map[string]string

	mu sync.Mutex
}

// Config
type ResourceConfig struct {
	TCPPortMin uint16
	TCPPortMax uint16
	UDPPortMin uint16
	UDPPortMax uint16
}

// Config
func DefaultResourceConfig() *ResourceConfig {
	return &ResourceConfig{
		TCPPortMin: 30000,
		TCPPortMax: 40000,
		UDPPortMin: 30000,
		UDPPortMax: 40000,
	}
}

// Create
func NewResourcePool(config *ResourceConfig, domainProvider DomainProvider) *ResourcePool {
	if config == nil {
		config = DefaultResourceConfig()
	}
	return &ResourcePool{
		tcpPortMin:     config.TCPPortMin,
		tcpPortMax:     config.TCPPortMax,
		udpPortMin:     config.UDPPortMin,
		udpPortMax:     config.UDPPortMax,
		tcpUsed:        make(map[uint16]bool),
		udpUsed:        make(map[uint16]bool),
		tcpNext:        config.TCPPortMin,
		udpNext:        config.UDPPortMin,
		allocated:      make(map[string]bool),
		aliasedDomains: make(map[string]string),
		domainProvider: domainProvider,
	}
}

func (p *ResourcePool) AllocateTCP() (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocatePort(p.tcpPortMin, p.tcpPortMax, &p.tcpNext, p.tcpUsed, "TCP")
}

func (p *ResourcePool) AllocateTCPPort(port uint16) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if port < p.tcpPortMin || port > p.tcpPortMax {
		return 0, fmt.Errorf("TCP port %d is out of range [%d, %d]", port, p.tcpPortMin, p.tcpPortMax)
	}
	if p.tcpUsed[port] {
		return 0, fmt.Errorf("TCP port %d is already allocated", port)
	}

	p.tcpUsed[port] = true
	if p.tcpNext == port {
		p.tcpNext = port + 1
		if p.tcpNext > p.tcpPortMax {
			p.tcpNext = p.tcpPortMin
		}
	}
	return port, nil
}

func (p *ResourcePool) AllocateUDP() (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocatePort(p.udpPortMin, p.udpPortMax, &p.udpNext, p.udpUsed, "UDP")
}

func (p *ResourcePool) AllocateUDPPort(port uint16) (uint16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if port < p.udpPortMin || port > p.udpPortMax {
		return 0, fmt.Errorf("UDP port %d is out of range [%d, %d]", port, p.udpPortMin, p.udpPortMax)
	}
	if p.udpUsed[port] {
		return 0, fmt.Errorf("UDP port %d is already allocated", port)
	}

	p.udpUsed[port] = true
	if p.udpNext == port {
		p.udpNext = port + 1
		if p.udpNext > p.udpPortMax {
			p.udpNext = p.udpPortMin
		}
	}
	return port, nil
}

func (p *ResourcePool) ReleaseTCP(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tcpUsed, port)
}

func (p *ResourcePool) ReleaseUDP(port uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.udpUsed, port)
}

func (p *ResourcePool) allocatePort(min, max uint16, next *uint16, used map[uint16]bool, name string) (uint16, error) {
	total := int(max - min + 1)
	if len(used) >= total {
		return 0, fmt.Errorf("no available %s ports in range [%d, %d]", name, min, max)
	}

	startPort := *next
	port := startPort

	for {
		if !used[port] {
			used[port] = true
			*next = port + 1
			if *next > max {
				*next = min
			}
			return port, nil
		}
		port++
		if port > max {
			port = min
		}
		if port == startPort {
			return 0, fmt.Errorf("no available %s ports", name)
		}
	}
}

func (p *ResourcePool) AllocateDomain(subdomain, customDomain string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	customDomain = normalizeDomain(customDomain)
	if customDomain != "" {
		if _, exists := p.aliasedDomains[customDomain]; exists {
			return "", fmt.Errorf("custom domain already in use: %s", customDomain)
		}
		p.aliasedDomains[customDomain] = customDomain
		return customDomain, nil
	}

	// subdomain必须已经提供（通过用户指定或自动生成）
	if subdomain == "" {
		return "", fmt.Errorf("subdomain is required")
	}

	var finalSubdomain string
	subdomain = strings.ToLower(subdomain)
	if !subdomainRegex.MatchString(subdomain) {
		return "", fmt.Errorf("invalid subdomain format: %s", subdomain)
	}
	if p.allocated[subdomain] {
		// subdomain已被占用，添加随机后缀
		suffix := p.randomSuffix(6)
		finalSubdomain = fmt.Sprintf("%s-%s", subdomain, suffix)
	} else {
		finalSubdomain = subdomain
	}

	p.allocated[finalSubdomain] = true
	assignedDomain := p.getAssignedDomain()
	if assignedDomain == "" {
		// Deterministic contract: a channel's full domain must always be
		// subdomain + assignedDomain. Never return a bare subdomain — that
		// would propagate an invalid address (e.g. "tdzrbo") to the client.
		delete(p.allocated, finalSubdomain)
		return "", fmt.Errorf("assigned domain is not configured on this edge; cannot allocate channel domain")
	}
	return fmt.Sprintf("%s.%s", finalSubdomain, assignedDomain), nil
}

func (p *ResourcePool) ReleaseDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	domain = normalizeDomain(domain)
	if _, ok := p.aliasedDomains[domain]; ok {
		delete(p.aliasedDomains, domain)
		return
	}

	subdomain := extractSubdomain(domain)
	if subdomain != "" {
		delete(p.allocated, subdomain)
	}
}

func (p *ResourcePool) ComposeDomain(subdomain, customDomain string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.composeDomainLocked(subdomain, customDomain)
}

func (p *ResourcePool) composeDomainLocked(subdomain, customDomain string) (string, error) {
	customDomain = normalizeDomain(customDomain)
	if customDomain != "" {
		return customDomain, nil
	}

	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	if subdomain == "" {
		return "", fmt.Errorf("subdomain is required")
	}
	if !subdomainRegex.MatchString(subdomain) {
		return "", fmt.Errorf("invalid subdomain format: %s", subdomain)
	}
	assignedDomain := p.getAssignedDomain()
	if assignedDomain == "" {
		return "", fmt.Errorf("assigned domain is not configured on this edge; cannot compose channel domain")
	}
	return fmt.Sprintf("%s.%s", subdomain, assignedDomain), nil
}

// SetDomainProvider 设置域名提供者（用于热切换场景）
func (p *ResourcePool) SetDomainProvider(dp DomainProvider) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.domainProvider = dp
}

// getAssignedDomain 从 DomainProvider 获取 AssignedDomain
func (p *ResourcePool) getAssignedDomain() string {
	if p.domainProvider == nil {
		return ""
	}
	return normalizeDomain(p.domainProvider.GetAssignedDomain())
}

func (p *ResourcePool) randomSuffix(length int) string {
	bytes := make([]byte, (length+1)/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:length]
}

// EncodeID 将数据库ID编码为base36字符串
// base36使用 0-9 和 a-z，比base64更适合域名（大小写不敏感）
func EncodeID(id int64) string {
	const charset = "0123456789abcdefghijklmnopqrstuvwxyz"
	if id == 0 {
		return "0"
	}
	var result []byte
	for id > 0 {
		result = append([]byte{charset[id%36]}, result...)
		id /= 36
	}
	return string(result)
}

// Status

func (p *ResourcePool) TCPUsed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tcpUsed)
}

func (p *ResourcePool) UDPUsed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.udpUsed)
}

func (p *ResourcePool) DomainCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.allocated) + len(p.aliasedDomains)
}

// Get
func (p *ResourcePool) GetPortRange() (tcpMin, tcpMax, udpMin, udpMax uint16) {
	return p.tcpPortMin, p.tcpPortMax, p.udpPortMin, p.udpPortMax
}

// GetAssignedDomain 返回当前的 AssignedDomain
func (p *ResourcePool) GetAssignedDomain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.getAssignedDomain()
}

// GetCustomDomain 返回当前的 CustomDomain
func (p *ResourcePool) GetCustomDomain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.domainProvider == nil {
		return ""
	}
	return normalizeDomain(p.domainProvider.GetCustomDomain())
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimSuffix(domain, ".")
}

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
