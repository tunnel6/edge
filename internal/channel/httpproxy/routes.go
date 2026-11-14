package httpproxy

import (
	"strings"

	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

func (p *HTTPProxy) Register(target *ct.Channel) {
	if target == nil {
		return
	}
	subdomain := strings.TrimSpace(target.Subdomain)
	if subdomain == "" {
		subdomain = extractSubdomain(target.Domain)
	}
	p.RegisterSubdomain(subdomain, target)
	if target.AliasDomain != "" {
		p.RegisterDomain(target.AliasDomain, target)
	}
}

func (p *HTTPProxy) RegisterDomain(domain string, target *ct.Channel) {
	domain = normalizeDomain(domain)
	if domain == "" || target == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets[domain] = target
	logger.Debugf("HTTP target registered: %s -> %s", domain, target.ID)
}

func (p *HTTPProxy) RegisterSubdomain(subdomain string, target *ct.Channel) {
	subdomain = normalizeDomain(subdomain)
	if subdomain == "" || target == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.subdomainTargets[subdomain] = target
	logger.Debugf("HTTP subdomain target registered: %s -> %s", subdomain, target.ID)
}

func (p *HTTPProxy) Unregister(domain string) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.targets, domain)
	logger.Debugf("HTTP target unregistered: %s", domain)
}

func (p *HTTPProxy) UnregisterSubdomain(subdomain string) {
	subdomain = normalizeDomain(subdomain)
	if subdomain == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.subdomainTargets, subdomain)
	logger.Debugf("HTTP subdomain target unregistered: %s", subdomain)
}

func (p *HTTPProxy) GetTarget(domain string) *ct.Channel {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.targets[domain]
}

func (p *HTTPProxy) resolveTargetByAliasOrSubdomain(host string) *ct.Channel {
	host = normalizeDomain(host)
	if host == "" {
		return nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if target, ok := p.targets[host]; ok && target != nil {
		return target
	}

	subdomain := host
	if idx := strings.Index(subdomain, "."); idx > 0 {
		subdomain = subdomain[:idx]
	}
	if target, ok := p.subdomainTargets[subdomain]; ok && target != nil {
		return target
	}
	return nil
}
