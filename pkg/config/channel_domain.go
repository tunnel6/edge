package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidateChannelDomain runs on the effective configuration, for every startup path.
func (c *Config) ValidateChannelDomain() error {
	if c.Proxy.HTTP == nil || !c.Proxy.HTTP.Enabled {
		return nil
	}
	domain := normalizeDomain(c.Channel.GetAssignedDomain())
	if c.Channel.BaseDomain != "" {
		domain = normalizeDomain(c.Channel.BaseDomain)
	}
	if domain == "" {
		return fmt.Errorf("HTTP channels require channel.base_domain; configure --channel.base_domain=files.example.com or disable them with --channel.http.enable=false")
	}
	if len(domain) > 253 || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid channel.base_domain %q: expected a DNS base domain without wildcard, scheme, port or path", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabel.MatchString(label) {
			return fmt.Errorf("invalid channel.base_domain %q: expected a DNS base domain without wildcard, scheme, port or path", domain)
		}
	}
	switch c.Proxy.HTTP.CertificateSource {
	case "", "dns01", "upload":
	default:
		return fmt.Errorf("invalid HTTPS certificate_source: expected dns01 or upload")
	}
	c.Channel.BaseDomain = domain
	if _, err := c.Channel.SetAssignedDomainWithError(domain); err != nil {
		return fmt.Errorf("persist channel.base_domain: %w", err)
	}
	return nil
}
