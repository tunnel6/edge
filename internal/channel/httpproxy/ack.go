package httpproxy

import (
	"encoding/json"
	"fmt"
	"strings"

	fbMsg "icool.io/yat/api/build/fb/golang/message"
	ct "icool.io/yat/edge/internal/channel/types"
	logger "icool.io/yat/edge/pkg/log"
)

const (
	defaultHTTPBufferSize = 16 * 1024
	minHTTPBufferSize     = 1024
	maxHTTPBufferSize     = 1024 * 1024
	manualDNS01Hint       = "If certificate fallback switches to manual dns-01, configure TXT in edge console / yat-fe edge management panel."
	manualDNS01ValueHint  = "<acme-dns01-value-from-edge-status>"
)

type channelCreateConfig struct {
	BufferSize  int  `json:"buffer_size"`
	HTTPS       bool `json:"https"`
	EnableHTTPS bool `json:"enable_https"`
}

type channelCreateAckMeta struct {
	BufferSize      int    `json:"buffer_size"`
	RequestedBuffer int    `json:"requested_buffer_size,omitempty"`
	EdgeBuffer      int    `json:"edge_buffer_size,omitempty"`
	DynamicWindow   bool   `json:"dynamic_window,omitempty"`
	BufferLock      bool   `json:"buffer_lock,omitempty"`
	DNSRequired     bool   `json:"dns_required,omitempty"`
	Subdomain       string `json:"subdomain,omitempty"`
	// AssignedDomain is the full domain allocated for this channel (e.g. tdzm5p.9.e.myproxy.dev).
	// The TLS certificate on edge covers this domain. Clients should use this directly
	// rather than reconstructing it from subdomain + base domain.
	AssignedDomain string `json:"assignedDomain,omitempty"`
	// CustomDomain is the full custom-base domain for this channel (e.g. tunnel.example.com).
	// Present only when the edge has a custom domain configured. Supports both https and http.
	CustomDomain string `json:"customDomain,omitempty"`
	AliasDomain  string `json:"alias_domain,omitempty"`

	DNSRecordType    string `json:"dns_record_type,omitempty"`
	DNSRecordName    string `json:"dns_record_name,omitempty"`
	DNSRecordValue   string `json:"dns_record_value,omitempty"`
	DNSHint          string `json:"dns_hint,omitempty"`
	DNS01RecordType  string `json:"dns01_record_type,omitempty"`
	DNS01RecordName  string `json:"dns01_record_name,omitempty"`
	DNS01RecordValue string `json:"dns01_record_value,omitempty"`
	DNS01Hint        string `json:"dns01_hint,omitempty"`

	TLSCertStatus  string `json:"tls_cert_status,omitempty"`
	TLSCertMessage string `json:"tls_cert_message,omitempty"`
}

func shouldEnableHTTPSFlow(
	channelType fbMsg.ChannelType,
	createReq *ct.CreateRequest,
	parsedCfg *channelCreateConfig,
) bool {
	if channelType == fbMsg.ChannelTypeHTTPS {
		return true
	}
	if createReq != nil && strings.EqualFold(strings.TrimSpace(createReq.Protocol), "https") {
		return true
	}
	if parsedCfg != nil && (parsedCfg.HTTPS || parsedCfg.EnableHTTPS) {
		return true
	}
	return false
}

func (p *HTTPProxy) hasAliasDomainCertificate(aliasDomain string) bool {
	aliasDomain = normalizeDomain(aliasDomain)
	if aliasDomain == "" {
		return false
	}

	p.mu.RLock()
	resolver := p.tlsCertResolver
	p.mu.RUnlock()
	if resolver == nil {
		return false
	}

	cert, err := resolver(aliasDomain)
	if err != nil {
		return false
	}
	return cert != nil
}

func (p *HTTPProxy) BuildChannelCreateAck(
	channelType fbMsg.ChannelType,
	configRaw []byte,
	createReq *ct.CreateRequest,
	result *ct.CreateResult,
) (aliasDomain, customDomain, assignedDomain, remoteEndpoint, ackErrorMessage string, err error) {
	if createReq == nil || result == nil {
		return "", "", "", "", "", fmt.Errorf("invalid HTTP create context")
	}

	assignedDomainForAlias := normalizeDomain(result.Domain)
	if createReq.AliasDomain != "" {
		recoveredAssignedDomain, recovered, assignedErr := resolveAssignedDomainForAliasDomain(
			result.Domain,
			result.Subdomain,
			p.getAssignedDomain(),
		)
		if assignedErr != nil {
			return "", "", "", "", "", assignedErr
		}
		assignedDomainForAlias = recoveredAssignedDomain
		if recovered {
			logger.Warnf(
				"channel assigned domain recovered for alias domain request, channel=%s, raw_domain=%s, subdomain=%s, base_domain=%s, recovered_domain=%s",
				createReq.ID,
				result.Domain,
				result.Subdomain,
				p.getAssignedDomain(),
				assignedDomainForAlias,
			)
		}
	}

	edgeBuffer := normalizeHTTPBufferSize(p.httpBufferSize)
	requestedBuffer := 0
	negotiatedBuffer := edgeBuffer
	dynamicWindow := true
	parsedCfg, parseErr := parseChannelCreateConfig(configRaw)
	if parseErr != nil {
		logger.Warnf("invalid channel config for %s: %v", createReq.ID, parseErr)
	}
	httpsFlowEnabled := p.httpsPort > 0 && shouldEnableHTTPSFlow(channelType, createReq, parsedCfg)
	if parsedCfg != nil && parsedCfg.BufferSize > 0 {
		requestedBuffer = parsedCfg.BufferSize
	}
	if p.httpBufferLock {
		negotiatedBuffer = edgeBuffer
		dynamicWindow = false
	} else if requestedBuffer > 0 {
		negotiatedBuffer = normalizeHTTPBufferSize(requestedBuffer)
		if negotiatedBuffer > edgeBuffer {
			negotiatedBuffer = edgeBuffer
		}
	}

	// Build full custom-domain address if edge has a custom domain configured.
	var fullCustomDomain string
	if subdomain := normalizeDomain(result.Subdomain); subdomain != "" {
		if customBase := p.getCustomDomain(); customBase != "" {
			fullCustomDomain = fmt.Sprintf("%s.%s", subdomain, customBase)
		}
	}

	ackMeta := channelCreateAckMeta{
		BufferSize:      negotiatedBuffer,
		RequestedBuffer: requestedBuffer,
		EdgeBuffer:      edgeBuffer,
		DynamicWindow:   dynamicWindow,
		BufferLock:      p.httpBufferLock,
		Subdomain:       result.Subdomain,
		AssignedDomain:  normalizeDomain(result.Domain),
		CustomDomain:    fullCustomDomain,
		AliasDomain:     result.AliasDomain,
	}

	if createReq.AliasDomain != "" && httpsFlowEnabled {
		normalizedAliasDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(createReq.AliasDomain)), ".")
		p.mu.RLock()
		onReq := p.onHTTPSDomainRequest
		p.mu.RUnlock()
		if p.hasAliasDomainCertificate(normalizedAliasDomain) {
			ackMeta.TLSCertStatus = "ready"
			ackMeta.TLSCertMessage = fmt.Sprintf(
				"certificate already exists on edge for %s; reusing existing certificate",
				normalizedAliasDomain,
			)
			logger.Infof(
				"alias domain certificate reused, channel=%s, alias_domain=%s, assigned_domain=%s, channel_type=%v",
				createReq.ID,
				normalizedAliasDomain,
				assignedDomainForAlias,
				channelType,
			)
		} else {
			if onReq != nil {
				ackMeta.TLSCertStatus = "pending"
				ackMeta.TLSCertMessage = fmt.Sprintf(
					"certificate issuance started; if fallback enters manual dns-01 mode, configure TXT name=%s value=%s (exact value available in edge status dns01_challenges)",
					"_acme-challenge."+normalizedAliasDomain,
					manualDNS01ValueHint,
				)
				aliasDomain := createReq.AliasDomain
				assignedDomain := assignedDomainForAlias
				logger.Infof(
					"alias domain certificate request queued, channel=%s, alias_domain=%s, assigned_domain=%s, channel_type=%v",
					createReq.ID,
					aliasDomain,
					assignedDomain,
					channelType,
				)
				go onReq(aliasDomain, assignedDomain)
			} else {
				ackMeta.TLSCertStatus = "unavailable"
				ackMeta.TLSCertMessage = fmt.Sprintf(
					"automatic certificate issuance is unavailable on this edge; configure manual dns-01 TXT name=%s value=%s (exact value available in edge status dns01_challenges), or upload certificate files manually",
					"_acme-challenge."+normalizedAliasDomain,
					manualDNS01ValueHint,
				)
			}
		}
	}

	if dnsMeta, ok := buildAliasDomainDNSMeta(createReq.AliasDomain, assignedDomainForAlias, httpsFlowEnabled); ok {
		ackMeta.DNSRequired = dnsMeta.DNSRequired
		ackMeta.DNSRecordType = dnsMeta.DNSRecordType
		ackMeta.DNSRecordName = dnsMeta.DNSRecordName
		ackMeta.DNSRecordValue = dnsMeta.DNSRecordValue
		ackMeta.DNSHint = dnsMeta.DNSHint
		ackMeta.DNS01RecordType = dnsMeta.DNS01RecordType
		ackMeta.DNS01RecordName = dnsMeta.DNS01RecordName
		ackMeta.DNS01RecordValue = dnsMeta.DNS01RecordValue
		ackMeta.DNS01Hint = dnsMeta.DNS01Hint
	}

	ackMetaRaw, marshalErr := json.Marshal(ackMeta)
	if marshalErr != nil {
		logger.Warnf("marshal channel ack meta failed: %v", marshalErr)
	} else {
		ackErrorMessage = string(ackMetaRaw)
	}

	// Return the three domain fields so the client can resolve the best address via
	// alias_domain || custom_domain || assigned_domain priority strategy.
	return result.AliasDomain, fullCustomDomain, normalizeDomain(result.Domain), "", ackErrorMessage, nil
}

func normalizeHTTPBufferSize(size int) int {
	if size <= 0 {
		return defaultHTTPBufferSize
	}
	if size < minHTTPBufferSize {
		return minHTTPBufferSize
	}
	if size > maxHTTPBufferSize {
		return maxHTTPBufferSize
	}
	return size
}

func parseChannelCreateConfig(raw []byte) (*channelCreateConfig, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	cfg := &channelCreateConfig{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func buildAliasDomainDNSMeta(aliasDomain, assignedDomain string, includeDNS01 bool) (channelCreateAckMeta, bool) {
	aliasDomain = normalizeDomain(aliasDomain)
	assignedDomain = normalizeDomain(assignedDomain)
	if aliasDomain == "" || assignedDomain == "" {
		return channelCreateAckMeta{}, false
	}
	dns01RecordName := "_acme-challenge." + aliasDomain

	out := channelCreateAckMeta{
		DNSRequired:    true,
		DNSRecordType:  "CNAME",
		DNSRecordName:  aliasDomain,
		DNSRecordValue: assignedDomain,
		DNSHint:        fmt.Sprintf("Create DNS CNAME: %s -> %s.", aliasDomain, assignedDomain),
	}
	if includeDNS01 {
		out.DNSHint = fmt.Sprintf("Create DNS CNAME: %s -> %s. %s", aliasDomain, assignedDomain, manualDNS01Hint)
		out.DNS01RecordType = "TXT"
		out.DNS01RecordName = dns01RecordName
		out.DNS01RecordValue = manualDNS01ValueHint
		out.DNS01Hint = fmt.Sprintf(
			"If fallback enters manual dns-01 mode, create TXT %s = %s. Exact TXT value is generated by ACME challenge and will be available in edge status dns01_challenges.",
			dns01RecordName,
			manualDNS01ValueHint,
		)
	}
	return out, true
}

func validateAssignedDomainForAliasDomain(assignedDomain string) error {
	assignedDomain = normalizeDomain(assignedDomain)
	if assignedDomain == "" {
		return fmt.Errorf("assigned domain is empty; check edge assigned_domain configuration")
	}
	if !strings.Contains(assignedDomain, ".") {
		return fmt.Errorf("assigned domain %q is invalid (missing base domain suffix); check edge assigned_domain configuration", assignedDomain)
	}
	return nil
}

func resolveAssignedDomainForAliasDomain(
	channelAssignedDomain string,
	subdomain string,
	assignedDomainBase string,
) (resolved string, recovered bool, err error) {
	channelAssignedDomain = normalizeDomain(channelAssignedDomain)
	if strings.Contains(channelAssignedDomain, ".") {
		return channelAssignedDomain, false, nil
	}

	baseDomain := normalizeDomain(assignedDomainBase)
	if strings.Contains(baseDomain, ".") {
		subdomainLabel := normalizeDomain(subdomain)
		if strings.Contains(subdomainLabel, ".") {
			subdomainLabel = extractSubdomain(subdomainLabel)
		}
		if subdomainLabel == "" {
			subdomainLabel = channelAssignedDomain
		}
		if subdomainLabel != "" {
			return fmt.Sprintf("%s.%s", subdomainLabel, baseDomain), true, nil
		}
	}

	if assignedErr := validateAssignedDomainForAliasDomain(channelAssignedDomain); assignedErr != nil {
		return "", false, assignedErr
	}
	return channelAssignedDomain, false, nil
}
