package letsencrypt

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type DNS01Challenge struct {
	provider string
	executor DNS01Executor
}

func NewDNS01Challenge(provider string, executor DNS01Executor) *DNS01Challenge {
	return &DNS01Challenge{
		provider: strings.TrimSpace(provider),
		executor: executor,
	}
}

func (c *DNS01Challenge) Method() ChallengeMethod {
	return ChallengeDNS01
}

func (c *DNS01Challenge) Validate(opts *Options) error {
	_ = opts
	return nil
}

func (c *DNS01Challenge) Start(ctx context.Context, req *ChallengeStartRequest) error {
	if req == nil {
		return ErrInvalidDomain
	}
	domain := normalizeDomain(req.Domain)
	txtDomainTarget := dns01TargetDomain(domain)
	if txtDomainTarget == "" {
		return ErrInvalidDomain
	}

	dnsReq := &DNS01Request{
		Domain:           txtDomainTarget,
		Provider:         c.provider,
		ACMEDirectoryURL: strings.TrimSpace(req.ACMEDirectoryURL),
		Token:            req.Token,
		KeyAuthorization: req.KeyAuthorization,
		ACMEOrderURL:     req.ACMEOrderURL,
		ACMEFinalizeURL:  req.ACMEFinalizeURL,
		ACMEAuthzURL:     req.ACMEAuthzURL,
		ACMEChallengeURL: req.ACMEChallengeURL,
	}
	if c.executor != nil {
		if err := c.executor(ctx, dnsReq); err != nil {
			return fmt.Errorf("%w: %v", ErrChallengeFailed, err)
		}
		return nil
	}

	// Fallback behavior: if no custom executor is provided, require pre-created
	// TXT record for _acme-challenge.<domain> to pass DNS-01 readiness check.
	txtDomain := "_acme-challenge." + txtDomainTarget
	records, err := net.DefaultResolver.LookupTXT(ctx, txtDomain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDNSRecordNotFound, err)
	}
	for _, record := range records {
		if strings.TrimSpace(record) != "" {
			return nil
		}
	}
	return ErrDNSRecordNotFound
}

func (c *DNS01Challenge) Guidance() string {
	return DefaultDNS01Guidance
}

func dns01TargetDomain(domain string) string {
	domain = normalizeDomain(domain)
	domain = strings.TrimPrefix(domain, "*.")
	return strings.TrimSpace(domain)
}
