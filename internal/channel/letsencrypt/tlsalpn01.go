package letsencrypt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrHTTPSListenerRequired = errors.New("letsencrypt: tls-alpn-01 requires HTTPS listener")

type TLSALPN01Challenge struct {
	listener net.Listener
	executor TLSALPN01Executor
	timeout  time.Duration
}

func NewTLSALPN01Challenge(listener net.Listener, executor TLSALPN01Executor, timeout time.Duration) *TLSALPN01Challenge {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &TLSALPN01Challenge{
		listener: listener,
		executor: executor,
		timeout:  timeout,
	}
}

func (c *TLSALPN01Challenge) Method() ChallengeMethod {
	return ChallengeTLSALPN01
}

func (c *TLSALPN01Challenge) Validate(opts *Options) error {
	if opts == nil || opts.HTTPSListener == nil {
		return ErrHTTPSListenerRequired
	}
	return nil
}

func (c *TLSALPN01Challenge) BuildTLSConfig(base *tls.Config) (*tls.Config, error) {
	if base == nil {
		base = &tls.Config{}
	} else {
		base = base.Clone()
	}

	hasALPN := false
	for _, proto := range base.NextProtos {
		if proto == TLSALPN01Protocol {
			hasALPN = true
			break
		}
	}
	if !hasALPN {
		base.NextProtos = append(base.NextProtos, TLSALPN01Protocol)
	}
	return base, nil
}

func (c *TLSALPN01Challenge) Start(ctx context.Context, req *ChallengeStartRequest) error {
	if req == nil {
		return ErrInvalidDomain
	}
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return ErrInvalidDomain
	}
	if c.listener == nil {
		return ErrHTTPSListenerRequired
	}

	tlsReq := &TLSALPN01Request{
		Domain:           domain,
		Listener:         c.listener,
		ACMEDirectoryURL: strings.TrimSpace(req.ACMEDirectoryURL),
		Token:            req.Token,
		KeyAuthorization: req.KeyAuthorization,
	}
	if c.executor != nil {
		if err := c.executor(ctx, tlsReq); err != nil {
			return fmt.Errorf("%w: %v", ErrChallengeFailed, err)
		}
		return nil
	}

	probeCtx := ctx
	var cancel context.CancelFunc
	if c.timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	if err := probeTLSALPNListener(probeCtx, c.listener, domain); err != nil {
		return fmt.Errorf("%w: tls-alpn-01 listener probe failed: %v", ErrChallengeFailed, err)
	}
	return nil
}
