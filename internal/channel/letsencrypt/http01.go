package letsencrypt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	logger "icool.io/yat/edge/pkg/log"
)

var ErrHTTPListenerRequired = errors.New("letsencrypt: http-01 requires HTTP listener")
var ErrHTTP01HandlerRequired = errors.New("letsencrypt: http-01 handler is required")
var ErrHTTP01KeyAuthorizationRequired = errors.New("letsencrypt: http-01 key authorization is required")

const http01ChallengePathPrefix = "/.well-known/acme-challenge/"

type HTTP01Challenge struct {
	listener net.Listener
	handler  *HTTP01Handler
	executor HTTP01Executor
	timeout  time.Duration
}

func NewHTTP01Challenge(listener net.Listener, handler *HTTP01Handler, executor HTTP01Executor, timeout time.Duration) *HTTP01Challenge {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if handler == nil {
		handler = NewHTTP01Handler()
	}
	return &HTTP01Challenge{
		listener: listener,
		handler:  handler,
		executor: executor,
		timeout:  timeout,
	}
}

func (c *HTTP01Challenge) Method() ChallengeMethod {
	return ChallengeHTTP01
}

func (c *HTTP01Challenge) Validate(opts *Options) error {
	if opts == nil || opts.HTTPListener == nil {
		return ErrHTTPListenerRequired
	}
	return nil
}

func (c *HTTP01Challenge) Start(ctx context.Context, req *ChallengeStartRequest) error {
	if req == nil {
		return ErrInvalidDomain
	}
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return ErrInvalidDomain
	}
	if c.listener == nil {
		return ErrHTTPListenerRequired
	}
	if c.handler == nil {
		return ErrHTTP01HandlerRequired
	}

	challengePath, err := BuildHTTP01ChallengePath(req.Token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrChallengeFailed, err)
	}

	httpReq := &HTTP01Request{
		Domain:           domain,
		Listener:         c.listener,
		ACMEDirectoryURL: strings.TrimSpace(req.ACMEDirectoryURL),
		Token:            req.Token,
		KeyAuthorization: req.KeyAuthorization,
		ChallengePath:    challengePath,
	}
	if strings.TrimSpace(req.KeyAuthorization) == "" {
		return fmt.Errorf("%w: %w", ErrChallengeFailed, ErrHTTP01KeyAuthorizationRequired)
	}
	if err := c.handler.Set(domain, req.Token, req.KeyAuthorization); err != nil {
		return fmt.Errorf("%w: %v", ErrChallengeFailed, err)
	}
	challengeReady := false
	defer func() {
		if !challengeReady {
			c.handler.Delete(domain, req.Token)
		}
	}()

	if c.executor != nil {
		if err := c.executor(ctx, httpReq); err != nil {
			return fmt.Errorf("%w: %v", ErrChallengeFailed, err)
		}
		challengeReady = true
		return nil
	}

	probeCtx := ctx
	var cancel context.CancelFunc
	if c.timeout > 0 {
		probeCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	if err := probeListenerTCP(probeCtx, c.listener); err != nil {
		return fmt.Errorf("%w: http-01 listener probe failed: %v", ErrChallengeFailed, err)
	}
	if err := probeHTTP01Challenge(probeCtx, c.listener, domain, challengePath, req.KeyAuthorization); err != nil {
		return fmt.Errorf("%w: http-01 challenge self-check failed: %v", ErrChallengeFailed, err)
	}
	challengeReady = true
	return nil
}

func BuildHTTP01ChallengePath(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("%w: http-01 token is empty", ErrInvalidChallenge)
	}
	return http01ChallengePathPrefix + url.PathEscape(token), nil
}

type HTTP01Handler struct {
	mu         sync.RWMutex
	challenges map[string]map[string]string
}

func NewHTTP01Handler() *HTTP01Handler {
	return &HTTP01Handler{
		challenges: make(map[string]map[string]string),
	}
}

func (h *HTTP01Handler) Set(domain, token, keyAuthorization string) error {
	if h == nil {
		return ErrHTTP01HandlerRequired
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return ErrInvalidDomain
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInvalidChallenge
	}
	keyAuthorization = strings.TrimSpace(keyAuthorization)
	if keyAuthorization == "" {
		return ErrHTTP01KeyAuthorizationRequired
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	m, ok := h.challenges[domain]
	if !ok {
		m = make(map[string]string)
		h.challenges[domain] = m
	}
	m[token] = keyAuthorization
	logger.Infof(
		"acme http-01 token set, domain=%s, token=%s, token_count=%d",
		domain,
		shortHTTP01Token(token),
		len(m),
	)
	return nil
}

func (h *HTTP01Handler) Delete(domain, token string) {
	if h == nil {
		return
	}
	domain = normalizeDomain(domain)
	token = strings.TrimSpace(token)
	if domain == "" || token == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	m, ok := h.challenges[domain]
	if !ok {
		return
	}
	delete(m, token)
	logger.Infof(
		"acme http-01 token delete, domain=%s, token=%s, token_count=%d",
		domain,
		shortHTTP01Token(token),
		len(m),
	)
	if len(m) == 0 {
		delete(h.challenges, domain)
	}
}

// DeleteDomain removes all http-01 challenge tokens for the given domain.
func (h *HTTP01Handler) DeleteDomain(domain string) {
	if h == nil {
		return
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}

	h.mu.Lock()
	tokenCount := len(h.challenges[domain])
	delete(h.challenges, domain)
	h.mu.Unlock()
	logger.Infof("acme http-01 domain cleanup, domain=%s, removed_tokens=%d", domain, tokenCount)
}

func (h *HTTP01Handler) Resolve(domain, token string) (string, bool) {
	if h == nil {
		return "", false
	}
	domain = normalizeDomain(domain)
	token = strings.TrimSpace(token)
	if domain == "" || token == "" {
		return "", false
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	m, ok := h.challenges[domain]
	if !ok {
		return "", false
	}
	value, ok := m[token]
	return value, ok
}

func (h *HTTP01Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || r == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenEscaped := strings.TrimPrefix(r.URL.EscapedPath(), http01ChallengePathPrefix)
	if tokenEscaped == r.URL.EscapedPath() || tokenEscaped == "" || strings.Contains(tokenEscaped, "/") {
		http.NotFound(w, r)
		return
	}
	token, err := url.PathUnescape(tokenEscaped)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	domain := normalizeHTTPHost(r.Host)
	if domain == "" {
		logger.Warnf("acme http-01 request dropped: empty host, raw_host=%q, path=%q", r.Host, r.URL.Path)
		http.NotFound(w, r)
		return
	}

	logger.Infof(
		"acme http-01 request received, host=%s, token=%s, method=%s, remote=%s",
		domain,
		shortHTTP01Token(token),
		r.Method,
		r.RemoteAddr,
	)
	value, ok := h.Resolve(domain, token)
	if !ok {
		logger.Warnf(
			"acme http-01 token miss, host=%s, token=%s, known_tokens=%d",
			domain,
			shortHTTP01Token(token),
			h.tokenCountForDomain(domain),
		)
		http.NotFound(w, r)
		return
	}
	logger.Infof("acme http-01 token hit, host=%s, token=%s", domain, shortHTTP01Token(token))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(value))
	}
}

func normalizeHTTPHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	} else if strings.Count(host, ":") == 1 {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return normalizeDomain(host)
}

func (h *HTTP01Handler) tokenCountForDomain(domain string) int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	m, ok := h.challenges[domain]
	if !ok {
		return 0
	}
	return len(m)
}

func shortHTTP01Token(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "<empty>"
	}
	if len(token) <= 8 {
		return token
	}
	return token[:8] + "..."
}
