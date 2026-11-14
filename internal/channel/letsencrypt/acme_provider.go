package letsencrypt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	logger "icool.io/yat/edge/pkg/log"
)

type ACMEProvider struct {
	accountKey   crypto.Signer
	contactEmail string

	clientsMu   sync.Mutex
	clients     map[string]*acme.Client
	accountOnce map[string]*sync.Once
	accountErr  map[string]error

	sessionsMu sync.Mutex
	sessions   map[string]*acmeSession
}

type acmeSession struct {
	Domain           string
	Method           ChallengeMethod
	ACMEDirectoryURL string
	Token            string
	AuthorizationURL string
	OrderURL         string
	FinalizeURL      string
	Challenge        *acme.Challenge
	CreatedAt        time.Time
}

func NewACMEProvider(accountKey crypto.Signer, contactEmail string) (*ACMEProvider, error) {
	if accountKey == nil {
		return nil, fmt.Errorf("letsencrypt: acme account key is required")
	}
	return &ACMEProvider{
		accountKey:   accountKey,
		contactEmail: normalizeACMEContactEmail(contactEmail),
		clients:      make(map[string]*acme.Client),
		accountOnce:  make(map[string]*sync.Once),
		accountErr:   make(map[string]error),
		sessions:     make(map[string]*acmeSession),
	}, nil
}

func (p *ACMEProvider) ChallengeCredential(ctx context.Context, req *ChallengeCredentialRequest) (*ChallengeCredential, error) {
	if req == nil {
		return nil, ErrInvalidDomain
	}
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return nil, ErrInvalidDomain
	}
	if req.Method == "" {
		return nil, fmt.Errorf("letsencrypt: challenge method is required")
	}
	logger.Infof("acme challenge prepare start, domain=%s, method=%s", domain, req.Method)

	directoryURL := normalizeACMEDirectoryURL(req.ACMEDirectoryURL)
	client := p.clientFor(directoryURL)
	if err := p.ensureAccount(ctx, directoryURL, client); err != nil {
		return nil, err
	}

	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: domain}})
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: acme authorize order: %w", err)
	}

	var lastErr error
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			lastErr = err
			continue
		}
		if authz == nil {
			lastErr = fmt.Errorf("authorization is nil")
			continue
		}
		challenge := findACMEChallenge(authz.Challenges, req.Method)
		if challenge == nil {
			lastErr = fmt.Errorf("challenge %s is not available for authorization %s", req.Method, authzURL)
			continue
		}

		response, err := acmeChallengeResponse(client, req.Method, challenge.Token)
		if err != nil {
			lastErr = err
			continue
		}
		cred := &ChallengeCredential{
			Token:            challenge.Token,
			KeyAuthorization: response,
			ACMEOrderURL:     strings.TrimSpace(order.URI),
			ACMEFinalizeURL:  strings.TrimSpace(order.FinalizeURL),
			ACMEAuthzURL:     strings.TrimSpace(authz.URI),
			ACMEChallengeURL: strings.TrimSpace(challenge.URI),
		}
		if cred.ACMEOrderURL == "" {
			cred.ACMEOrderURL = strings.TrimSpace(order.URI)
		}
		if cred.ACMEAuthzURL == "" {
			cred.ACMEAuthzURL = strings.TrimSpace(authzURL)
		}

		session := &acmeSession{
			Domain:           domain,
			Method:           req.Method,
			ACMEDirectoryURL: directoryURL,
			Token:            challenge.Token,
			AuthorizationURL: cred.ACMEAuthzURL,
			OrderURL:         cred.ACMEOrderURL,
			FinalizeURL:      cred.ACMEFinalizeURL,
			Challenge:        challenge,
			CreatedAt:        time.Now(),
		}
		p.storeSession(session)
		logger.Infof(
			"acme challenge prepared, domain=%s, method=%s, token=%s, order_url=%s, authz_url=%s, challenge_url=%s",
			domain,
			req.Method,
			shortACMEToken(challenge.Token),
			cred.ACMEOrderURL,
			cred.ACMEAuthzURL,
			cred.ACMEChallengeURL,
		)
		return cred, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("letsencrypt: acme prepare challenge %s for %s: %w", req.Method, domain, lastErr)
	}
	return nil, fmt.Errorf("letsencrypt: acme challenge %s is unavailable for %s", req.Method, domain)
}

func (p *ACMEProvider) IssueCert(ctx context.Context, req *IssueRequest) (*CertMaterial, error) {
	if req == nil {
		return nil, ErrInvalidDomain
	}
	domain := normalizeDomain(req.Domain)
	if domain == "" {
		return nil, ErrInvalidDomain
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, ErrInvalidChallenge
	}

	session := p.popSession(domain, req.Method, token)
	if session == nil {
		return nil, fmt.Errorf("letsencrypt: acme session not found for %s %s", req.Method, domain)
	}
	logger.Infof(
		"acme issue start, domain=%s, method=%s, token=%s, order_url=%s, authz_url=%s",
		domain,
		req.Method,
		shortACMEToken(token),
		session.OrderURL,
		session.AuthorizationURL,
	)
	directoryURL := normalizeACMEDirectoryURL(req.ACMEDirectoryURL)
	if strings.TrimSpace(session.ACMEDirectoryURL) != "" {
		directoryURL = session.ACMEDirectoryURL
	}
	client := p.clientFor(directoryURL)
	if err := p.ensureAccount(ctx, directoryURL, client); err != nil {
		return nil, err
	}

	if _, err := client.Accept(ctx, session.Challenge); err != nil {
		return nil, fmt.Errorf("letsencrypt: acme accept challenge: %w", err)
	}
	logger.Infof("acme accept challenge success, domain=%s, method=%s, token=%s", domain, req.Method, shortACMEToken(token))
	if _, err := client.WaitAuthorization(ctx, session.AuthorizationURL); err != nil {
		return nil, fmt.Errorf("letsencrypt: acme wait authorization: %w", err)
	}
	logger.Infof("acme wait authorization success, domain=%s, method=%s, token=%s", domain, req.Method, shortACMEToken(token))

	order, err := client.WaitOrder(ctx, session.OrderURL)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: acme wait order: %w", err)
	}

	finalizeURL := strings.TrimSpace(session.FinalizeURL)
	if finalizeURL == "" && order != nil {
		finalizeURL = strings.TrimSpace(order.FinalizeURL)
	}
	if finalizeURL == "" {
		return nil, fmt.Errorf("letsencrypt: acme finalize URL is empty")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: generate cert key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: create csr: %w", err)
	}

	derChain, _, err := client.CreateOrderCert(ctx, finalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: acme create order cert: %w", err)
	}
	if len(derChain) == 0 {
		return nil, fmt.Errorf("letsencrypt: acme returned empty certificate chain")
	}

	var certPEM, chainPEM []byte
	for i, der := range derChain {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
		if i == 0 {
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
			continue
		}
		chainPEM = append(chainPEM, pem.EncodeToMemory(block)...)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	leaf, err := x509.ParseCertificate(derChain[0])
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: parse leaf certificate: %w", err)
	}
	return &CertMaterial{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		ChainPEM:       chainPEM,
		NotAfter:       leaf.NotAfter,
	}, nil
}

func (p *ACMEProvider) clientFor(directoryURL string) *acme.Client {
	directoryURL = normalizeACMEDirectoryURL(directoryURL)
	p.clientsMu.Lock()
	defer p.clientsMu.Unlock()

	client, ok := p.clients[directoryURL]
	if ok {
		return client
	}
	client = &acme.Client{
		Key:          p.accountKey,
		DirectoryURL: directoryURL,
	}
	p.clients[directoryURL] = client
	return client
}

func (p *ACMEProvider) ensureAccount(ctx context.Context, directoryURL string, client *acme.Client) error {
	directoryURL = normalizeACMEDirectoryURL(directoryURL)

	p.clientsMu.Lock()
	once, ok := p.accountOnce[directoryURL]
	if !ok {
		once = &sync.Once{}
		p.accountOnce[directoryURL] = once
	}
	p.clientsMu.Unlock()

	once.Do(func() {
		acct := &acme.Account{}
		if p.contactEmail != "" {
			acct.Contact = []string{"mailto:" + p.contactEmail}
		}
		_, err := client.Register(ctx, acct, acme.AcceptTOS)
		if shouldLoadExistingACMEAccount(err) {
			_, err = client.GetReg(ctx, "")
		}

		p.clientsMu.Lock()
		p.accountErr[directoryURL] = err
		p.clientsMu.Unlock()
	})

	p.clientsMu.Lock()
	err := p.accountErr[directoryURL]
	if err != nil {
		// Allow a later retry (for transient/network/context failures).
		p.accountOnce[directoryURL] = &sync.Once{}
		delete(p.accountErr, directoryURL)
	}
	p.clientsMu.Unlock()
	return err
}

func shouldLoadExistingACMEAccount(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		return true
	}
	var acmeErr *acme.Error
	return errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusConflict
}

func (p *ACMEProvider) storeSession(session *acmeSession) {
	if session == nil {
		return
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now()
	}
	key := sessionKey(session.Domain, session.Method, session.Token)
	p.sessionsMu.Lock()
	p.pruneSessionsLocked(time.Now().Add(-1*time.Hour), 2048)
	p.sessions[key] = session
	p.sessionsMu.Unlock()
}

func (p *ACMEProvider) popSession(domain string, method ChallengeMethod, token string) *acmeSession {
	key := sessionKey(domain, method, token)
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()

	session := p.sessions[key]
	delete(p.sessions, key)
	return session
}

func (p *ACMEProvider) pruneSessionsLocked(expireBefore time.Time, maxSessions int) {
	for key, session := range p.sessions {
		if session == nil || session.CreatedAt.Before(expireBefore) {
			delete(p.sessions, key)
		}
	}
	if len(p.sessions) <= maxSessions {
		return
	}
	// Best-effort cap to avoid unbounded growth.
	for key := range p.sessions {
		delete(p.sessions, key)
		if len(p.sessions) <= maxSessions {
			break
		}
	}
}

func sessionKey(domain string, method ChallengeMethod, token string) string {
	return normalizeDomain(domain) + "|" + string(method) + "|" + strings.TrimSpace(token)
}

func findACMEChallenge(challenges []*acme.Challenge, method ChallengeMethod) *acme.Challenge {
	for _, challenge := range challenges {
		if challenge == nil {
			continue
		}
		if strings.TrimSpace(challenge.Type) == string(method) {
			return challenge
		}
	}
	return nil
}

func acmeChallengeResponse(client *acme.Client, method ChallengeMethod, token string) (string, error) {
	switch method {
	case ChallengeHTTP01:
		return client.HTTP01ChallengeResponse(token)
	case ChallengeDNS01:
		return client.DNS01ChallengeRecord(token)
	case ChallengeTLSALPN01:
		// tls-alpn-01 validation ultimately relies on key authorization.
		return client.HTTP01ChallengeResponse(token)
	default:
		return "", fmt.Errorf("unsupported challenge method %s", method)
	}
}

func normalizeACMEDirectoryURL(directoryURL string) string {
	directoryURL = strings.TrimSpace(directoryURL)
	if directoryURL == "" {
		return DefaultACMEStagingDirectoryURL
	}
	return directoryURL
}

func normalizeACMEContactEmail(contactEmail string) string {
	contactEmail = strings.TrimSpace(contactEmail)
	contactEmail = strings.TrimPrefix(contactEmail, "mailto:")
	return strings.TrimSpace(contactEmail)
}

func shortACMEToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "<empty>"
	}
	if len(token) <= 8 {
		return token
	}
	return token[:8] + "..."
}
