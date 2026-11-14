package letsencrypt

import (
	"context"
	"fmt"
	"sync"
)

// LetsEncrypt is the standalone module entry for certificate issuance and renewal.
type LetsEncrypt struct {
	opts       Options
	challenges []Challenge
	guidance   string

	token            string
	keyAuthorization string

	http01Handler *HTTP01Handler

	domainMu    sync.Mutex
	domainLocks map[string]*sync.Mutex

	initOnce sync.Once
	initErr  error
	mu       sync.RWMutex
}

// Builder creates LetsEncrypt instances from options.
type Builder struct {
	opts Options
}

func NewBuilder(options ...Option) *Builder {
	return &Builder{
		opts: resolveOptions(options...),
	}
}

func (b *Builder) With(options ...Option) *Builder {
	b.opts = applyOptions(b.opts, options...)
	return b
}

func (b *Builder) Build(ctx context.Context) (*LetsEncrypt, error) {
	le, err := newLetsEncrypt(b.opts)
	if err != nil {
		return nil, err
	}
	if err := le.ensureInitialized(ctx); err != nil {
		return nil, err
	}
	return le, nil
}

func Build(ctx context.Context, options ...Option) (*LetsEncrypt, error) {
	return NewBuilder(options...).Build(ctx)
}

func newLetsEncrypt(opts Options) (*LetsEncrypt, error) {
	challenges, guidance, err := buildChallenges(opts)
	if err != nil {
		return nil, err
	}
	http01Handler := findHTTP01Handler(challenges)
	return &LetsEncrypt{
		opts:          opts,
		challenges:    challenges,
		guidance:      guidance,
		http01Handler: http01Handler,
		domainLocks:   make(map[string]*sync.Mutex),
	}, nil
}

func buildChallenges(opts Options) ([]Challenge, string, error) {
	challenges := make([]Challenge, 0, 3)
	guidance := ""

	methods := opts.PreferredMethods
	if len(methods) == 0 {
		methods = defaultOptions().PreferredMethods
	}

	for _, method := range methods {
		challenge, ok, err := createChallenge(opts, method)
		if err != nil {
			return nil, "", err
		}
		if !ok {
			continue
		}
		if err := challenge.Validate(&opts); err != nil {
			continue
		}
		challenges = append(challenges, challenge)
	}

	if len(challenges) == 0 {
		guidance = DefaultDNS01Guidance
		if opts.EnableDNS01Fallback {
			challenges = append(challenges, NewDNS01Challenge(opts.DNS01Provider, opts.DNS01Executor))
		}
	}

	if len(challenges) == 0 {
		return nil, guidance, fmt.Errorf("%w: %s", ErrNoViableChallenge, guidance)
	}

	return challenges, guidance, nil
}

func createChallenge(opts Options, method ChallengeMethod) (Challenge, bool, error) {
	switch method {
	case ChallengeHTTP01:
		if opts.HTTPListener == nil {
			return nil, false, nil
		}
		return NewHTTP01Challenge(opts.HTTPListener, opts.HTTP01Handler, opts.HTTP01Executor, opts.ChallengeTimeout), true, nil
	case ChallengeTLSALPN01:
		if opts.HTTPSListener == nil {
			return nil, false, nil
		}
		return NewTLSALPN01Challenge(opts.HTTPSListener, opts.TLSALPN01Executor, opts.ChallengeTimeout), true, nil
	case ChallengeDNS01:
		return NewDNS01Challenge(opts.DNS01Provider, opts.DNS01Executor), true, nil
	default:
		return nil, false, fmt.Errorf("letsencrypt: unsupported challenge method %q", method)
	}
}

func normalizeMethods(methods []ChallengeMethod) []ChallengeMethod {
	if len(methods) == 0 {
		return nil
	}
	seen := make(map[ChallengeMethod]struct{}, len(methods))
	out := make([]ChallengeMethod, 0, len(methods))
	for _, method := range methods {
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out = append(out, method)
	}
	return out
}

func (le *LetsEncrypt) Challenges() []Challenge {
	out := make([]Challenge, 0, len(le.challenges))
	out = append(out, le.challenges...)
	return out
}

func (le *LetsEncrypt) ChallengeMethods() []ChallengeMethod {
	out := make([]ChallengeMethod, 0, len(le.challenges))
	for _, ch := range le.challenges {
		out = append(out, ch.Method())
	}
	return out
}

func (le *LetsEncrypt) Guidance() string {
	return le.guidance
}

func (le *LetsEncrypt) Options() Options {
	return le.opts
}

func (le *LetsEncrypt) HTTP01Handler() *HTTP01Handler {
	return le.http01Handler
}

func (le *LetsEncrypt) ACMEDirectoryURL() string {
	return le.opts.ACMEDirectoryURL
}

func (le *LetsEncrypt) Token() string {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.token
}

func (le *LetsEncrypt) KeyAuthorization() string {
	le.mu.RLock()
	defer le.mu.RUnlock()
	return le.keyAuthorization
}

func (le *LetsEncrypt) ensureInitialized(ctx context.Context) error {
	le.initOnce.Do(func() {
		le.initErr = le.initialize(ctx)
	})
	return le.initErr
}

func (le *LetsEncrypt) NewCert(ctx context.Context, method ChallengeMethod, domain string) (*StoredCertificate, error) {
	return le.issueCertificate(ctx, OperationNew, method, domain)
}

func (le *LetsEncrypt) RenewCert(ctx context.Context, method ChallengeMethod, domain string) (*StoredCertificate, error) {
	return le.issueCertificate(ctx, OperationRenew, method, domain)
}

func (le *LetsEncrypt) issueCertificate(ctx context.Context, op CertOperation, method ChallengeMethod, domain string) (*StoredCertificate, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, ErrInvalidDomain
	}
	unlock := le.lockDomain(domain)
	defer unlock()

	callback := le.opts.OnNewCert
	if op == OperationRenew {
		callback = le.opts.OnRenewCert
	}

	le.emit(ctx, callback, CertEvent{
		Operation: op,
		Stage:     EventStarted,
		Domain:    domain,
	})

	if err := le.ensureInitialized(ctx); err != nil {
		le.emit(ctx, callback, CertEvent{
			Operation: op,
			Stage:     EventFailed,
			Domain:    domain,
			Err:       err,
		})
		return nil, err
	}

	method, cred, err := le.runChallenge(ctx, method, domain)
	if err != nil {
		le.emit(ctx, callback, CertEvent{
			Operation: op,
			Stage:     EventFailed,
			Domain:    domain,
			Err:       err,
		})
		return nil, err
	}
	if method == ChallengeHTTP01 && le.http01Handler != nil {
		defer le.http01Handler.Delete(domain, cred.Token)
	}

	issuer := le.opts.NewCertIssuer
	if op == OperationRenew && le.opts.RenewIssuer != nil {
		issuer = le.opts.RenewIssuer
	}
	if issuer == nil {
		err = ErrIssuerMissing
		le.emit(ctx, callback, CertEvent{
			Operation: op,
			Stage:     EventFailed,
			Domain:    domain,
			Method:    method,
			Err:       err,
		})
		return nil, err
	}

	var existing *StoredCertificate
	if op == OperationRenew {
		existing = le.loadStoredCertificate(domain)
	}

	material, err := issuer(ctx, &IssueRequest{
		Domain:           domain,
		ACMEDirectoryURL: le.opts.ACMEDirectoryURL,
		Token:            cred.Token,
		KeyAuthorization: cred.KeyAuthorization,
		ACMEOrderURL:     cred.ACMEOrderURL,
		ACMEFinalizeURL:  cred.ACMEFinalizeURL,
		ACMEAuthzURL:     cred.ACMEAuthzURL,
		ACMEChallengeURL: cred.ACMEChallengeURL,
		Method:           method,
		Stored:           existing,
	})
	if err != nil {
		le.emit(ctx, callback, CertEvent{
			Operation: op,
			Stage:     EventFailed,
			Domain:    domain,
			Method:    method,
			Err:       err,
		})
		return nil, err
	}

	stored, err := le.saveCertificate(domain, method, material)
	if err != nil {
		le.emit(ctx, callback, CertEvent{
			Operation: op,
			Stage:     EventFailed,
			Domain:    domain,
			Method:    method,
			Err:       err,
		})
		return nil, err
	}

	le.emit(ctx, callback, CertEvent{
		Operation: op,
		Stage:     EventSucceeded,
		Domain:    domain,
		Method:    method,
		Stored:    stored,
	})
	return stored, nil
}

func (le *LetsEncrypt) runChallenge(ctx context.Context, chMethod ChallengeMethod, domain string) (ChallengeMethod, ChallengeCredential, error) {
	staticCred, staticErr := le.resolveCredential(ctx)

	var errs []error
	for _, ch := range le.challenges {
		if ch.Method() != chMethod && chMethod != "" {
			continue
		}
		cred := staticCred
		if le.opts.CredRequester != nil {
			requested, err := le.opts.CredRequester(ctx, &ChallengeCredentialRequest{
				Domain:           domain,
				Method:           ch.Method(),
				ACMEDirectoryURL: le.opts.ACMEDirectoryURL,
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: request challenge credential: %w", ch.Method(), err))
				continue
			}
			cred, err = normalizeCredential(requested)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: normalize challenge credential: %w", ch.Method(), err))
				continue
			}
			le.setCredential(cred)
		} else if staticErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Method(), staticErr))
			continue
		}

		if err := ch.Start(ctx, &ChallengeStartRequest{
			Domain:           domain,
			Method:           ch.Method(),
			ACMEDirectoryURL: le.opts.ACMEDirectoryURL,
			Token:            cred.Token,
			KeyAuthorization: cred.KeyAuthorization,
			ACMEOrderURL:     cred.ACMEOrderURL,
			ACMEFinalizeURL:  cred.ACMEFinalizeURL,
			ACMEAuthzURL:     cred.ACMEAuthzURL,
			ACMEChallengeURL: cred.ACMEChallengeURL,
		}); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.Method(), err))
			continue
		}
		return ch.Method(), cred, nil
	}

	if len(errs) == 0 {
		if le.guidance != "" {
			return "", ChallengeCredential{}, fmt.Errorf("%w: %s", ErrNoViableChallenge, le.guidance)
		}
		return "", ChallengeCredential{}, ErrNoViableChallenge
	}
	if le.guidance != "" {
		return "", ChallengeCredential{}, fmt.Errorf("%w: %w, guidance: %s", ErrNoViableChallenge, joinErrors(errs), le.guidance)
	}
	return "", ChallengeCredential{}, fmt.Errorf("%w: %w", ErrNoViableChallenge, joinErrors(errs))
}

func (le *LetsEncrypt) emit(ctx context.Context, cb CertLifecycleCallback, event CertEvent) {
	if cb != nil {
		cb(ctx, event)
	}
}

func (le *LetsEncrypt) lockDomain(domain string) func() {
	le.domainMu.Lock()
	lock, ok := le.domainLocks[domain]
	if !ok {
		lock = &sync.Mutex{}
		le.domainLocks[domain] = lock
	}
	le.domainMu.Unlock()

	lock.Lock()
	return lock.Unlock
}

func findHTTP01Handler(challenges []Challenge) *HTTP01Handler {
	for _, challenge := range challenges {
		http01, ok := challenge.(*HTTP01Challenge)
		if !ok || http01 == nil {
			continue
		}
		return http01.handler
	}
	return nil
}
