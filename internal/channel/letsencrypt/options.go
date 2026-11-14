package letsencrypt

import (
	"net"
	"path/filepath"
	"strings"
	"time"
)

// Options controls module initialization and challenge selection.
type Options struct {
	HTTPListener        net.Listener
	HTTPSListener       net.Listener
	PreferredMethods    []ChallengeMethod
	EnableDNS01Fallback bool
	DNS01Provider       string
	ACMEDirectoryURL    string

	DataDir   string
	CertDir   string
	TokenFile string

	TokenRequester TokenRequester
	CredRequester  ChallengeCredentialRequester
	NewCertIssuer  CertIssuer
	RenewIssuer    CertIssuer

	OnNewCert   CertLifecycleCallback
	OnRenewCert CertLifecycleCallback

	HTTP01Handler     *HTTP01Handler
	HTTP01Executor    HTTP01Executor
	TLSALPN01Executor TLSALPN01Executor
	DNS01Executor     DNS01Executor
	ChallengeTimeout  time.Duration
}

type Option func(*Options)

func defaultOptions() Options {
	return Options{
		PreferredMethods:    []ChallengeMethod{ChallengeHTTP01, ChallengeTLSALPN01},
		EnableDNS01Fallback: true,
		ACMEDirectoryURL:    DefaultACMEStagingDirectoryURL,
		DataDir:             "data",
		ChallengeTimeout:    5 * time.Second,
	}
}

func resolveOptions(options ...Option) Options {
	return applyOptions(defaultOptions(), options...)
}

func applyOptions(base Options, options ...Option) Options {
	opts := base
	for _, opt := range options {
		if opt != nil {
			opt(&opts)
		}
	}

	opts.DataDir = strings.TrimSpace(opts.DataDir)
	if opts.DataDir == "" {
		opts.DataDir = "data"
	}

	if strings.TrimSpace(opts.CertDir) == "" {
		opts.CertDir = filepath.Join(opts.DataDir, defaultCustomCertDirName)
	} else {
		opts.CertDir = strings.TrimSpace(opts.CertDir)
	}

	if strings.TrimSpace(opts.TokenFile) == "" {
		opts.TokenFile = filepath.Join(opts.DataDir, defaultTokenFileName)
	} else {
		opts.TokenFile = strings.TrimSpace(opts.TokenFile)
	}

	opts.PreferredMethods = normalizeMethods(opts.PreferredMethods)
	opts.ACMEDirectoryURL = strings.TrimSpace(opts.ACMEDirectoryURL)
	if opts.ACMEDirectoryURL == "" {
		opts.ACMEDirectoryURL = DefaultACMEStagingDirectoryURL
	}
	if opts.ChallengeTimeout <= 0 {
		opts.ChallengeTimeout = 5 * time.Second
	}
	return opts
}

func WithHTTPListener(listener net.Listener) Option {
	return func(o *Options) {
		o.HTTPListener = listener
	}
}

func WithHTTPSListener(listener net.Listener) Option {
	return func(o *Options) {
		o.HTTPSListener = listener
	}
}

func WithPreferredMethods(methods ...ChallengeMethod) Option {
	return func(o *Options) {
		o.PreferredMethods = append([]ChallengeMethod{}, methods...)
	}
}

func WithDNS01Fallback(enabled bool) Option {
	return func(o *Options) {
		o.EnableDNS01Fallback = enabled
	}
}

func WithDNS01Provider(provider string) Option {
	return func(o *Options) {
		o.DNS01Provider = provider
	}
}

func WithACMEDirectoryURL(directoryURL string) Option {
	return func(o *Options) {
		o.ACMEDirectoryURL = strings.TrimSpace(directoryURL)
	}
}

func WithACMEStaging() Option {
	return func(o *Options) {
		o.ACMEDirectoryURL = DefaultACMEStagingDirectoryURL
	}
}

func WithACMEProduction() Option {
	return func(o *Options) {
		o.ACMEDirectoryURL = DefaultACMEProductionDirectoryURL
	}
}

func WithDataDir(dir string) Option {
	return func(o *Options) {
		o.DataDir = strings.TrimSpace(dir)
	}
}

func WithCertDir(dir string) Option {
	return func(o *Options) {
		o.CertDir = strings.TrimSpace(dir)
	}
}

func WithTokenFile(path string) Option {
	return func(o *Options) {
		o.TokenFile = strings.TrimSpace(path)
	}
}

func WithTokenRequester(requester TokenRequester) Option {
	return func(o *Options) {
		o.TokenRequester = requester
	}
}

func WithChallengeCredentialRequester(requester ChallengeCredentialRequester) Option {
	return func(o *Options) {
		o.CredRequester = requester
	}
}

func WithACMEProvider(provider *ACMEProvider) Option {
	return func(o *Options) {
		if provider == nil {
			return
		}
		o.CredRequester = provider.ChallengeCredential
		o.NewCertIssuer = provider.IssueCert
		o.RenewIssuer = provider.IssueCert
	}
}

func WithNewCertIssuer(issuer CertIssuer) Option {
	return func(o *Options) {
		o.NewCertIssuer = issuer
	}
}

func WithRenewCertIssuer(issuer CertIssuer) Option {
	return func(o *Options) {
		o.RenewIssuer = issuer
	}
}

func WithNewCertCallback(cb CertLifecycleCallback) Option {
	return func(o *Options) {
		o.OnNewCert = cb
	}
}

func WithRenewCertCallback(cb CertLifecycleCallback) Option {
	return func(o *Options) {
		o.OnRenewCert = cb
	}
}

func WithHTTP01Executor(executor HTTP01Executor) Option {
	return func(o *Options) {
		o.HTTP01Executor = executor
	}
}

func WithHTTP01Handler(handler *HTTP01Handler) Option {
	return func(o *Options) {
		o.HTTP01Handler = handler
	}
}

func WithTLSALPN01Executor(executor TLSALPN01Executor) Option {
	return func(o *Options) {
		o.TLSALPN01Executor = executor
	}
}

func WithDNS01Executor(executor DNS01Executor) Option {
	return func(o *Options) {
		o.DNS01Executor = executor
	}
}

func WithChallengeTimeout(timeout time.Duration) Option {
	return func(o *Options) {
		o.ChallengeTimeout = timeout
	}
}
