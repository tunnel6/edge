package letsencrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (le *LetsEncrypt) initialize(ctx context.Context) error {
	_ = ctx
	if err := os.MkdirAll(le.opts.DataDir, 0o755); err != nil {
		return fmt.Errorf("letsencrypt: create data dir: %w", err)
	}
	if err := os.MkdirAll(le.opts.CertDir, 0o755); err != nil {
		return fmt.Errorf("letsencrypt: create cert dir: %w", err)
	}
	return nil
}

func (le *LetsEncrypt) resolveCredential(ctx context.Context) (ChallengeCredential, error) {
	cred, err := le.requestToken(ctx)
	if err == nil {
		le.setCredential(cred)
		return cred, nil
	}
	if !errors.Is(err, ErrTokenMissing) {
		return ChallengeCredential{}, err
	}

	// Backward-compatible fallback for statically configured credentials.
	state, err := loadTokenState(le.opts.TokenFile)
	if err == nil {
		cred = ChallengeCredential{
			Token:            state.Token,
			KeyAuthorization: state.KeyAuthorization,
		}
		le.setCredential(cred)
		return cred, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return ChallengeCredential{}, ErrTokenMissing
	}
	return ChallengeCredential{}, fmt.Errorf("letsencrypt: load token: %w", err)
}

func (le *LetsEncrypt) requestToken(ctx context.Context) (ChallengeCredential, error) {
	if le.opts.TokenRequester == nil {
		return ChallengeCredential{}, ErrTokenMissing
	}

	cred, err := le.opts.TokenRequester(ctx)
	if err != nil {
		return ChallengeCredential{}, fmt.Errorf("letsencrypt: request token: %w", err)
	}
	return normalizeCredential(cred)
}

func (le *LetsEncrypt) setCredential(cred ChallengeCredential) {
	le.mu.Lock()
	le.token = cred.Token
	le.keyAuthorization = cred.KeyAuthorization
	le.mu.Unlock()
}

func normalizeCredential(cred *ChallengeCredential) (ChallengeCredential, error) {
	if cred == nil {
		return ChallengeCredential{}, ErrTokenMissing
	}

	out := ChallengeCredential{
		Token:            strings.TrimSpace(cred.Token),
		KeyAuthorization: strings.TrimSpace(cred.KeyAuthorization),
	}
	if out.Token == "" {
		return ChallengeCredential{}, ErrInvalidChallenge
	}
	return out, nil
}

func (le *LetsEncrypt) saveCertificate(domain string, method ChallengeMethod, material *CertMaterial) (*StoredCertificate, error) {
	if material == nil || len(material.CertificatePEM) == 0 || len(material.PrivateKeyPEM) == 0 {
		return nil, ErrInvalidCertData
	}

	paths := certPathsForDomain(le.opts.CertDir, domain)
	if err := os.WriteFile(paths.CertificatePath, material.CertificatePEM, 0o644); err != nil {
		return nil, fmt.Errorf("letsencrypt: write certificate: %w", err)
	}
	if err := os.WriteFile(paths.PrivateKeyPath, material.PrivateKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("letsencrypt: write private key: %w", err)
	}
	if len(material.ChainPEM) > 0 {
		if err := os.WriteFile(paths.ChainPath, material.ChainPEM, 0o644); err != nil {
			return nil, fmt.Errorf("letsencrypt: write certificate chain: %w", err)
		}
	}

	now := time.Now()
	stored := &StoredCertificate{
		Domain:          domain,
		Method:          method,
		CertificatePath: paths.CertificatePath,
		PrivateKeyPath:  paths.PrivateKeyPath,
		ChainPath:       paths.ChainPath,
		MetaPath:        paths.MetaPath,
		UpdatedAt:       now,
		NotAfter:        material.NotAfter,
	}

	meta := certMeta{
		Domain:          stored.Domain,
		Method:          stored.Method,
		CertificatePath: stored.CertificatePath,
		PrivateKeyPath:  stored.PrivateKeyPath,
		ChainPath:       stored.ChainPath,
		UpdatedAt:       stored.UpdatedAt,
		NotAfter:        stored.NotAfter,
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: marshal certificate meta: %w", err)
	}
	if err := os.WriteFile(paths.MetaPath, data, 0o644); err != nil {
		return nil, fmt.Errorf("letsencrypt: write certificate meta: %w", err)
	}

	return stored, nil
}

func (le *LetsEncrypt) loadStoredCertificate(domain string) *StoredCertificate {
	paths := certPathsForDomain(le.opts.CertDir, domain)
	data, err := os.ReadFile(paths.MetaPath)
	if err != nil {
		return nil
	}
	var meta certMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}
	return &StoredCertificate{
		Domain:          meta.Domain,
		Method:          meta.Method,
		CertificatePath: meta.CertificatePath,
		PrivateKeyPath:  meta.PrivateKeyPath,
		ChainPath:       meta.ChainPath,
		MetaPath:        paths.MetaPath,
		UpdatedAt:       meta.UpdatedAt,
		NotAfter:        meta.NotAfter,
	}
}

type certFilePaths struct {
	CertificatePath string
	PrivateKeyPath  string
	ChainPath       string
	MetaPath        string
}

func certPathsForDomain(certDir, domain string) certFilePaths {
	base := sanitizeDomainForFile(domain)
	return certFilePaths{
		CertificatePath: filepath.Join(certDir, base+".crt"),
		PrivateKeyPath:  filepath.Join(certDir, base+".key"),
		ChainPath:       filepath.Join(certDir, base+".chain.crt"),
		MetaPath:        filepath.Join(certDir, base+".json"),
	}
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func sanitizeDomainForFile(domain string) string {
	domain = normalizeDomain(domain)
	if domain == "" {
		return "unknown"
	}

	var b strings.Builder
	b.Grow(len(domain))
	for i := 0; i < len(domain); i++ {
		ch := domain[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch)
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		case ch == '.', ch == '-':
			b.WriteByte(ch)
		case ch == '*':
			b.WriteString("wildcard")
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func loadTokenState(path string) (*tokenState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	state := &tokenState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, err
	}
	state.Token = strings.TrimSpace(state.Token)
	state.KeyAuthorization = strings.TrimSpace(state.KeyAuthorization)
	if state.Token == "" {
		return nil, ErrTokenMissing
	}
	return state, nil
}

func saveTokenState(path string, state *tokenState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	err := errs[0]
	for i := 1; i < len(errs); i++ {
		err = fmt.Errorf("%w; %v", err, errs[i])
	}
	return err
}
