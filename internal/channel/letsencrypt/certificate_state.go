package letsencrypt

import "time"

func (le *LetsEncrypt) StoredCertificate(domain string) *StoredCertificate {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	return le.loadStoredCertificate(domain)
}

func (le *LetsEncrypt) HasUsableCertificate(domain string, minRemaining time.Duration) (*StoredCertificate, bool) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, false
	}

	stored := le.loadStoredCertificate(domain)
	if stored == nil {
		return nil, false
	}

	if minRemaining < 0 {
		minRemaining = 0
	}
	if stored.NotAfter.IsZero() {
		return stored, true
	}
	return stored, time.Until(stored.NotAfter) > minRemaining
}
