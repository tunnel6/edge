package server

import (
	"fmt"
	"strings"
)

// enrollmentCredential has one wire representation shared by every client.
// Supported schemes are selected by the server; client input never supplies privileges.
type enrollmentCredential struct {
	scheme   string
	provider string
	secret   string
}

func parseEnrollmentToken(token string) (enrollmentCredential, error) {
	scheme, value, ok := strings.Cut(token, ":")
	if !ok {
		return enrollmentCredential{}, fmt.Errorf("prefixed enrollment token required")
	}
	credential := enrollmentCredential{scheme: scheme, secret: value}
	switch scheme {
	case "public":
		if value == "" {
			return credential, nil
		}
		return enrollmentCredential{}, fmt.Errorf("public enrollment takes no credential")
	case "invite", "pair":
	case "oauth":
		provider, secret, found := strings.Cut(value, ":")
		if !found || strings.TrimSpace(provider) == "" || strings.TrimSpace(provider) != provider {
			return enrollmentCredential{}, fmt.Errorf("oauth token requires a provider")
		}
		credential.provider, credential.secret = provider, secret
	default:
		return enrollmentCredential{}, fmt.Errorf("unsupported enrollment scheme")
	}
	if strings.TrimSpace(credential.secret) == "" || strings.TrimSpace(credential.secret) != credential.secret {
		return enrollmentCredential{}, fmt.Errorf("empty or malformed enrollment credential")
	}
	return credential, nil
}
