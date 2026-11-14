// Package auth defines the authentication interfaces for Edge.
// The first version only supports mTLS (device certificate authentication).
// The Provider interface is reserved for a future federated identity integration.
package auth

import (
	"context"
	"crypto/x509"
)

// Identity represents an authenticated entity (device or user).
type Identity struct {
	// DeviceID is the unique identifier of the device (extracted from client certificate).
	DeviceID string
	// UserID is the optional federated subject (reserved for future identity providers).
	UserID string
	// Roles contains the roles assigned to this identity.
	Roles []string
	// Metadata contains additional key-value pairs.
	Metadata map[string]string
}

// Provider defines the interface for authenticating requests.
// Different implementations can support different authentication methods:
// - OIDCProvider: authenticates via OIDC token (future)
type Provider interface {
	// Authenticate verifies the request and returns the authenticated identity.
	// Returns nil identity and nil error if authentication is not applicable.
	// Returns nil identity and non-nil error if authentication fails.
	Authenticate(ctx context.Context, clientCerts []*x509.Certificate) (*Identity, error)

	// Name returns the name of this authentication provider.
	Name() string
}
