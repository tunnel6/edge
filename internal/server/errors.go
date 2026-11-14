package server

import "errors"

// Const
var (
	// Verify
	ErrNotEdgeOwner = errors.New("permission denied: not edge owner")
	// Auth/session identity guards
	ErrAuthIdentityMismatch = errors.New("auth identity mismatch")
	ErrCSRIdentityMismatch  = errors.New("csr identity mismatch")

	// Error
	ErrNoClientCertificate  = errors.New("no client certificate")
	ErrInvalidCertificateCN = errors.New("invalid certificate CN format")

	// Error
	ErrNotTLSConnection = errors.New("not a TLS connection")

	// Error
)
