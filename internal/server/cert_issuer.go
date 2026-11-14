package server

import (
	"context"
	"errors"
	"time"

	"icool.io/yat/edge/internal/upstream/certmgr"
	logger "icool.io/yat/edge/pkg/log"
)

var ErrCertServiceUnavailable = errors.New("certificate signing service not available")

// InviteTokenVerifier validates invite tokens and returns the associated
// network ID. Implemented by the WireGuard InviteStore and wired into
// the Server during channel setup.
type InviteTokenVerifier interface {
	// Peek looks up a token without consuming a use, returning the
	// associated network ID and owner user ID.
	Peek(tokenStr string) (networkID string, ownerUserID string, err error)
}

// PairTokenVerifier validates one-time pairing tokens.
// Implemented by PairingManager and wired into the Server at startup.
type PairTokenVerifier interface {
	Verify(token string) (string, error)
}

type IssueRequest struct {
	EdgeID   string
	Role     string
	DeviceID string
	CSR      []byte
	// Scopes limits what the certificate can access. Empty = full access.
	// Each entry is a scope token, e.g. "network:<networkID>".
	Scopes []string
}

// CertIssueResult contains the result of a certificate issuance operation.
type CertIssueResult struct {
	CertificatePEM   []byte
	CertificateChain []byte
	CACertificatePEM []byte
	SerialNumber     string
	ExpiresAt        time.Time
}

// ClientCertIssuer defines the interface for issuing client certificates.
type ClientCertIssuer interface {
	Issue(ctx context.Context, req *IssueRequest) (*CertIssueResult, error)
}

// edgeCACertIssuer issues client certificates using the local EdgeCA.
type edgeCACertIssuer struct {
	certBundle *certmgr.CertificateBundle
}

// NewClientCertIssuer creates a ClientCertIssuer that uses local EdgeCA for signing.
func NewClientCertIssuer(bundle *certmgr.CertificateBundle) ClientCertIssuer {
	return &edgeCACertIssuer{
		certBundle: bundle,
	}
}

func (i *edgeCACertIssuer) Issue(ctx context.Context, req *IssueRequest) (*CertIssueResult, error) {
	logger.Debugf("[CertIssuer] Issue request: deviceID=%s", req.DeviceID)

	if i.certBundle == nil {
		logger.Error("certificate bundle not available, cannot sign certificates")
		return nil, ErrCertServiceUnavailable
	}

	edgeCA, err := i.certBundle.GetEdgeCA()
	if err != nil || edgeCA == nil {
		logger.Errorf("EdgeCA not available: %v", err)
		return nil, ErrCertServiceUnavailable
	}

	validity := 30 * 24 * time.Hour // 30 天

	result, signErr := edgeCA.SignClientCSR(req.CSR, req.DeviceID, validity, req.Scopes, certmgr.EdgeAuthorization{EdgeID: req.EdgeID, Role: req.Role})
	if signErr != nil {
		logger.Errorf("client cert signing failed: %v", signErr)
		return nil, signErr
	}

	logger.Infof("client cert signed locally, device: %s, serial: %s", req.DeviceID, result.SerialNumber)

	return &CertIssueResult{
		CertificatePEM:   result.CertPEM,
		CertificateChain: result.ChainPEM,
		CACertificatePEM: i.certBundle.RootCACertPEM,
		SerialNumber:     result.SerialNumber,
		ExpiresAt:        result.ExpiresAt,
	}, nil
}
