package letsencrypt

import (
	"context"
	"errors"
	"net"
	"time"
)

type ChallengeMethod string

const (
	ChallengeHTTP01    ChallengeMethod = "http-01"
	ChallengeTLSALPN01 ChallengeMethod = "tls-alpn-01"
	ChallengeDNS01     ChallengeMethod = "dns-01"
)

const DefaultDNS01Guidance = "当前环境无法使用 http-01 / tls-alpn-01，请引导用户使用 DNS-01 挑战并配置对应 DNS TXT 记录。"
const DefaultACMEStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
const DefaultACMEProductionDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
const defaultTokenFileName = "letsencrypt.token.json"
const defaultCustomCertDirName = "custome_certs"

var (
	ErrNotImplemented    = errors.New("letsencrypt: challenge implementation not provided yet")
	ErrNoViableChallenge = errors.New("letsencrypt: no viable challenge method")
	ErrTokenMissing      = errors.New("letsencrypt: token missing and token requester is not configured")
	ErrIssuerMissing     = errors.New("letsencrypt: certificate issuer callback is not configured")
	ErrInvalidDomain     = errors.New("letsencrypt: domain is required")
	ErrInvalidCertData   = errors.New("letsencrypt: invalid certificate material")
	ErrChallengeFailed   = errors.New("letsencrypt: challenge failed")
	ErrInvalidChallenge  = errors.New("letsencrypt: invalid challenge credential")

	ErrDNSRecordNotFound = errors.New("letsencrypt: dns-01 TXT record not found")
)

type Challenge interface {
	Method() ChallengeMethod
	Validate(opts *Options) error
	Start(ctx context.Context, req *ChallengeStartRequest) error
}

type ChallengeStartRequest struct {
	Domain           string
	Method           ChallengeMethod
	ACMEDirectoryURL string
	Token            string
	KeyAuthorization string
	ACMEOrderURL     string
	ACMEFinalizeURL  string
	ACMEAuthzURL     string
	ACMEChallengeURL string
}

type HTTP01Request struct {
	Domain           string
	Listener         net.Listener
	ACMEDirectoryURL string
	Token            string
	KeyAuthorization string
	ChallengePath    string
}

type TLSALPN01Request struct {
	Domain           string
	Listener         net.Listener
	ACMEDirectoryURL string
	Token            string
	KeyAuthorization string
}

type DNS01Request struct {
	Domain           string
	Provider         string
	ACMEDirectoryURL string
	Token            string
	KeyAuthorization string
	ACMEOrderURL     string
	ACMEFinalizeURL  string
	ACMEAuthzURL     string
	ACMEChallengeURL string
}

type HTTP01Executor func(ctx context.Context, req *HTTP01Request) error
type TLSALPN01Executor func(ctx context.Context, req *TLSALPN01Request) error
type DNS01Executor func(ctx context.Context, req *DNS01Request) error

type ChallengeCredential struct {
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization,omitempty"`
	ACMEOrderURL     string `json:"acme_order_url,omitempty"`
	ACMEFinalizeURL  string `json:"acme_finalize_url,omitempty"`
	ACMEAuthzURL     string `json:"acme_authz_url,omitempty"`
	ACMEChallengeURL string `json:"acme_challenge_url,omitempty"`
}

type TokenRequester func(ctx context.Context) (*ChallengeCredential, error)
type ChallengeCredentialRequester func(ctx context.Context, req *ChallengeCredentialRequest) (*ChallengeCredential, error)

type ChallengeCredentialRequest struct {
	Domain           string
	Method           ChallengeMethod
	ACMEDirectoryURL string
}

type CertIssuer func(ctx context.Context, req *IssueRequest) (*CertMaterial, error)

type CertLifecycleCallback func(ctx context.Context, event CertEvent)

type CertOperation string

const (
	OperationNew   CertOperation = "new"
	OperationRenew CertOperation = "renew"
)

type CertEventStage string

const (
	EventStarted   CertEventStage = "started"
	EventSucceeded CertEventStage = "succeeded"
	EventFailed    CertEventStage = "failed"
)

type CertEvent struct {
	Operation CertOperation
	Stage     CertEventStage
	Domain    string
	Method    ChallengeMethod
	Stored    *StoredCertificate
	Err       error
}

type IssueRequest struct {
	Domain           string
	ACMEDirectoryURL string
	Token            string
	KeyAuthorization string
	ACMEOrderURL     string
	ACMEFinalizeURL  string
	ACMEAuthzURL     string
	ACMEChallengeURL string
	Method           ChallengeMethod
	Stored           *StoredCertificate
}

type CertMaterial struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	ChainPEM       []byte
	NotAfter       time.Time
}

type StoredCertificate struct {
	Domain          string
	Method          ChallengeMethod
	CertificatePath string
	PrivateKeyPath  string
	ChainPath       string
	MetaPath        string
	UpdatedAt       time.Time
	NotAfter        time.Time
}

type tokenState struct {
	Token            string    `json:"token"`
	KeyAuthorization string    `json:"key_authorization,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type certMeta struct {
	Domain          string          `json:"domain"`
	Method          ChallengeMethod `json:"method"`
	CertificatePath string          `json:"certificate_path"`
	PrivateKeyPath  string          `json:"private_key_path"`
	ChainPath       string          `json:"chain_path,omitempty"`
	UpdatedAt       time.Time       `json:"updated_at"`
	NotAfter        time.Time       `json:"not_after,omitempty"`
}
