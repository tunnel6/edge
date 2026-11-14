package letsencrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestNewACMEProviderRequiresAccountKey(t *testing.T) {
	provider, err := NewACMEProvider(nil, "ops@example.com")
	if err == nil || provider != nil {
		t.Fatal("expected error for nil account key")
	}
}

func TestWithACMEProviderSetsCallbacks(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key failed: %v", err)
	}
	provider, err := NewACMEProvider(key, "ops@example.com")
	if err != nil {
		t.Fatalf("NewACMEProvider failed: %v", err)
	}

	opts := resolveOptions(WithACMEProvider(provider))
	if opts.CredRequester == nil {
		t.Fatal("expected challenge credential requester to be configured")
	}
	if opts.NewCertIssuer == nil || opts.RenewIssuer == nil {
		t.Fatal("expected issuer callbacks to be configured")
	}
}

func TestShouldLoadExistingACMEAccount(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil",
			err:  nil,
			want: false,
		},
		{
			name: "account already exists sentinel",
			err:  acme.ErrAccountAlreadyExists,
			want: true,
		},
		{
			name: "account already exists wrapped",
			err:  errors.Join(errors.New("wrapped"), acme.ErrAccountAlreadyExists),
			want: true,
		},
		{
			name: "http 409 conflict",
			err: &acme.Error{
				StatusCode: http.StatusConflict,
				Detail:     "already exists",
			},
			want: true,
		},
		{
			name: "other acme error",
			err: &acme.Error{
				StatusCode: http.StatusBadRequest,
				Detail:     "bad request",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		if got := shouldLoadExistingACMEAccount(tt.err); got != tt.want {
			t.Fatalf("%s: shouldLoadExistingACMEAccount()=%v, want %v", tt.name, got, tt.want)
		}
	}
}
