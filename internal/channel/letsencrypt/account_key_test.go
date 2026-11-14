package letsencrypt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateACMEAccountKey(t *testing.T) {
	key, err := CreateACMEAccountKey()
	if err != nil {
		t.Fatalf("CreateACMEAccountKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected ecdsa private key, got %T", key)
	}
}

func TestLoadOrCreateACMEAccountKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "acme-account.key")

	key1, err := LoadOrCreateACMEAccountKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateACMEAccountKey(create) failed: %v", err)
	}
	key2, err := LoadOrCreateACMEAccountKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateACMEAccountKey(load) failed: %v", err)
	}

	pub1, err := signerPublicDER(key1)
	if err != nil {
		t.Fatalf("marshal pub1 failed: %v", err)
	}
	pub2, err := signerPublicDER(key2)
	if err != nil {
		t.Fatalf("marshal pub2 failed: %v", err)
	}
	if !bytes.Equal(pub1, pub2) {
		t.Fatal("loaded key does not match saved key")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key file failed: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("unexpected file perm: got=%#o want=%#o", got, 0o600)
		}
	}
}

func TestLoadACMEAccountKeyInvalidData(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "invalid.key")
	if err := os.WriteFile(keyPath, []byte("not-a-pem"), 0o600); err != nil {
		t.Fatalf("write invalid data failed: %v", err)
	}
	_, err := LoadACMEAccountKey(keyPath)
	if err == nil {
		t.Fatal("expected load error for invalid key data")
	}
	if !errors.Is(err, ErrInvalidACMEAccountKey) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func signerPublicDER(signer crypto.Signer) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(signer.Public())
}
