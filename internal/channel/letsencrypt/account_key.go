package letsencrypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrInvalidACMEAccountKey = errors.New("letsencrypt: invalid acme account key")

func CreateACMEAccountKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt: generate acme account key: %w", err)
	}
	return key, nil
}

func LoadOrCreateACMEAccountKey(path string) (crypto.Signer, error) {
	key, err := LoadACMEAccountKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err = CreateACMEAccountKey()
	if err != nil {
		return nil, err
	}
	if err := SaveACMEAccountKey(path, key); err != nil {
		// Handle process races where another process already created the key.
		if loaded, loadErr := LoadACMEAccountKey(path); loadErr == nil {
			return loaded, nil
		}
		return nil, err
	}
	return key, nil
}

func LoadACMEAccountKey(path string) (crypto.Signer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("letsencrypt: acme account key path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidACMEAccountKey
	}

	key, err := parsePEMPrivateKey(block)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidACMEAccountKey
	}
	return signer, nil
}

func SaveACMEAccountKey(path string, key crypto.Signer) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("letsencrypt: acme account key path is required")
	}
	if key == nil {
		return ErrInvalidACMEAccountKey
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("letsencrypt: marshal acme account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("letsencrypt: create key dir: %w", err)
		}
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, pemData, 0o600); err != nil {
		return fmt.Errorf("letsencrypt: write acme account key: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("letsencrypt: move acme account key: %w", err)
	}
	return nil
}

func parsePEMPrivateKey(block *pem.Block) (any, error) {
	if block == nil {
		return nil, ErrInvalidACMEAccountKey
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidACMEAccountKey, err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidACMEAccountKey, err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidACMEAccountKey, err)
		}
		return key, nil
	default:
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, ErrInvalidACMEAccountKey
	}
}
