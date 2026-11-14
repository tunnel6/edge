package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"icool.io/yat/edge/internal/upstream/certmgr"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PairingManager manages pairing tokens for mTLS-based pairing flow.
// Tokens are one-time use and expire after 1 hour.
type PairingManager struct {
	mu            sync.Mutex
	tokens        map[string]*pairToken
	consumed      map[string]bool
	stateFile     string
	tunnelAddress string // mTLS tunnel address returned in pairing response
}

type pairToken struct {
	value     string
	createdAt time.Time
	used      bool
	role      string
}

// NewPairingManager creates a new PairingManager.
func NewPairingManager(tunnelAddress string) *PairingManager {
	return &PairingManager{tokens: make(map[string]*pairToken), consumed: make(map[string]bool), tunnelAddress: tunnelAddress}
}

// Persist consumed bootstrap tokens so restarting with PAIR_TOKEN cannot replay them.
func (pm *PairingManager) SetStateFile(path string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &pm.consumed); err != nil {
			return err
		}
		if pm.consumed == nil {
			pm.consumed = make(map[string]bool)
		}
	}
	pm.stateFile = path
	return nil
}

func tokenHash(token string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(token))) }

// Verify consumes before signing. Enrollment failures require a new token;
// clients must never blindly replay an enrollment whose response may be lost.
func (pm *PairingManager) Verify(token string) (string, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	entry, ok := pm.tokens[token]
	if !ok || entry.used || pm.consumed[tokenHash(token)] || time.Since(entry.createdAt) > time.Hour {
		return "", fmt.Errorf("invalid or expired pairing token")
	}
	pm.consumed[tokenHash(token)] = true
	if pm.stateFile != "" {
		data, err := json.Marshal(pm.consumed)
		if err == nil {
			err = os.MkdirAll(filepath.Dir(pm.stateFile), 0700)
		}
		if err == nil {
			err = os.WriteFile(pm.stateFile+".tmp", data, 0600)
		}
		if err == nil {
			err = os.Rename(pm.stateFile+".tmp", pm.stateFile)
		}
		if err != nil {
			delete(pm.consumed, tokenHash(token))
			return "", fmt.Errorf("persist consumed token: %w", err)
		}
	}
	entry.used = true
	return entry.role, nil
}

// TunnelAddress returns the mTLS tunnel address for pairing responses.
func (pm *PairingManager) TunnelAddress() string {
	return pm.tunnelAddress
}

// GenerateToken creates a new one-time pairing token.
func (pm *PairingManager) GenerateToken() string { return pm.GenerateTokenForRole(certmgr.RoleDevice) }

func (pm *PairingManager) GenerateTokenForRole(role string) string {
	if role != certmgr.RoleOwner {
		role = certmgr.RoleDevice
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate pairing token: %v", err))
	}
	token := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

	pm.tokens[token] = &pairToken{
		value:     token,
		createdAt: time.Now(),
		used:      false,
		role:      role,
	}

	pm.cleanupExpiredLocked()
	return token
}

// RegisterToken pre-registers a specific token for auto-pairing.
func (pm *PairingManager) RegisterToken(token string) {
	pm.RegisterTokenForRole(token, certmgr.RoleDevice)
}

func (pm *PairingManager) RegisterTokenForRole(token, role string) {
	if role != certmgr.RoleOwner {
		role = certmgr.RoleDevice
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.tokens[token] = &pairToken{
		value:     token,
		createdAt: time.Now(),
		used:      false,
		role:      role,
	}
}

// HasValidToken returns true if there are any unused, unexpired tokens.
func (pm *PairingManager) HasValidToken() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, t := range pm.tokens {
		if !t.used && !pm.consumed[tokenHash(t.value)] && time.Since(t.createdAt) <= time.Hour {
			return true
		}
	}
	return false
}

// cleanupExpiredLocked removes expired tokens. Caller must hold pm.mu.
func (pm *PairingManager) cleanupExpiredLocked() {
	for k, t := range pm.tokens {
		if time.Since(t.createdAt) > time.Hour {
			delete(pm.tokens, k)
		}
	}
}
