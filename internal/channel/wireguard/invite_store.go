package wireguard

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// defaultInviteExpiry is the default lifetime of an invite token when the
// caller does not specify one (3600 seconds = 1 hour).
const defaultInviteExpiry = 3600 * time.Second

// InviteToken represents a single-use or multi-use invitation to join a
// WireGuard network.  Tokens are opaque random strings; the network ID
// and ownership are stored alongside for validation.
type InviteToken struct {
	Token       string
	NetworkID   string
	OwnerUserID string
	ExpiresAt   time.Time
	MaxUses     uint32 // 0 = unlimited
	UsedCount   uint32
	CreatedAt   time.Time
}

// IsExpired reports whether the token has passed its expiry time.
func (t *InviteToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// CanUse reports whether the token may still be consumed.
func (t *InviteToken) CanUse() bool {
	if t.IsExpired() {
		return false
	}
	if t.MaxUses > 0 && t.UsedCount >= t.MaxUses {
		return false
	}
	return true
}

// InviteStore is a concurrency-safe, in-memory store for network invite
// tokens.  It is intentionally ephemeral: tokens do not survive Edge
// restarts.  Persistence can be added later if needed.
type InviteStore struct {
	mu     sync.RWMutex
	tokens map[string]*InviteToken // token string → InviteToken
}

// NewInviteStore creates an empty InviteStore.
func NewInviteStore() *InviteStore {
	return &InviteStore{
		tokens: make(map[string]*InviteToken),
	}
}

// Create generates a new invite token for the given network and stores it.
//
//   - expiresInSeconds <= 0 → default 3600s
//   - maxUses == 0 → unlimited
func (s *InviteStore) Create(networkID, ownerUserID string, expiresInSeconds uint32, maxUses uint32) (*InviteToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate invite token: %w", err)
	}
	tokenStr := hex.EncodeToString(raw)

	expiry := time.Duration(expiresInSeconds) * time.Second
	if expiry <= 0 {
		expiry = defaultInviteExpiry
	}

	tok := &InviteToken{
		Token:       tokenStr,
		NetworkID:   networkID,
		OwnerUserID: ownerUserID,
		ExpiresAt:   time.Now().Add(expiry),
		MaxUses:     maxUses,
		CreatedAt:   time.Now(),
	}

	s.mu.Lock()
	s.tokens[tokenStr] = tok
	s.mu.Unlock()

	return tok, nil
}

// Validate checks whether the token is valid for the given network.
// On success it increments UsedCount and returns the token.
func (s *InviteStore) Validate(tokenStr, networkID string) (*InviteToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.tokens[tokenStr]
	if !ok {
		return nil, fmt.Errorf("invalid invite token")
	}
	if tok.NetworkID != networkID {
		return nil, fmt.Errorf("invite token network mismatch")
	}
	if !tok.CanUse() {
		if tok.IsExpired() {
			return nil, fmt.Errorf("invite token expired")
		}
		return nil, fmt.Errorf("invite token max uses reached")
	}

	tok.UsedCount++
	return tok, nil
}

// Peek looks up a token by its string value without consuming a use.
// It returns the token's NetworkID and OwnerUserID if the token exists
// and is still usable.  The actual consumption happens later when the
// client calls HandleJoinNetwork, which invokes Validate.
// Used by the cert request flow to determine the scope for scoped certs.
func (s *InviteStore) Peek(tokenStr string) (*InviteToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tok, ok := s.tokens[tokenStr]
	if !ok {
		return nil, fmt.Errorf("invalid invite token")
	}
	if !tok.CanUse() {
		if tok.IsExpired() {
			return nil, fmt.Errorf("invite token expired")
		}
		return nil, fmt.Errorf("invite token max uses reached")
	}
	return tok, nil
}

// PurgeExpired removes all expired tokens.  Safe to call periodically.
func (s *InviteStore) PurgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, tok := range s.tokens {
		if tok.IsExpired() {
			delete(s.tokens, k)
		}
	}
}
