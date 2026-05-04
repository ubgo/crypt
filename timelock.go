package crypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Time-locked tokens — a sealed payload with a hard expiry baked in.
//
// Use cases:
//   - Password-reset email links (~1h TTL)
//   - Email-verification links (~24h TTL)
//   - Magic-login links (~5min TTL)
//   - Stateless one-time tokens
//
// The expiry is encoded into the plaintext alongside the user's
// payload, then sealed under the AEAD key. Open verifies the AEAD
// tag (integrity) and then checks the embedded expiry. No DB lookup
// needed.
//
// Wire format (inside the AEAD):
//
//	[expiry_unix:8 (big-endian)][payload:N]
//
// The whole thing is then sealed normally — so the wire format on
// the network is the same as plain Seal output (version 0x01,
// base64url-no-pad). Open via VerifyToken handles the unwrap.

// ErrExpired is returned when a token's embedded expiry is in the past.
var ErrExpired = errors.New("crypt: token expired")

// IssueToken seals payload alongside an expiry under key. Use a
// purpose-specific aad (e.g., "pwreset-v1", "email-verify-v1") to
// prevent token-type confusion across endpoints.
func IssueToken(key, payload []byte, ttl time.Duration, aad []byte) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("crypt: TTL must be positive; got %v", ttl)
	}
	expiry := time.Now().Add(ttl).Unix()
	wrapped := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(wrapped[:8], uint64(expiry))
	copy(wrapped[8:], payload)
	return Seal(key, wrapped, aad)
}

// VerifyToken opens a token, checks the embedded expiry, and returns
// the original payload.
//
// Returns ErrExpired if the token has expired (different from the
// AEAD-level errors).
func VerifyToken(key []byte, token string, aad []byte) ([]byte, error) {
	wrapped, err := Open(key, token, aad)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < 8 {
		return nil, fmt.Errorf("%w: token plaintext too short", ErrInvalidCiphertext)
	}
	expiry := int64(binary.BigEndian.Uint64(wrapped[:8]))
	if time.Now().Unix() >= expiry {
		return nil, ErrExpired
	}
	return wrapped[8:], nil
}
