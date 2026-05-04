package crypt

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// bcrypt password hashing — for compatibility with systems that
// already store bcrypt hashes (Rails, Django, Node bcrypt, etc.).
//
// New systems should use HashPassword (argon2id) instead. Bcrypt
// is retained here only to enable migration paths where existing
// users have bcrypt hashes that need to be verifiable until they
// next log in (at which point the application can re-hash with
// argon2id).
//
// Note bcrypt's 72-byte input limit: passwords longer than 72 bytes
// are silently truncated by bcrypt. The wrapper rejects them
// explicitly to avoid surprise.

const bcryptMaxInputLen = 72

// DefaultBcryptCost is bcrypt's recommended cost factor as of 2026.
// Higher = slower = more brute-force resistant. Each +1 doubles work.
const DefaultBcryptCost = 12

// HashPasswordBcrypt hashes plaintext using bcrypt at the given cost.
// Pass DefaultBcryptCost (12) unless you have a specific reason to
// deviate.
//
// Returns an error if the plaintext exceeds 72 bytes (bcrypt's hard
// input limit) — bcrypt would silently truncate, which is a foot-gun.
//
// Deprecated: Use HashPassword (argon2id) for new code. Bcrypt is
// retained for migration scenarios.
func HashPasswordBcrypt(plaintext string, cost int) (string, error) {
	if len(plaintext) > bcryptMaxInputLen {
		return "", fmt.Errorf("crypt: bcrypt input must be <= %d bytes; got %d (use HashPassword for longer)", bcryptMaxInputLen, len(plaintext))
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("crypt: bcrypt cost must be in [%d, %d]; got %d", bcrypt.MinCost, bcrypt.MaxCost, cost)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", fmt.Errorf("crypt: bcrypt: %w", err)
	}
	return string(hash), nil
}

// VerifyPasswordBcrypt compares plaintext against a bcrypt-format
// hash string (e.g., "$2a$12$..."). Constant-time internally.
//
// Returns:
//   - (true, nil) on match
//   - (false, nil) on mismatch
//   - (false, ErrInvalidPasswordHash) on malformed hash
//
// Deprecated: Use VerifyPassword for new code. Bcrypt is retained
// for migration scenarios.
func VerifyPasswordBcrypt(plaintext, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if errors.Is(err, bcrypt.ErrHashTooShort) ||
		errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
	}
	// Other errors (e.g. unsupported version): treat as malformed.
	return false, fmt.Errorf("%w: %v", ErrInvalidPasswordHash, err)
}
