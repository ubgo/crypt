package crypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// HMAC signing primitives. HMAC-SHA256 is the symmetric MAC of choice
// for webhook signing, URL parameter integrity, and any case where
// both signer and verifier hold the same secret key.
//
// For asymmetric public-key signing (signer holds private, verifier
// holds public), see future Ed25519 support (v2 roadmap).

// Sign returns an HMAC-SHA256 tag computed over data with key.
// The output is always 32 bytes.
//
// HMAC is unkeyed-collision-resistant: any key length works
// cryptographically, but for SHA-256 the recommendation is at least
// 32 bytes for full security strength.
func Sign(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// Verify checks that mac is a valid HMAC-SHA256 of data under key,
// using a constant-time comparison to prevent timing attacks.
//
// Returns false (without error) if mac is the wrong length. This
// avoids forcing callers to wrap every Verify call in error handling
// for a malformed-input case that's rare and equivalent to a verify
// failure anyway.
func Verify(key, data, mac []byte) bool {
	if len(mac) != sha256.Size {
		return false
	}
	expected := Sign(key, data)
	return hmac.Equal(expected, mac)
}

// ConstantTimeEqual reports whether a and b have equal contents,
// in time independent of the contents.
//
// Use this instead of `bytes.Equal` for any comparison involving
// secret material: API keys, MACs, password hashes, session tokens.
// `bytes.Equal` short-circuits at the first mismatch and leaks
// timing information that an attacker can exploit to recover the
// secret one byte at a time.
//
// For inputs of different lengths, returns false in constant time
// with respect to the equal-length comparison. The length check
// itself is not constant-time (it cannot be, in Go), but in nearly
// all practical applications the inputs already have a known fixed
// length (e.g., a 32-byte HMAC tag).
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
