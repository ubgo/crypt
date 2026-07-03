package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// randReader is the CSPRNG source for every random-byte read in this
// package (nonces, IVs, salts, key material). It is a package var
// solely so tests can substitute a failing reader to exercise the
// otherwise-unreachable RNG-failure error branches. Production code
// never reassigns it; it always points at crypto/rand.Reader. Never
// reassign it outside tests.
var randReader io.Reader = rand.Reader

// Random helpers wrap crypto/rand with typed output formats. All
// helpers source bytes from the operating system's CSPRNG and are
// safe for cryptographic use (token generation, ID generation,
// session secrets, CSRF tokens).
//
// For an AEAD key specifically, prefer RandomBytes(crypt.AEADKeySize)
// to make the intent obvious to readers.

// RandomBytes returns n cryptographically-random bytes from
// crypto/rand.
//
// Errors are returned only on rare OS-level random source failure.
// Returns ErrInvalidKey for n <= 0.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypt: RandomBytes n must be positive; got %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return nil, fmt.Errorf("crypt: random read: %w", err)
	}
	return buf, nil
}

// RandomToken returns n random bytes encoded as URL-safe base64
// without padding. Suitable for API keys, magic-link tokens, CSRF
// tokens, session IDs, anywhere you need a URL-safe random string.
//
// Output length is ceil(n * 4 / 3) characters, no '=' padding.
// Common sizes:
//
//	RandomToken(16) -> 22 chars  (~96 bits of entropy)
//	RandomToken(24) -> 32 chars  (~144 bits)
//	RandomToken(32) -> 43 chars  (~192 bits)
//
// For most token use cases, 16 or 24 bytes is plenty. 32 bytes is
// the conservative choice for high-value tokens (root API keys,
// password-reset links).
func RandomToken(n int) (string, error) {
	buf, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// RandomHex returns n random bytes encoded as lowercase hexadecimal.
// Suitable for IDs, filenames, ETag-style content addressing.
//
// Output length is exactly 2 * n characters.
//
//	RandomHex(8)  -> 16 chars
//	RandomHex(16) -> 32 chars
//	RandomHex(32) -> 64 chars
//
// Hex is preferred over base64 when the consumer cannot handle
// base64 characters (for instance, in filesystem paths on case-
// insensitive filesystems).
func RandomHex(n int) (string, error) {
	buf, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
