package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AEAD authenticated encryption using AES-256-GCM.
//
// Output of Seal is base64url-no-pad encoding of the binary layout:
//
//	[version:1=0x01][nonce:12][ciphertext:N][tag:16]
//
// The version byte enables forward-compatibility. Future algorithms
// receive new version numbers; decoders explicitly enumerate the
// versions they understand.
//
// AES-256-GCM is the default AEAD because:
//   - It's the NIST-standardized authenticated mode (SP 800-38D).
//   - It runs in hardware on every modern x86_64 server (AES-NI) and
//     ARMv8 mobile/server CPU.
//   - It produces minimal overhead: 28 bytes added to plaintext (1
//     version + 12 nonce + 16 tag).
//   - Both Go's std crypto/cipher and Node's crypto.createCipheriv
//     support it identically, enabling cross-language wire compat.

// Seal encrypts plaintext under key with optional additional
// authenticated data (AAD) and returns the ciphertext as a base64url
// no-pad string.
//
// The AAD is authenticated but not encrypted: it can be any context-
// binding data (e.g., user ID, tenant ID, message type) that callers
// also pass to Open. If aad differs at Open time, decryption fails
// with ErrTampered.
//
// key must be exactly 32 bytes (AES-256). Nonces are generated from
// crypto/rand on every call; encrypting the same plaintext twice with
// the same key produces different ciphertexts.
//
// Errors:
//   - ErrInvalidKey if key length != 32.
//   - Other errors only on crypto/rand failure (rare).
func Seal(key, plaintext, aad []byte) (string, error) {
	return sealWithNonce(key, plaintext, aad, nil)
}

// Open decrypts a base64url-no-pad ciphertext produced by Seal under
// the same key and aad. Returns the plaintext bytes.
//
// Errors:
//   - ErrInvalidKey if key length != 32.
//   - ErrInvalidCiphertext if the input is not valid base64url.
//   - ErrCiphertextTooShort if the decoded bytes are smaller than
//     the minimum (29 bytes).
//   - ErrUnsupportedVersion if the version byte is not 0x01.
//   - ErrTampered if the GCM tag does not match (wrong key, wrong
//     AAD, or modified ciphertext).
func Open(key []byte, ciphertext string, aad []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("%w: AEAD requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}

	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < aeadMinSize {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != VersionAEADv1 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypt: cipher.NewGCM: %w", err)
	}

	nonce := raw[1:aeadHeaderSize]
	body := raw[aeadHeaderSize:]

	plaintext, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	return plaintext, nil
}

// sealWithNonce is the test-injectable form of Seal. When nonce is
// nil, a fresh random nonce is generated; when non-nil, it must be
// exactly aeadNonceSize bytes. This is used only by deterministic
// test vectors and must never be exposed to callers, because reusing
// a nonce with the same key catastrophically breaks GCM.
func sealWithNonce(key, plaintext, aad, nonce []byte) (string, error) {
	if len(key) != AEADKeySize {
		return "", fmt.Errorf("%w: AEAD requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypt: cipher.NewGCM: %w", err)
	}

	if nonce == nil {
		nonce = make([]byte, aeadNonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return "", fmt.Errorf("crypt: random nonce: %w", err)
		}
	} else if len(nonce) != aeadNonceSize {
		return "", fmt.Errorf("crypt: nonce must be %d bytes; got %d", aeadNonceSize, len(nonce))
	}

	out := make([]byte, 0, aeadHeaderSize+len(plaintext)+aeadTagSize)
	out = append(out, VersionAEADv1)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Sealer holds a pre-validated AEAD key and its bound cipher state.
//
// A Sealer is safe for concurrent use by multiple goroutines: the
// underlying cipher.AEAD instance is itself concurrent-safe per Go
// std lib documentation.
//
// Prefer Sealer over the package-level Seal/Open functions when:
//   - You encrypt many times with the same key (avoids re-validating
//     and re-constructing the cipher.AEAD on every call).
//   - You want to inject a sealer as a service dependency for testing.
//   - You want to bind the key into a long-lived component (plugin,
//     service, etc.) rather than threading it through every call.
//
// Design choice — a Sealer is immutable and has no Rekey method.
// The key is bound once at NewSealer and never changes. This is
// deliberate:
//   - Immutability is what makes a Sealer lock-free to share across
//     goroutines; a mutable key would force a mutex or atomic.Pointer
//     load on every Seal/Open just to serve a rare swap.
//   - A hard key swap would instantly make all previously-sealed
//     ciphertext undecryptable. Real rotation needs old and new keys
//     live at once — that is [KeyRing]'s job, not a setter's.
//
// To rotate keys, choose by need:
//   - Restart-free rotation with a decrypt-only grace window for old
//     data: use [KeyRing] (writes with the active key, reads dispatch
//     by the kid embedded in each ciphertext).
//   - Single-key swap at a safe boundary (e.g. config reload): build a
//     fresh Sealer and replace the pointer, guarding the shared field
//     with sync/atomic.Pointer[Sealer] so concurrent callers stay safe.
//     Reassigning a plain *Sealer variable under live readers is a data
//     race.
//
// There is intentionally no package-level default key or global
// SetKey. AEAD operations require an explicit key (call-time for
// Seal/Open, construction-time for Sealer) so there is no hidden
// mutable state, no zero-key footgun, and tests never share a key.
type Sealer struct {
	gcm cipher.AEAD
}

// NewSealer constructs a Sealer from a 32-byte AES-256 key.
//
// The cipher.AEAD is constructed once and reused across Seal/Open
// calls, eliminating per-call setup overhead.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("%w: AEAD requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypt: cipher.NewGCM: %w", err)
	}
	return &Sealer{gcm: gcm}, nil
}

// Seal encrypts plaintext with optional aad and returns a base64url
// no-pad ciphertext.
func (s *Sealer) Seal(plaintext, aad []byte) (string, error) {
	nonce := make([]byte, aeadNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypt: random nonce: %w", err)
	}
	out := make([]byte, 0, aeadHeaderSize+len(plaintext)+aeadTagSize)
	out = append(out, VersionAEADv1)
	out = append(out, nonce...)
	out = s.gcm.Seal(out, nonce, plaintext, aad)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a Seal-produced ciphertext.
func (s *Sealer) Open(ciphertext string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < aeadMinSize {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != VersionAEADv1 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}

	nonce := raw[1:aeadHeaderSize]
	body := raw[aeadHeaderSize:]

	plaintext, err := s.gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	return plaintext, nil
}
