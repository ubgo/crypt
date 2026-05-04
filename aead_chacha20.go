package crypt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20-Poly1305 AEAD — alternative to AES-256-GCM for hardware
// without AES-NI (older ARM, embedded devices). Same wire format
// shape as v1, with version byte 0x02:
//
//	[0x02][nonce:12][ciphertext:N][tag:16]
//
// Use it when:
//   - Target hardware lacks AES-NI (you'll see worse AES-GCM
//     performance vs ChaCha20).
//   - You want defense-in-depth diversity (different cipher family).
//
// Otherwise, prefer Seal (AES-256-GCM) — it's the default because
// AES-NI is ubiquitous on modern x86_64 and ARMv8.

// SealChaCha20 encrypts plaintext under a 32-byte ChaCha20-Poly1305
// key with optional AAD and returns base64url-no-pad ciphertext
// tagged with version byte 0x02.
func SealChaCha20(key, plaintext, aad []byte) (string, error) {
	return sealChaCha20WithNonce(key, plaintext, aad, nil)
}

// OpenChaCha20 decrypts a v2 ciphertext (ChaCha20-Poly1305).
//
// Errors:
//   - ErrInvalidKey if key length != 32.
//   - ErrInvalidCiphertext on bad base64url.
//   - ErrCiphertextTooShort if too small.
//   - ErrUnsupportedVersion if version byte != 0x02.
//   - ErrTampered on auth failure.
func OpenChaCha20(key []byte, ciphertext string, aad []byte) ([]byte, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("%w: ChaCha20 requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}

	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < aeadMinSize {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != VersionAEADv2 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}

	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: chacha20poly1305.New: %w", err)
	}

	nonce := raw[1:aeadHeaderSize]
	body := raw[aeadHeaderSize:]

	plaintext, err := c.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	return plaintext, nil
}

// sealChaCha20WithNonce is the test-injectable form. nil nonce →
// random; non-nil must be 12 bytes.
func sealChaCha20WithNonce(key, plaintext, aad, nonce []byte) (string, error) {
	if len(key) != AEADKeySize {
		return "", fmt.Errorf("%w: ChaCha20 requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}

	c, err := chacha20poly1305.New(key)
	if err != nil {
		return "", fmt.Errorf("crypt: chacha20poly1305.New: %w", err)
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
	out = append(out, VersionAEADv2)
	out = append(out, nonce...)
	out = c.Seal(out, nonce, plaintext, aad)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// cipher.AEAD interface check — ensures std lib drift is caught at
// compile time if x/crypto changes.
var _ cipher.AEAD = (*chacha20poly1305Wrapper)(nil)

type chacha20poly1305Wrapper struct{ cipher.AEAD }
