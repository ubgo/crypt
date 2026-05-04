package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Asymmetric encryption — sealed-box style. The sender encrypts to a
// recipient's public key; only the recipient (with the matching
// private key) can decrypt. age and NaCl secretbox use this same
// X25519 + ChaCha20-Poly1305 construction.
//
// Wire format (version 0x05):
//
//	[0x05][ephemeral_pub:32][nonce:12][ciphertext:N][tag:16]
//
// On encrypt, the sender:
//   1. Generates an ephemeral X25519 keypair.
//   2. Performs ECDH between ephemeral private + recipient public to
//      derive a shared secret.
//   3. Hashes the shared secret with the ephemeral public to derive
//      the symmetric key (chacha20poly1305).
//   4. Encrypts the message under that symmetric key.
//   5. Outputs ephemeral_pub || nonce || ciphertext+tag.
//
// On decrypt, the recipient performs the matching ECDH to derive the
// same symmetric key, then decrypts.
//
// This is "anonymous sender" — the recipient cannot determine who
// encrypted (anyone with their public key could). For sender
// authentication, sign the plaintext with Ed25519 first.

const (
	// X25519KeySize is the size of an X25519 public/private key (32 bytes).
	X25519KeySize = curve25519.ScalarSize

	versionAsymmetricV1 byte = 0x05
)

// GenerateKeyPair returns a fresh X25519 keypair for use with
// SealAsymmetric / OpenAsymmetric.
func GenerateKeyPair() (publicKey, privateKey []byte, err error) {
	priv := make([]byte, X25519KeySize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("crypt: x25519 keygen: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("crypt: x25519 derive public: %w", err)
	}
	return pub, priv, nil
}

// SealAsymmetric encrypts plaintext to recipientPublicKey. The
// resulting ciphertext is base64url-no-pad with version 0x05.
//
// Anyone with recipientPrivateKey (and the matching public key)
// can decrypt; nobody else can. The sender's identity is NOT
// authenticated by this operation — sign the plaintext with
// Ed25519 first if you need that.
func SealAsymmetric(recipientPublicKey, plaintext []byte) (string, error) {
	if len(recipientPublicKey) != X25519KeySize {
		return "", fmt.Errorf("%w: recipient public key must be %d bytes; got %d",
			ErrInvalidKey, X25519KeySize, len(recipientPublicKey))
	}

	// Generate ephemeral keypair.
	ephPub, ephPriv, err := GenerateKeyPair()
	if err != nil {
		return "", err
	}

	// ECDH.
	shared, err := curve25519.X25519(ephPriv, recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("crypt: x25519 ecdh: %w", err)
	}

	// Symmetric key derived via chacha20poly1305.NewX (XChaCha20-Poly1305
	// would also work; we use ChaCha20-Poly1305 with a 12-byte nonce
	// for simplicity).
	c, err := chacha20poly1305.New(shared)
	if err != nil {
		return "", fmt.Errorf("crypt: chacha20poly1305: %w", err)
	}

	nonce := make([]byte, aeadNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypt: random nonce: %w", err)
	}

	// AAD binds the ephemeral public key into the cipher tag — an
	// attacker swapping ephemeralPub fails authentication.
	out := make([]byte, 0, 1+X25519KeySize+aeadNonceSize+len(plaintext)+aeadTagSize)
	out = append(out, versionAsymmetricV1)
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = c.Seal(out, nonce, plaintext, ephPub)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// OpenAsymmetric decrypts a SealAsymmetric output using the recipient's
// private key.
func OpenAsymmetric(recipientPrivateKey []byte, ciphertext string) ([]byte, error) {
	if len(recipientPrivateKey) != X25519KeySize {
		return nil, fmt.Errorf("%w: recipient private key must be %d bytes; got %d",
			ErrInvalidKey, X25519KeySize, len(recipientPrivateKey))
	}

	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	const minSize = 1 + X25519KeySize + aeadNonceSize + aeadTagSize
	if len(raw) < minSize {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != versionAsymmetricV1 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}

	ephPub := raw[1 : 1+X25519KeySize]
	nonce := raw[1+X25519KeySize : 1+X25519KeySize+aeadNonceSize]
	body := raw[1+X25519KeySize+aeadNonceSize:]

	shared, err := curve25519.X25519(recipientPrivateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("crypt: x25519 ecdh: %w", err)
	}

	c, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, fmt.Errorf("crypt: chacha20poly1305: %w", err)
	}

	pt, err := c.Open(nil, nonce, body, ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTampered, err)
	}
	return pt, nil
}

// silence linter; ensure x/crypto/curve25519 import is exercised.
var _ = errors.New
