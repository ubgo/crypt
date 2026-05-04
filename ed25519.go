package crypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Ed25519 — public-key signatures.
//
// Use cases:
//   - Webhook signing where verifier shouldn't have the signing key
//     (e.g., partners verify with our public key alone).
//   - Software update signing (server signs, clients verify).
//   - Distributed verifiability (publish public key, anyone can check).
//
// For symmetric (shared-secret) signing, prefer Sign / Verify
// (HMAC-SHA256) — it's faster and simpler.

const (
	// Ed25519PublicKeySize is the size of an Ed25519 public key (32 bytes).
	Ed25519PublicKeySize = ed25519.PublicKeySize

	// Ed25519PrivateKeySize is the size of an Ed25519 private key (64 bytes).
	Ed25519PrivateKeySize = ed25519.PrivateKeySize

	// Ed25519SignatureSize is the size of an Ed25519 signature (64 bytes).
	Ed25519SignatureSize = ed25519.SignatureSize
)

// ErrInvalidSignature is returned by SignEd25519 / VerifyEd25519 when
// inputs have wrong shape.
var ErrInvalidSignature = errors.New("crypt: invalid signature")

// GenerateEd25519 returns a new Ed25519 keypair from the OS CSPRNG.
func GenerateEd25519() (publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypt: ed25519 keygen: %w", err)
	}
	return pub, priv, nil
}

// SignEd25519 produces a 64-byte signature over data using priv.
//
// Errors:
//   - ErrInvalidKey if priv length != 64 bytes.
func SignEd25519(priv ed25519.PrivateKey, data []byte) ([]byte, error) {
	if len(priv) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key must be %d bytes; got %d",
			ErrInvalidKey, Ed25519PrivateKeySize, len(priv))
	}
	return ed25519.Sign(priv, data), nil
}

// VerifyEd25519 checks an Ed25519 signature in constant time.
//
// Returns false (no error) on mismatch. Returns ErrInvalidKey or
// ErrInvalidSignature only on shape errors (wrong key/sig size).
func VerifyEd25519(pub ed25519.PublicKey, data, sig []byte) (bool, error) {
	if len(pub) != Ed25519PublicKeySize {
		return false, fmt.Errorf("%w: ed25519 public key must be %d bytes; got %d",
			ErrInvalidKey, Ed25519PublicKeySize, len(pub))
	}
	if len(sig) != Ed25519SignatureSize {
		return false, fmt.Errorf("%w: ed25519 signature must be %d bytes; got %d",
			ErrInvalidSignature, Ed25519SignatureSize, len(sig))
	}
	return ed25519.Verify(pub, data, sig), nil
}
