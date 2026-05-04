package crypt

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a length-byte key from a master key using HKDF
// with SHA-256.
//
// Use cases:
//   - Per-tenant sub-keys (info = "tenant:" + tenantID)
//   - Per-purpose sub-keys ("aead-v1", "mac-v1") from a single master
//   - Per-environment salting (salt = environment marker)
//
// HKDF assumes a high-entropy input key (32+ bytes from a CSPRNG).
// Do NOT use it on user passwords — use HashPassword (argon2id)
// instead.
//
// The salt parameter is optional (nil is fine). The info parameter
// is the context binding — different info values produce independent
// derived keys from the same master.
//
// Example:
//
//	// Per-tenant key for AEAD encryption.
//	tenantKey, _ := crypt.DeriveKey(rootKey, nil, []byte("tenant:"+tid), crypt.AEADKeySize)
//	sealer, _ := crypt.NewSealer(tenantKey)
func DeriveKey(masterKey, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("crypt: DeriveKey length must be positive; got %d", length)
	}
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("crypt: DeriveKey masterKey must be non-empty")
	}
	r := hkdf.New(sha256.New, masterKey, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("crypt: hkdf: %w", err)
	}
	return out, nil
}
