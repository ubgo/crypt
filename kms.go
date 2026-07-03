package crypt

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// KMS is the interface a Key Management Service adapter implements.
// `crypt` ships the interface and a static-key in-memory adapter for
// testing; production adapters for AWS KMS, GCP KMS, HashiCorp Vault,
// etc. are separate packages so this module doesn't pull cloud SDKs.
//
// The interface is intentionally minimal: GenerateDataKey returns a
// fresh DEK along with that DEK encrypted under the KEK, so the
// caller can store the wrapped DEK alongside the ciphertext. Decrypt
// unwraps a previously-stored wrapped DEK.
type KMS interface {
	// GenerateDataKey returns a fresh data encryption key (plaintext)
	// and the same key wrapped under the KEK identified by keyID.
	GenerateDataKey(ctx context.Context, keyID string) (plaintextDEK, wrappedDEK []byte, err error)

	// Decrypt unwraps a previously-wrapped DEK back to plaintext.
	Decrypt(ctx context.Context, keyID string, wrappedDEK []byte) (plaintextDEK []byte, err error)

	// Encrypt wraps an arbitrary blob under the KEK. Optional —
	// most callers use GenerateDataKey + Decrypt instead.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) (ciphertext []byte, err error)
}

// EnvelopeSealer uses a KMS for envelope encryption: each call to
// Seal generates a fresh DEK from the KMS, encrypts the plaintext
// under that DEK with AES-256-GCM, and stores the wrapped DEK
// alongside the ciphertext.
//
// Use cases:
//   - Per-row encryption keys for regulated tables (PCI, HIPAA).
//   - Cross-region encryption with cloud KMS (AWS / GCP).
//   - Defense-in-depth: even if the database is exfiltrated, the
//     attacker still needs KMS access to decrypt.
//
// Wire format (version 0x06):
//
//	[0x06][wrapped_len:4 BE][wrapped_dek][nonce:12][ciphertext:N][tag:16]
//
// Each Seal makes one KMS round-trip (GenerateDataKey). Each Open
// makes one KMS round-trip (Decrypt). Cache wisely if your hot path
// requires more throughput.
type EnvelopeSealer struct {
	kms   KMS
	keyID string
}

// NewEnvelopeSealer constructs an EnvelopeSealer bound to a
// KMS-managed key. The keyID is opaque; its meaning is up to the
// adapter (AWS KMS uses ARNs, GCP uses resource names, etc.).
func NewEnvelopeSealer(kms KMS, keyID string) *EnvelopeSealer {
	return &EnvelopeSealer{kms: kms, keyID: keyID}
}

const versionEnvelopeV1 byte = 0x06

// Seal encrypts plaintext using a fresh DEK from the KMS.
func (e *EnvelopeSealer) Seal(ctx context.Context, plaintext, aad []byte) (string, error) {
	dek, wrapped, err := e.kms.GenerateDataKey(ctx, e.keyID)
	if err != nil {
		return "", fmt.Errorf("crypt: kms.GenerateDataKey: %w", err)
	}
	defer zeroBytes(dek)

	inner, err := Seal(dek, plaintext, aad)
	if err != nil {
		return "", err
	}

	innerRaw, err := base64.RawURLEncoding.DecodeString(inner)
	if err != nil {
		return "", fmt.Errorf("crypt: re-decode inner: %w", err)
	}

	out := make([]byte, 0, 1+4+len(wrapped)+len(innerRaw))
	out = append(out, versionEnvelopeV1)

	var lenField [4]byte
	binary.BigEndian.PutUint32(lenField[:], uint32(len(wrapped)))
	out = append(out, lenField[:]...)
	out = append(out, wrapped...)
	out = append(out, innerRaw...)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts an EnvelopeSealer.Seal output by unwrapping the DEK
// via the KMS and then decrypting the inner ciphertext.
func (e *EnvelopeSealer) Open(ctx context.Context, ciphertext string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < 1+4 {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != versionEnvelopeV1 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}
	wrappedLen := binary.BigEndian.Uint32(raw[1:5])
	// Widen BEFORE adding: computing 5+wrappedLen in uint32 wraps for
	// attacker-chosen wrappedLen near math.MaxUint32, sneaking past the
	// bound check and panicking the slice below (out-of-range). Add in
	// uint64 so the length is compared honestly.
	if uint64(5)+uint64(wrappedLen) > uint64(len(raw)) {
		return nil, ErrCiphertextTooShort
	}
	wrapped := raw[5 : 5+wrappedLen]
	inner := raw[5+wrappedLen:]

	dek, err := e.kms.Decrypt(ctx, e.keyID, wrapped)
	if err != nil {
		return nil, fmt.Errorf("crypt: kms.Decrypt: %w", err)
	}
	defer zeroBytes(dek)

	// Re-encode inner as base64url so we can call Open which expects
	// a string. This is wasteful; future versions may expose a
	// byte-slice Open variant.
	innerStr := base64.RawURLEncoding.EncodeToString(inner)
	return Open(dek, innerStr, aad)
}

// zeroBytes overwrites a buffer with zeros — best-effort, since Go's
// GC may move the slice and Go gives no formal guarantee.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ----- in-memory KMS for tests + dev -----

// StaticKMS is a trivial KMS adapter that uses a fixed local key as
// the KEK. Useful for tests and local development; not for production
// (defeats the purpose of envelope encryption — the KEK is in the
// process memory).
type StaticKMS struct {
	mu   sync.RWMutex
	keks map[string][]byte
}

// NewStaticKMS constructs a StaticKMS. Add keys with AddKey.
func NewStaticKMS() *StaticKMS {
	return &StaticKMS{keks: map[string][]byte{}}
}

// AddKey registers a 32-byte key under keyID.
func (s *StaticKMS) AddKey(keyID string, key []byte) error {
	if len(key) != AEADKeySize {
		return fmt.Errorf("%w: KEK must be %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}
	s.mu.Lock()
	s.keks[keyID] = append([]byte(nil), key...)
	s.mu.Unlock()
	return nil
}

func (s *StaticKMS) lookup(keyID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keks[keyID]
	if !ok {
		return nil, fmt.Errorf("static kms: unknown keyID %q", keyID)
	}
	return k, nil
}

// GenerateDataKey for StaticKMS returns a fresh 32-byte DEK and that
// DEK encrypted under the KEK using crypt.Seal.
func (s *StaticKMS) GenerateDataKey(_ context.Context, keyID string) ([]byte, []byte, error) {
	kek, err := s.lookup(keyID)
	if err != nil {
		return nil, nil, err
	}
	dek, err := RandomBytes(AEADKeySize)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := Seal(kek, dek, nil)
	if err != nil {
		return nil, nil, err
	}
	return dek, []byte(wrapped), nil
}

// Decrypt unwraps a wrapped DEK.
func (s *StaticKMS) Decrypt(_ context.Context, keyID string, wrapped []byte) ([]byte, error) {
	kek, err := s.lookup(keyID)
	if err != nil {
		return nil, err
	}
	return Open(kek, string(wrapped), nil)
}

// Encrypt wraps arbitrary plaintext.
func (s *StaticKMS) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	kek, err := s.lookup(keyID)
	if err != nil {
		return nil, err
	}
	ct, err := Seal(kek, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return []byte(ct), nil
}

var _ KMS = (*StaticKMS)(nil)

// silence unused import if we reorganize later.
var _ = errors.New
