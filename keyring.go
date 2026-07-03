package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
)

// KeyRing supports graceful key rotation: writes always use the
// active key; reads dispatch by the kid (key id) embedded in each
// ciphertext.
//
// Wire format (version 0x03):
//
//	[0x03][kid_len:1][kid:kid_len][nonce:12][ciphertext:N][tag:16]
//
// Old AEAD ciphertext (version 0x01) is also openable by KeyRing
// when the active key happens to match — KeyRing.Open detects v1
// and falls back to plain Open with the active key. To open v1
// ciphertext under a non-active key, the caller must use plain
// crypt.Open with that key.
//
// Use cases:
//   - Annual key rotation (compliance).
//   - Compromise response: add new active key, drop old key after
//     all data has rotated through.
type KeyRing struct {
	active  string
	keys    map[string]cipher.AEAD
	rawKeys map[string][]byte // kept for v1-fallback Open with non-active keys
}

// NewKeyRing constructs a ring with one key marked active. The
// active kid identifies the key used for new Seals. Other kids
// can be added with Add.
//
// kid must be 1..64 ASCII bytes. Reasonable choices: "v1",
// "2026-q1", a UUID, etc.
func NewKeyRing(activeKid string, activeKey []byte) (*KeyRing, error) {
	if err := validKid(activeKid); err != nil {
		return nil, err
	}
	if len(activeKey) != AEADKeySize {
		return nil, fmt.Errorf("%w: KeyRing requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(activeKey))
	}
	block, err := aes.NewCipher(activeKey)
	if err != nil {
		return nil, fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypt: cipher.NewGCM: %w", err)
	}
	return &KeyRing{
		active:  activeKid,
		keys:    map[string]cipher.AEAD{activeKid: gcm},
		rawKeys: map[string][]byte{activeKid: append([]byte(nil), activeKey...)},
	}, nil
}

// Add registers an additional key under kid. Used to keep retired
// keys readable during a rotation window.
func (r *KeyRing) Add(kid string, key []byte) error {
	if err := validKid(kid); err != nil {
		return err
	}
	if _, exists := r.keys[kid]; exists {
		return fmt.Errorf("crypt: KeyRing already has kid %q", kid)
	}
	if len(key) != AEADKeySize {
		return fmt.Errorf("%w: KeyRing requires %d bytes; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("crypt: cipher.NewGCM: %w", err)
	}
	r.keys[kid] = gcm
	r.rawKeys[kid] = append([]byte(nil), key...)
	return nil
}

// Remove drops a kid from the ring. After this, ciphertexts tagged
// with that kid become unreadable — call this only after all
// ciphertexts have been re-encrypted.
func (r *KeyRing) Remove(kid string) error {
	if kid == r.active {
		return fmt.Errorf("crypt: cannot remove active kid %q", kid)
	}
	if _, exists := r.keys[kid]; !exists {
		return fmt.Errorf("crypt: KeyRing has no kid %q", kid)
	}
	delete(r.keys, kid)
	delete(r.rawKeys, kid)
	return nil
}

// ActiveKid returns the kid of the currently-active key.
func (r *KeyRing) ActiveKid() string { return r.active }

// SetActive marks an existing kid as active. Subsequent Seal calls
// use the new active key. Old ciphertexts remain readable.
func (r *KeyRing) SetActive(kid string) error {
	if _, exists := r.keys[kid]; !exists {
		return fmt.Errorf("crypt: KeyRing has no kid %q", kid)
	}
	r.active = kid
	return nil
}

// Seal encrypts under the active key, tagging the ciphertext with
// the active kid.
func (r *KeyRing) Seal(plaintext, aad []byte) (string, error) {
	gcm := r.keys[r.active]
	nonce := make([]byte, aeadNonceSize)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return "", fmt.Errorf("crypt: random nonce: %w", err)
	}

	kidBytes := []byte(r.active)
	out := make([]byte, 0, 1+1+len(kidBytes)+aeadNonceSize+len(plaintext)+aeadTagSize)
	out = append(out, VersionAEADv3)
	out = append(out, byte(len(kidBytes)))
	out = append(out, kidBytes...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plaintext, aad)

	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a ciphertext, dispatching by the embedded kid for v3
// ciphertexts. v1 ciphertexts (no kid) are opened under the active
// key as a fallback.
func (r *KeyRing) Open(ciphertext string, aad []byte) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < aeadMinSize {
		return nil, ErrCiphertextTooShort
	}

	switch raw[0] {
	case VersionAEADv1:
		// Try active key first; if it doesn't open, try the rest.
		for _, kid := range r.kidsActiveFirst() {
			pt, err := openV1WithAEAD(r.keys[kid], raw, aad)
			if err == nil {
				return pt, nil
			}
		}
		return nil, fmt.Errorf("%w: no key in ring opens this v1 ciphertext", ErrTampered)

	case VersionAEADv3:
		// Parse kid_len + kid.
		if len(raw) < 2 {
			return nil, ErrCiphertextTooShort
		}
		kidLen := int(raw[1])
		if kidLen < 1 || kidLen > keyRingMaxKidLen {
			return nil, fmt.Errorf("%w: invalid kid length %d", ErrInvalidCiphertext, kidLen)
		}
		if len(raw) < 2+kidLen+aeadNonceSize+aeadTagSize {
			return nil, ErrCiphertextTooShort
		}
		kid := string(raw[2 : 2+kidLen])
		gcm, ok := r.keys[kid]
		if !ok {
			return nil, fmt.Errorf("%w: no key for kid %q in ring", ErrTampered, kid)
		}
		nonce := raw[2+kidLen : 2+kidLen+aeadNonceSize]
		body := raw[2+kidLen+aeadNonceSize:]

		pt, err := gcm.Open(nil, nonce, body, aad)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTampered, err)
		}
		return pt, nil

	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, raw[0])
	}
}

// kidsActiveFirst returns kids with the active one first, then the
// rest in iteration order. Order doesn't matter for correctness
// (try-each-until-success) but checking the active key first is the
// common case.
func (r *KeyRing) kidsActiveFirst() []string {
	out := make([]string, 0, len(r.keys))
	out = append(out, r.active)
	for kid := range r.keys {
		if kid != r.active {
			out = append(out, kid)
		}
	}
	return out
}

// openV1WithAEAD parses a v1 ciphertext and decrypts with the given
// AEAD. Used by KeyRing for v1 fallback.
func openV1WithAEAD(gcm cipher.AEAD, raw, aad []byte) ([]byte, error) {
	if len(raw) < aeadMinSize {
		return nil, ErrCiphertextTooShort
	}
	if raw[0] != VersionAEADv1 {
		return nil, ErrUnsupportedVersion
	}
	nonce := raw[1:aeadHeaderSize]
	body := raw[aeadHeaderSize:]
	pt, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// validKid checks that kid is non-empty and within length bounds.
// We accept any byte content; ASCII is the convention but not
// enforced (UTF-8 emoji-as-kid is technically allowed).
func validKid(kid string) error {
	if len(kid) == 0 {
		return fmt.Errorf("crypt: kid must be non-empty")
	}
	if len(kid) > keyRingMaxKidLen {
		return fmt.Errorf("crypt: kid length %d exceeds limit %d", len(kid), keyRingMaxKidLen)
	}
	return nil
}
