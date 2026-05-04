// Package legacy holds migration helpers for moving from the older
// AES-CBC ciphertext format to the modern AES-GCM AEAD format.
//
// The presence of an `import "github.com/ubgo/crypt/legacy"` line in
// any non-migration code is a smell: production reads should use
// crypt.Open directly. This subpackage exists to keep migration
// tooling visible to code-search and code review.
package legacy

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/ubgo/crypt"
)

// OpenAuto attempts to decrypt ciphertext that may be in either the
// modern AEAD (base64url-encoded, version 0x01 prefix) or the legacy
// AES-CBC (hex-encoded, no version) format.
//
// The dispatch rules:
//
//  1. If ciphertext base64url-decodes AND first byte is 0x01 AND it's
//     long enough to contain header + tag → call crypt.Open.
//  2. Else if ciphertext hex-decodes AND length looks like CBC →
//     call crypt.DecryptCBC. AAD is ignored (CBC has no AAD).
//  3. Else → return crypt.ErrUnknownFormat.
//
// Use cases:
//   - One-shot migration scripts iterating a table to re-encrypt all
//     rows with crypt.Seal.
//   - Read-path during a rollover window when writers are emitting
//     AEAD but old AEAD-illiterate data may still be encountered.
//
// Anti-use-case: do not put OpenAuto in normal application code paths.
// Production reads should call crypt.Open directly. Code grep should
// find every site using OpenAuto so they can be cleaned up after
// migration completes.
func OpenAuto(key []byte, ciphertext string, aad []byte) ([]byte, error) {
	// Try AEAD path first.
	if isLikelyAEAD(ciphertext) {
		if pt, err := crypt.Open(key, ciphertext, aad); err == nil {
			return pt, nil
		}
		// Fall through to CBC if AEAD detection was a false positive
		// (e.g., legitimate-looking base64url that happened to start
		// with 0x01 by coincidence — vanishingly rare but possible).
	}

	// Try legacy CBC path.
	if isLikelyCBC(ciphertext) {
		if pt, err := crypt.DecryptCBC(key, ciphertext); err == nil {
			return pt, nil
		}
	}

	return nil, crypt.ErrUnknownFormat
}

// isLikelyAEAD returns true if the input looks like a base64url-no-pad
// string whose first byte (after decoding) is the AEAD version tag.
func isLikelyAEAD(ciphertext string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return false
	}
	const minAEAD = 1 + 12 + 16 // version + nonce + tag
	if len(raw) < minAEAD {
		return false
	}
	return raw[0] == crypt.VersionAEADv1
}

// isLikelyCBC returns true if the input looks like hex of a CBC
// ciphertext (IV + multiple-of-16 body).
func isLikelyCBC(ciphertext string) bool {
	raw, err := hex.DecodeString(ciphertext)
	if err != nil {
		return false
	}
	const blockSize = 16
	if len(raw) < blockSize {
		return false
	}
	body := raw[blockSize:]
	return len(body)%blockSize == 0 && len(body) > 0
}
