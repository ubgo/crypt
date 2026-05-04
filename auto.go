package crypt

import (
	"encoding/base64"
	"encoding/hex"
)

// OpenAuto attempts to decrypt ciphertext that may be in either AES-GCM
// (base64url, version byte 0x01) or AES-CBC (hex) format.
//
// Dispatch rules:
//
//  1. If ciphertext base64url-decodes AND first byte is 0x01 AND it's
//     long enough to contain header + tag → call Open.
//  2. Else if ciphertext hex-decodes AND length looks like CBC →
//     call DecryptCBC. AAD is ignored (CBC has no AAD).
//  3. Else → return ErrUnknownFormat.
//
// Use cases:
//   - One-shot migration scripts iterating a table to re-encrypt
//     mixed-format rows.
//   - Read-path during a rollover window where writers emit AES-GCM
//     but historical AES-CBC ciphertext may still be present.
//
// For normal application code, call Open or DecryptCBC directly —
// you should know which format the input is in.
func OpenAuto(key []byte, ciphertext string, aad []byte) ([]byte, error) {
	if isLikelyAEAD(ciphertext) {
		if pt, err := Open(key, ciphertext, aad); err == nil {
			return pt, nil
		}
		// Fall through to CBC if AEAD detection was a false positive.
	}

	if isLikelyCBC(ciphertext) {
		if pt, err := DecryptCBC(key, ciphertext); err == nil {
			return pt, nil
		}
	}

	return nil, ErrUnknownFormat
}

// isLikelyAEAD reports whether ciphertext looks like a base64url-no-pad
// string whose first decoded byte is the AEAD version tag.
func isLikelyAEAD(ciphertext string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return false
	}
	if len(raw) < aeadMinSize {
		return false
	}
	return raw[0] == VersionAEADv1
}

// isLikelyCBC reports whether ciphertext looks like hex of a CBC
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
