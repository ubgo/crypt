package crypt

import "errors"

// Sentinel errors returned by the package. Use errors.Is to compare.
var (
	// ErrInvalidKey is returned when a provided key has the wrong length
	// for the requested operation. AEAD requires exactly 32 bytes
	// (AES-256-GCM). Legacy CBC accepts 16, 24, or 32 bytes.
	ErrInvalidKey = errors.New("crypt: invalid key length")

	// ErrCiphertextTooShort is returned when ciphertext is smaller than
	// the minimum required to contain the version byte, nonce, and
	// authentication tag (AEAD) or IV (CBC).
	ErrCiphertextTooShort = errors.New("crypt: ciphertext too short")

	// ErrCiphertextNotBlockAligned is returned when CBC ciphertext
	// (excluding IV) is not a multiple of the AES block size.
	ErrCiphertextNotBlockAligned = errors.New("crypt: ciphertext is not a multiple of the block size")

	// ErrInvalidPadding is returned when PKCS#7 padding cannot be
	// removed because the padding length byte is out of range or
	// inconsistent. CBC-only.
	ErrInvalidPadding = errors.New("crypt: invalid PKCS#7 padding")

	// ErrUnsupportedVersion is returned when an AEAD ciphertext
	// begins with a version byte that this package version does not
	// know how to decrypt.
	ErrUnsupportedVersion = errors.New("crypt: unsupported ciphertext version")

	// ErrTampered is returned when AEAD authentication fails. This can
	// indicate a tampered ciphertext, a wrong key, or wrong AAD.
	ErrTampered = errors.New("crypt: ciphertext authentication failed")

	// ErrInvalidCiphertext is returned when a ciphertext cannot be
	// decoded (e.g., not valid base64url for AEAD, not valid hex for
	// CBC, or otherwise malformed).
	ErrInvalidCiphertext = errors.New("crypt: invalid ciphertext encoding")

	// ErrUnknownFormat is returned by legacy.OpenAuto when it cannot
	// detect whether the ciphertext is AEAD or legacy CBC.
	ErrUnknownFormat = errors.New("crypt: unknown ciphertext format")

	// ErrInvalidPasswordHash is returned when a stored password hash
	// string cannot be parsed (not a valid PHC string, unsupported
	// algorithm, or malformed parameters).
	ErrInvalidPasswordHash = errors.New("crypt: invalid password hash format")
)
