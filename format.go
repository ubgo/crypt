package crypt

// Wire format constants shared between encoders and decoders.
//
// The AEAD output is a base64url-no-pad encoding of:
//
//	[version:1][nonce:12][ciphertext:N][tag:16]
//
// The version byte enables forward-compatibility: future algorithms get
// new version numbers, and decoders explicitly enumerate which versions
// they understand.
const (
	// VersionAEADv1 — AES-256-GCM with 12-byte nonce and 16-byte tag.
	VersionAEADv1 byte = 0x01

	// AEADKeySize is the required key length for AEAD operations.
	AEADKeySize = 32

	// aeadNonceSize is the GCM standard nonce length (96 bits).
	aeadNonceSize = 12

	// aeadTagSize is the GCM authentication tag length (128 bits).
	aeadTagSize = 16

	// aeadHeaderSize is the version byte + nonce.
	aeadHeaderSize = 1 + aeadNonceSize

	// aeadMinSize is the smallest possible AEAD ciphertext: header + tag,
	// for an empty plaintext.
	aeadMinSize = aeadHeaderSize + aeadTagSize
)
