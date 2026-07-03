package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
)

// This file holds the AES-CBC implementation. CBC is offered as a
// peer to AES-GCM (Seal/Open) — both are first-class. CBC has no
// built-in message authentication, so callers who care about tamper
// detection should either layer HMAC on top (encrypt-then-MAC) or
// use Seal/Open (which build in authentication).
//
// Wire format: hex(IV[16] || PKCS7-padded-ciphertext)
//
// Key sizes accepted: 16, 24, or 32 bytes (AES-128/192/256).
//
// Use cases for CBC over AEAD:
//   - Interop with existing systems (PHP openssl_encrypt, Java
//     javax.crypto, older Python/Ruby) that use AES-CBC.
//   - Reading ciphertext your application already wrote with this
//     format.
//   - Compliance requirements that mandate a specific algorithm.
//
// The v0.x type-based API (Cipher, New) and string-based wrappers
// (EncryptWithKey, DecryptWithKey) are kept here, both wrapping
// EncryptCBC/DecryptCBC. They remain marked Deprecated as they are
// superseded by the byte-typed forms.

// EncryptCBC PKCS#7-pads the plaintext, AES-CBC encrypts it with a
// fresh random IV from crypto/rand, and returns hex(IV || ciphertext).
//
// Trade-offs vs Seal (AES-256-GCM):
//   - CBC has no message authentication. A tampered ciphertext is
//     either rejected by PKCS#7 unpadding (~255/256 of the time) or
//     produces silent garbage plaintext (~1/256). If you care about
//     tamper detection, layer HMAC on top (encrypt-then-MAC) or use
//     Seal which builds in authentication.
//   - CBC accepts 16/24/32-byte keys (AES-128/192/256). Seal is
//     AES-256-only.
//   - Output is hex; Seal output is base64url-no-pad. CBC ciphertext
//     is typically larger because hex doubles every byte.
//
// Use it when:
//   - Interoperating with an existing system that uses AES-CBC
//     (PHP openssl_encrypt, Java javax.crypto with CBC, older
//     Python/Ruby code, etc.).
//   - Reading ciphertext your application already wrote with this
//     format.
//   - A specific compliance or library-compat constraint requires
//     AES-CBC.
func EncryptCBC(key, plaintext []byte) (string, error) {
	if !validCBCKeyLen(len(key)) {
		return "", fmt.Errorf("%w: CBC requires 16, 24, or 32 bytes; got %d", ErrInvalidKey, len(key))
	}

	plain, err := pad(plaintext, aes.BlockSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}

	out := make([]byte, aes.BlockSize+len(plain))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(randReader, iv); err != nil {
		return "", fmt.Errorf("crypt: random IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[aes.BlockSize:], plain)
	return hex.EncodeToString(out), nil
}

// DecryptCBC reverses EncryptCBC: hex-decodes the input, takes the IV
// from the first AES block, AES-CBC decrypts the rest, and removes
// PKCS#7 padding.
//
// See EncryptCBC for trade-offs vs the authenticated AEAD path
// (Open/Seal). If you control both ends of the wire and need
// authentication, prefer Open.
func DecryptCBC(key []byte, ciphertext string) ([]byte, error) {
	if !validCBCKeyLen(len(key)) {
		return nil, fmt.Errorf("%w: CBC requires 16, 24, or 32 bytes; got %d", ErrInvalidKey, len(key))
	}

	raw, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	if len(raw) < aes.BlockSize {
		return nil, ErrCiphertextTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypt: aes.NewCipher: %w", err)
	}

	iv := raw[:aes.BlockSize]
	body := raw[aes.BlockSize:]
	if len(body)%aes.BlockSize != 0 {
		return nil, ErrCiphertextNotBlockAligned
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(body, body)

	unpadded, err := unpad(body, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return unpadded, nil
}

// validCBCKeyLen reports whether n is one of the AES key sizes.
func validCBCKeyLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}

// pad returns buf padded to a multiple of size using PKCS#7.
func pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	out := make([]byte, bufLen+padLen)
	copy(out, buf)
	for i := 0; i < padLen; i++ {
		out[bufLen+i] = byte(padLen)
	}
	return out, nil
}

// unpad removes PKCS#7 padding from buf, returning a fresh slice.
func unpad(buf []byte, size int) ([]byte, error) {
	if len(buf) == 0 || len(buf)%size != 0 {
		return nil, ErrInvalidPadding
	}
	pad := int(buf[len(buf)-1])
	if pad == 0 || pad > size || pad > len(buf) {
		return nil, ErrInvalidPadding
	}
	for i := len(buf) - pad; i < len(buf); i++ {
		if int(buf[i]) != pad {
			return nil, ErrInvalidPadding
		}
	}
	out := make([]byte, len(buf)-pad)
	copy(out, buf[:len(buf)-pad])
	return out, nil
}

// ---------------------------------------------------------------------
// Backward-compat shim for the original v0.x API.
//
// The original surface (Cipher, New, EncryptWithKey, DecryptWithKey)
// is kept working so existing callers don't break. All of it is
// CBC-based and Deprecated; new callers should use Seal/Open.
// ---------------------------------------------------------------------

// Cipher is a reusable AES-CBC + PKCS#7 cipher pre-keyed at construction.
//
// Deprecated: Cipher uses AES-CBC, which is not authenticated. Use
// Sealer (AES-256-GCM) for new code.
type Cipher struct {
	key []byte
}

// New constructs a Cipher from a 16, 24, or 32-byte key string.
//
// Deprecated: prefer NewSealer for AES-256-GCM authenticated encryption.
func New(key string) (*Cipher, error) {
	if !validCBCKeyLen(len(key)) {
		return nil, fmt.Errorf("%w: CBC requires 16, 24, or 32 bytes; got %d", ErrInvalidKey, len(key))
	}
	return &Cipher{key: []byte(key)}, nil
}

// Encrypt PKCS#7-pads the plaintext, AES-CBC encrypts it with a fresh
// random IV, and returns hex(IV || ciphertext).
//
// Deprecated: prefer Sealer.Seal for authenticated encryption.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return EncryptCBC(c.key, []byte(plaintext))
}

// Decrypt reverses Encrypt.
//
// Deprecated: prefer Sealer.Open. CBC cannot detect tampering.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	out, err := DecryptCBC(c.key, ciphertext)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// EncryptWithKey is the package-level form of Cipher.Encrypt.
//
// Deprecated: prefer Seal for authenticated encryption.
func EncryptWithKey(key, plaintext string) (string, error) {
	return EncryptCBC([]byte(key), []byte(plaintext))
}

// DecryptWithKey is the package-level form of Cipher.Decrypt.
//
// Deprecated: prefer Open. CBC cannot detect tampering.
func DecryptWithKey(key, ciphertext string) (string, error) {
	out, err := DecryptCBC([]byte(key), ciphertext)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
