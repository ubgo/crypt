// Package crypt provides AES-CBC + PKCS#7 encryption with hex-encoded
// ciphertext output. Designed for storing short secrets (API keys, tokens)
// at rest in a database column.
//
// Keys must be 16, 24, or 32 bytes long, selecting AES-128, AES-192, or
// AES-256 respectively. AES-256 is strongly recommended for new code.
//
// The package has zero third-party dependencies and uses crypto/rand for
// IV generation. The output is hex-encoded for easy storage in TEXT-style
// columns; switch to base64 if you prefer.
//
// Example:
//
//	c, err := crypt.New("32-byte-aes-256-key-go-here-padded")
//	if err != nil { return err }
//	enc, _ := c.Encrypt("my-secret")
//	dec, _ := c.Decrypt(enc) // "my-secret"
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// ErrCiphertextTooShort is returned when ciphertext is smaller than the AES
// block size — which means it cannot contain the IV.
var ErrCiphertextTooShort = errors.New("crypt: ciphertext too short")

// ErrCiphertextNotBlockAligned is returned when ciphertext (excluding IV) is
// not a multiple of the AES block size.
var ErrCiphertextNotBlockAligned = errors.New("crypt: ciphertext is not a multiple of the block size")

// ErrInvalidPadding is returned when PKCS#7 padding cannot be removed
// because the padding length byte is out of range or inconsistent.
var ErrInvalidPadding = errors.New("crypt: invalid PKCS#7 padding")

// Cipher is a reusable AES-CBC + PKCS#7 cipher pre-keyed at construction.
//
// Cipher is safe for concurrent use — every Encrypt / Decrypt call constructs
// a fresh cipher.Block from the stored key.
type Cipher struct {
	key []byte
}

// New constructs a Cipher from a 16, 24, or 32-byte key string.
func New(key string) (*Cipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("crypt: key must be 16, 24, or 32 bytes; got %d", len(key))
	}
	return &Cipher{key: []byte(key)}, nil
}

// Encrypt PKCS#7-pads the plaintext, AES-CBC encrypts it with a fresh random
// IV, and returns hex(IV || ciphertext).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return EncryptWithKey(string(c.key), plaintext)
}

// Decrypt reverses Encrypt: hex-decodes the input, takes the IV from the
// first AES block, AES-CBC decrypts the rest, and removes PKCS#7 padding.
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	return DecryptWithKey(string(c.key), ciphertext)
}

// EncryptWithKey is the package-level form of Cipher.Encrypt. Useful for
// one-shot calls when you don't want to construct a Cipher.
func EncryptWithKey(key, plaintext string) (string, error) {
	keyBytes := []byte(key)
	plain, err := pad([]byte(plaintext), aes.BlockSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	out := make([]byte, aes.BlockSize+len(plain))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[aes.BlockSize:], plain)
	return hex.EncodeToString(out), nil
}

// DecryptWithKey is the package-level form of Cipher.Decrypt.
func DecryptWithKey(key, ciphertext string) (string, error) {
	raw, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("crypt: hex decode: %w", err)
	}
	if len(raw) < aes.BlockSize {
		return "", ErrCiphertextTooShort
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	iv := raw[:aes.BlockSize]
	body := raw[aes.BlockSize:]
	if len(body)%aes.BlockSize != 0 {
		return "", ErrCiphertextNotBlockAligned
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(body, body)

	unpadded, err := unpad(body, aes.BlockSize)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
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
