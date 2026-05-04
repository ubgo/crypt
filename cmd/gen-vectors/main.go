// gen-vectors writes testdata/vectors.json — known-answer test vectors
// shared between the Go and TypeScript implementations.
//
// Run from the repo root:
//
//	go run ./cmd/gen-vectors > testdata/vectors.json
//
// Or via Taskfile:
//
//	task gen:vectors
//
// The vectors are computed against the standard library directly
// (crypto/cipher AEAD interface, crypto/hmac), so they serve as an
// independent reference for both Go and TS implementations of crypt.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// VersionAEADv1 — must match crypt.VersionAEADv1.
const VersionAEADv1 byte = 0x01

// AEADVector is one known-answer test for AES-256-GCM. All byte
// fields are hex-encoded to be safe for arbitrary binary content
// inside JSON.
type AEADVector struct {
	Name           string `json:"name"`
	KeyHex         string `json:"key_hex"`
	NonceHex       string `json:"nonce_hex"`
	AADHex         string `json:"aad_hex"`
	PlaintextHex   string `json:"plaintext_hex"`
	ExpectedB64URL string `json:"expected_b64url"`
}

// HMACVector is one known-answer test for HMAC-SHA256.
type HMACVector struct {
	Name        string `json:"name"`
	KeyHex      string `json:"key_hex"`
	DataHex     string `json:"data_hex"`
	ExpectedHex string `json:"expected_hex"`
}

// CBCVector is one known-answer test for legacy AES-256-CBC. CBC
// vectors fix the IV so output is deterministic.
type CBCVector struct {
	Name         string `json:"name"`
	KeyHex       string `json:"key_hex"`
	IVHex        string `json:"iv_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	ExpectedHex  string `json:"expected_hex"`
}

// Vectors is the top-level JSON document.
type Vectors struct {
	Version int          `json:"version"`
	Notes   string       `json:"notes"`
	AEAD    []AEADVector `json:"aead"`
	HMAC    []HMACVector `json:"hmac"`
	CBC     []CBCVector  `json:"cbc_legacy"`
}

func main() {
	out := Vectors{
		Version: 1,
		Notes:   "Cross-language test vectors for github.com/ubgo/crypt and @ubgo/crypt. Both Go and TS test suites consume this file. Regenerate with: go run ./cmd/gen-vectors > testdata/vectors.json",
		AEAD:    aeadVectors(),
		HMAC:    hmacVectors(),
		CBC:     cbcVectors(),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

func aeadVectors() []AEADVector {
	specs := []struct {
		name         string
		keyHex       string
		nonceHex     string
		aadHex       string
		plaintextHex string
	}{
		{
			name:         "all-zero key, all-zero nonce, empty plaintext, no AAD",
			keyHex:       repeatHex("00", 32),
			nonceHex:     repeatHex("00", 12),
			aadHex:       "",
			plaintextHex: "",
		},
		{
			name:         "all-zero key, all-zero nonce, ASCII plaintext, no AAD",
			keyHex:       repeatHex("00", 32),
			nonceHex:     repeatHex("00", 12),
			aadHex:       "",
			plaintextHex: hex.EncodeToString([]byte("hello, world")),
		},
		{
			name:         "all-zero key, all-zero nonce, ASCII plaintext, ASCII AAD",
			keyHex:       repeatHex("00", 32),
			nonceHex:     repeatHex("00", 12),
			aadHex:       hex.EncodeToString([]byte("user:42")),
			plaintextHex: hex.EncodeToString([]byte("hello, world")),
		},
		{
			name:         "patterned key, patterned nonce, longer plaintext",
			keyHex:       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			nonceHex:     "111213141516171819101a1b",
			aadHex:       hex.EncodeToString([]byte("context-binding-string")),
			plaintextHex: hex.EncodeToString([]byte("the quick brown fox jumps over the lazy dog 0123456789")),
		},
		{
			name:         "binary plaintext, no AAD",
			keyHex:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			nonceHex:     "fedcba9876543210fedcba98",
			aadHex:       "",
			plaintextHex: "000102030405060708090a0b0c0d0e0ffefcfdf8f0e0d0c0b0a0908070605040",
		},
	}

	out := make([]AEADVector, 0, len(specs))
	for _, s := range specs {
		key, _ := hex.DecodeString(s.keyHex)
		nonce, _ := hex.DecodeString(s.nonceHex)
		plaintext, err := hex.DecodeString(s.plaintextHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode plaintext_hex %q: %v\n", s.plaintextHex, err)
			os.Exit(1)
		}
		var aad []byte
		if s.aadHex != "" {
			aad, err = hex.DecodeString(s.aadHex)
			if err != nil {
				fmt.Fprintf(os.Stderr, "decode aad_hex %q: %v\n", s.aadHex, err)
				os.Exit(1)
			}
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Fprintln(os.Stderr, "aes.NewCipher:", err)
			os.Exit(1)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cipher.NewGCM:", err)
			os.Exit(1)
		}

		// Output layout: [version][nonce][ciphertext+tag]
		buf := make([]byte, 0, 1+len(nonce)+len(plaintext)+16)
		buf = append(buf, VersionAEADv1)
		buf = append(buf, nonce...)
		buf = gcm.Seal(buf, nonce, plaintext, aad)
		expected := base64.RawURLEncoding.EncodeToString(buf)

		out = append(out, AEADVector{
			Name:           s.name,
			KeyHex:         s.keyHex,
			NonceHex:       s.nonceHex,
			AADHex:         s.aadHex,
			PlaintextHex:   s.plaintextHex,
			ExpectedB64URL: expected,
		})
	}
	return out
}

func hmacVectors() []HMACVector {
	specs := []struct {
		name    string
		keyHex  string
		dataHex string
	}{
		{"empty data", repeatHex("aa", 32), ""},
		{"short ASCII data", repeatHex("aa", 32), hex.EncodeToString([]byte("hello"))},
		{"long ASCII data", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", hex.EncodeToString([]byte("the quick brown fox jumps over the lazy dog"))},
		{"binary data", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", "000102fffefd"},
	}
	out := make([]HMACVector, 0, len(specs))
	for _, s := range specs {
		key, _ := hex.DecodeString(s.keyHex)
		data, err := hex.DecodeString(s.dataHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode data_hex %q: %v\n", s.dataHex, err)
			os.Exit(1)
		}
		h := hmac.New(sha256.New, key)
		h.Write(data)
		mac := h.Sum(nil)
		out = append(out, HMACVector{
			Name:        s.name,
			KeyHex:      s.keyHex,
			DataHex:     s.dataHex,
			ExpectedHex: hex.EncodeToString(mac),
		})
	}
	return out
}

func cbcVectors() []CBCVector {
	specs := []struct {
		name         string
		keyHex       string
		ivHex        string
		plaintextHex string
	}{
		{
			name:         "AES-256-CBC, short plaintext",
			keyHex:       repeatHex("00", 32),
			ivHex:        repeatHex("11", 16),
			plaintextHex: hex.EncodeToString([]byte("hello")),
		},
		{
			name:         "AES-256-CBC, exact-block plaintext",
			keyHex:       repeatHex("00", 32),
			ivHex:        repeatHex("22", 16),
			plaintextHex: hex.EncodeToString([]byte("0123456789abcdef")), // 16 bytes
		},
		{
			name:         "AES-256-CBC, longer plaintext",
			keyHex:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			ivHex:        "fedcba9876543210fedcba9876543210",
			plaintextHex: hex.EncodeToString([]byte("the quick brown fox jumps over the lazy dog")),
		},
	}
	out := make([]CBCVector, 0, len(specs))
	for _, s := range specs {
		key, _ := hex.DecodeString(s.keyHex)
		iv, _ := hex.DecodeString(s.ivHex)
		plaintext, err := hex.DecodeString(s.plaintextHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode plaintext_hex: %v\n", err)
			os.Exit(1)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Fprintln(os.Stderr, "aes.NewCipher:", err)
			os.Exit(1)
		}
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		ct := make([]byte, len(padded))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ct, padded)
		full := append(append([]byte{}, iv...), ct...)
		out = append(out, CBCVector{
			Name:         s.name,
			KeyHex:       s.keyHex,
			IVHex:        s.ivHex,
			PlaintextHex: s.plaintextHex,
			ExpectedHex:  hex.EncodeToString(full),
		})
	}
	return out
}

func pkcs7Pad(buf []byte, size int) []byte {
	padLen := size - len(buf)%size
	out := make([]byte, len(buf)+padLen)
	copy(out, buf)
	for i := len(buf); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func repeatHex(twoChar string, count int) string {
	out := make([]byte, 0, len(twoChar)*count)
	for i := 0; i < count; i++ {
		out = append(out, twoChar...)
	}
	return string(out)
}
