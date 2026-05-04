package crypt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorsDoc mirrors testdata/vectors.json. Both Go and TypeScript
// test suites consume this file to assert byte-for-byte parity.
type vectorsDoc struct {
	Version int          `json:"version"`
	Notes   string       `json:"notes"`
	AEAD    []aeadVector `json:"aead"`
	HMAC    []hmacVector `json:"hmac"`
	CBC     []cbcVector  `json:"cbc_legacy"`
}

type aeadVector struct {
	Name           string `json:"name"`
	KeyHex         string `json:"key_hex"`
	NonceHex       string `json:"nonce_hex"`
	AADHex         string `json:"aad_hex"`
	PlaintextHex   string `json:"plaintext_hex"`
	ExpectedB64URL string `json:"expected_b64url"`
}

type hmacVector struct {
	Name        string `json:"name"`
	KeyHex      string `json:"key_hex"`
	DataHex     string `json:"data_hex"`
	ExpectedHex string `json:"expected_hex"`
}

type cbcVector struct {
	Name         string `json:"name"`
	KeyHex       string `json:"key_hex"`
	IVHex        string `json:"iv_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	ExpectedHex  string `json:"expected_hex"`
}

func loadVectors(t *testing.T) vectorsDoc {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var v vectorsDoc
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshal vectors.json: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestVectors_AEAD_Seal(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.AEAD {
		t.Run(vec.Name, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			nonce := mustHex(t, vec.NonceHex)
			aad := mustHex(t, vec.AADHex)
			plaintext := mustHex(t, vec.PlaintextHex)
			got, err := sealWithNonce(key, plaintext, aad, nonce)
			if err != nil {
				t.Fatalf("sealWithNonce: %v", err)
			}
			if got != vec.ExpectedB64URL {
				t.Errorf("ciphertext mismatch:\n  got:  %s\n  want: %s", got, vec.ExpectedB64URL)
			}
		})
	}
}

func TestVectors_AEAD_Open(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.AEAD {
		t.Run(vec.Name, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			aad := mustHex(t, vec.AADHex)
			expectedPlaintext := mustHex(t, vec.PlaintextHex)
			pt, err := Open(key, vec.ExpectedB64URL, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, expectedPlaintext) {
				t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", pt, expectedPlaintext)
			}
		})
	}
}

func TestVectors_HMAC(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.HMAC {
		t.Run(vec.Name, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			data := mustHex(t, vec.DataHex)
			want := mustHex(t, vec.ExpectedHex)
			got := Sign(key, data)
			if !bytes.Equal(got, want) {
				t.Errorf("HMAC mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(got), vec.ExpectedHex)
			}
			if !Verify(key, data, want) {
				t.Errorf("Verify rejected expected MAC")
			}
		})
	}
}

func TestVectors_CBC_Decrypt(t *testing.T) {
	v := loadVectors(t)
	for _, vec := range v.CBC {
		t.Run(vec.Name, func(t *testing.T) {
			key := mustHex(t, vec.KeyHex)
			expectedPlaintext := mustHex(t, vec.PlaintextHex)
			pt, err := DecryptCBC(key, vec.ExpectedHex)
			if err != nil {
				t.Fatalf("DecryptCBC: %v", err)
			}
			if !bytes.Equal(pt, expectedPlaintext) {
				t.Errorf("plaintext mismatch:\n  got:  %x\n  want: %x", pt, expectedPlaintext)
			}
		})
	}
}
