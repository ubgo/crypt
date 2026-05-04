package crypt

import (
	"strings"
	"testing"
)

const (
	key128 = "1234567890abcdef"                 // 16 bytes
	key192 = "123456789012345678901234"         // 24 bytes
	key256 = "12345678901234567890123456789012" // 32 bytes
)

func TestNew_AcceptsValidKeyLengths(t *testing.T) {
	for _, k := range []string{key128, key192, key256} {
		if _, err := New(k); err != nil {
			t.Errorf("New(%d-byte): %v", len(k), err)
		}
	}
}

func TestNew_RejectsInvalidKeyLengths(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 31, 33} {
		if _, err := New(strings.Repeat("a", n)); err == nil {
			t.Errorf("New(%d-byte): expected error", n)
		}
	}
}

func TestEncryptDecrypt_RoundTrip_AllKeySizes(t *testing.T) {
	plaintexts := []string{"", "a", "the quick brown fox", strings.Repeat("x", 100)}
	for _, k := range []string{key128, key192, key256} {
		c, err := New(k)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for _, pt := range plaintexts {
			enc, err := c.Encrypt(pt)
			if err != nil {
				t.Errorf("Encrypt(%q, key%d): %v", pt, len(k), err)
				continue
			}
			dec, err := c.Decrypt(enc)
			if err != nil {
				t.Errorf("Decrypt(%q, key%d): %v", pt, len(k), err)
				continue
			}
			if dec != pt {
				t.Errorf("RoundTrip(%q, key%d): got %q", pt, len(k), dec)
			}
		}
	}
}

func TestEncrypt_DifferentEachCall(t *testing.T) {
	c, _ := New(key256)
	a, _ := c.Encrypt("hello")
	b, _ := c.Encrypt("hello")
	if a == b {
		t.Errorf("encrypting the same plaintext twice should produce different ciphertexts (random IV)")
	}
}

func TestDecrypt_NotHex(t *testing.T) {
	if _, err := DecryptWithKey(key256, "not-a-hex-string"); err == nil {
		t.Errorf("expected hex-decode error")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	if _, err := DecryptWithKey(key256, "deadbeef"); err == nil {
		t.Errorf("expected too-short error")
	}
}

func TestDecrypt_NotBlockAligned(t *testing.T) {
	// 16 bytes IV + 1 byte garbage = 34 hex chars, body unaligned.
	if _, err := DecryptWithKey(key256, strings.Repeat("0", 34)); err == nil {
		t.Errorf("expected not-block-aligned error")
	}
}

func TestPackageLevelEncryptDecrypt(t *testing.T) {
	enc, err := EncryptWithKey(key256, "secret")
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}
	dec, err := DecryptWithKey(key256, enc)
	if err != nil {
		t.Fatalf("DecryptWithKey: %v", err)
	}
	if dec != "secret" {
		t.Errorf("got %q, want %q", dec, "secret")
	}
}

func TestEncrypt_BadKeyToBlock(t *testing.T) {
	// Bypass Cipher (which validates), call package-level with bad key.
	if _, err := EncryptWithKey("not-a-valid-aes-key", "x"); err == nil {
		t.Errorf("expected aes.NewCipher error")
	}
}

func TestDecrypt_TamperedCiphertext_DiffersFromOriginal(t *testing.T) {
	// CBC has no message authentication: a flipped ciphertext byte
	// either produces an InvalidPadding error OR garbage plaintext
	// (~1/256 chance the corrupted last byte happens to look like
	// valid padding). Both are valid outcomes; we only assert the
	// result differs from the original.
	original := "secret-payload-of-some-length"
	enc, _ := EncryptWithKey(key256, original)
	tampered := enc[:len(enc)-2] + "ff"
	out, err := DecryptWithKey(key256, tampered)
	differed := err != nil || out != original
	if !differed {
		t.Errorf("expected tampered ciphertext to error or produce different plaintext")
	}
}
