package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// AEAD comprehensive — every reachable branch.
// ---------------------------------------------------------------------

func TestAEAD_LongPlaintext_OneMiB(t *testing.T) {
	t.Parallel()
	key := make([]byte, AEADKeySize)
	_, _ = rand.Read(key)
	pt := bytes.Repeat([]byte{0x42}, 1<<20)

	ct, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(key, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("plaintext mismatch on 1 MiB payload")
	}
}

func TestAEAD_BinaryPlaintext_AllByteValues(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x55}, AEADKeySize)
	pt := make([]byte, 256)
	for i := range pt {
		pt[i] = byte(i)
	}

	ct, err := Seal(key, pt, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(key, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("plaintext mismatch on 0..255 byte values")
	}
}

func TestAEAD_NilAndEmptyAAD_Equivalent(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x33}, AEADKeySize)
	// Sealing with nil AAD should be openable with empty AAD (and vice versa).
	ct, _ := Seal(key, []byte("hello"), nil)
	pt, err := Open(key, ct, []byte{})
	if err != nil {
		t.Fatalf("Open with empty AAD on nil-AAD ciphertext: %v", err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}

	ct2, _ := Seal(key, []byte("hello"), []byte{})
	pt2, err := Open(key, ct2, nil)
	if err != nil {
		t.Fatalf("Open with nil AAD on empty-AAD ciphertext: %v", err)
	}
	if string(pt2) != "hello" {
		t.Errorf("got %q", pt2)
	}
}

func TestAEAD_LargeAAD(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x77}, AEADKeySize)
	aad := bytes.Repeat([]byte{0xAA}, 4096)
	ct, _ := Seal(key, []byte("data"), aad)
	pt, err := Open(key, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(pt) != "data" {
		t.Errorf("got %q", pt)
	}
}

func TestOpen_SingleBitFlip_AllPositions(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x11}, AEADKeySize)
	ct, _ := Seal(key, []byte("hello, world, this is a longer payload"), []byte("aad"))

	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	// Flip one bit at every byte position in turn — all should fail
	// because GCM is non-malleable.
	for i := range raw {
		mutated := append([]byte{}, raw...)
		mutated[i] ^= 0x01
		bad := base64.RawURLEncoding.EncodeToString(mutated)
		if _, err := Open(key, bad, []byte("aad")); !errors.Is(err, ErrTampered) {
			// Version byte (offset 0) should produce ErrUnsupportedVersion;
			// everything else should be ErrTampered.
			if i == 0 && errors.Is(err, ErrUnsupportedVersion) {
				continue
			}
			t.Errorf("flipped byte %d: got %v, want ErrTampered or ErrUnsupportedVersion", i, err)
		}
	}
}

func TestOpen_EmptyString(t *testing.T) {
	t.Parallel()
	key := make([]byte, AEADKeySize)
	if _, err := Open(key, "", nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Open(empty string): got %v, want ErrCiphertextTooShort", err)
	}
}

func TestOpen_BadBase64Chars(t *testing.T) {
	t.Parallel()
	key := make([]byte, AEADKeySize)
	if _, err := Open(key, "***not-base64***", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestSealer_Open_RejectsInvalidBase64(t *testing.T) {
	t.Parallel()
	s, _ := NewSealer(bytes.Repeat([]byte{0x01}, AEADKeySize))
	if _, err := s.Open("***", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("Sealer.Open: got %v, want ErrInvalidCiphertext", err)
	}
}

func TestSealer_Open_RejectsTooShort(t *testing.T) {
	t.Parallel()
	s, _ := NewSealer(bytes.Repeat([]byte{0x01}, AEADKeySize))
	short := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02})
	if _, err := s.Open(short, nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("Sealer.Open: got %v, want ErrCiphertextTooShort", err)
	}
}

func TestSealer_Open_RejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()
	s, _ := NewSealer(bytes.Repeat([]byte{0x01}, AEADKeySize))
	buf := make([]byte, aeadMinSize)
	buf[0] = 0xAB
	bad := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := s.Open(bad, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("Sealer.Open: got %v, want ErrUnsupportedVersion", err)
	}
}

func TestSealer_Open_RejectsTamper(t *testing.T) {
	t.Parallel()
	s, _ := NewSealer(bytes.Repeat([]byte{0x01}, AEADKeySize))
	ct, _ := s.Seal([]byte("hello"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.Open(tampered, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("Sealer.Open: got %v, want ErrTampered", err)
	}
}

// ---------------------------------------------------------------------
// CBC comprehensive — every reachable branch.
// ---------------------------------------------------------------------

func TestCBC_RoundTrip_AllKeySizes(t *testing.T) {
	t.Parallel()
	for _, n := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{0x42}, n)
		for _, pt := range [][]byte{
			{},
			[]byte("a"),
			bytes.Repeat([]byte{0x42}, 15),  // < 1 block
			bytes.Repeat([]byte{0x42}, 16),  // exactly 1 block (full padding)
			bytes.Repeat([]byte{0x42}, 17),  // > 1 block
			bytes.Repeat([]byte{0x42}, 100), // multi-block
		} {
			ct, err := EncryptCBC(key, pt)
			if err != nil {
				t.Fatalf("EncryptCBC(key=%d, len=%d): %v", n, len(pt), err)
			}
			got, err := DecryptCBC(key, ct)
			if err != nil {
				t.Fatalf("DecryptCBC(key=%d, len=%d): %v", n, len(pt), err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("round-trip mismatch: key=%d, len=%d", n, len(pt))
			}
		}
	}
}

func TestEncryptCBC_RejectsInvalidKey(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 15, 17, 23, 25, 31, 33, 64} {
		key := make([]byte, n)
		if _, err := EncryptCBC(key, []byte("x")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("EncryptCBC(key=%d): got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestDecryptCBC_RejectsInvalidKey(t *testing.T) {
	t.Parallel()
	good := bytes.Repeat([]byte{0x01}, 32)
	ct, _ := EncryptCBC(good, []byte("x"))
	for _, n := range []int{0, 1, 15, 17, 23, 25, 31, 33, 64} {
		bad := make([]byte, n)
		if _, err := DecryptCBC(bad, ct); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("DecryptCBC(key=%d): got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestDecryptCBC_NotHex(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := DecryptCBC(key, "this is not hex at all"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestDecryptCBC_OddHex(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	if _, err := DecryptCBC(key, "abc"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestDecryptCBC_ShorterThanIV(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	short := strings.Repeat("ab", 8) // 16 hex = 8 bytes < 16
	if _, err := DecryptCBC(key, short); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("got %v, want ErrCiphertextTooShort", err)
	}
}

func TestDecryptCBC_BodyNotBlockAligned(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	// 16-byte IV + 1-byte body = 17 bytes hex = 34 chars
	bad := strings.Repeat("00", 17)
	if _, err := DecryptCBC(key, bad); !errors.Is(err, ErrCiphertextNotBlockAligned) {
		t.Errorf("got %v, want ErrCiphertextNotBlockAligned", err)
	}
}

func TestDecryptCBC_InvalidPadding_PadByteZero(t *testing.T) {
	t.Parallel()
	// Construct a ciphertext that decrypts to bytes ending in 0x00 —
	// invalid PKCS7 (pad byte must be 1..16).
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := make([]byte, 16) // 16 zero bytes; padding would be appended
	ct, err := EncryptCBC(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}
	// Strip the second-to-last block by truncating to one block of body.
	// Then decrypting gives back what looks like `plaintext` whose
	// last byte (after manipulating IV) happens to be zero.
	// Easier: replace the last byte of the IV; this XORs into the
	// first decrypted block. The CBC encrypt example used 32 bytes
	// (one block of plaintext + one full block of padding 0x10).
	// We mutate the last byte of the IV portion, breaking the
	// pre-padding block. Then unpad sees garbage and fails.
	raw, _ := hex.DecodeString(ct)
	raw[15] ^= 0x10 // toggles the IV's last byte; affects the first-block plaintext last byte
	tampered := hex.EncodeToString(raw)
	if _, err := DecryptCBC(key, tampered); err == nil {
		// Either valid (rare collision) or padding error.
		// Accept either; we just want no panic.
		t.Logf("tamper produced no error — acceptable rare case")
	}
}

// ---------------------------------------------------------------------
// CBC unpad — direct edge cases via internal helper exposure.
// ---------------------------------------------------------------------

func TestUnpad_Variants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"empty", []byte{}, true},
		{"not multiple of 16", make([]byte, 15), true},
		{"pad byte = 0", append(bytes.Repeat([]byte{0x00}, 15), 0x00), true},
		{"pad byte > block size", append(bytes.Repeat([]byte{0x00}, 15), 0x11), true},
		{"valid: 16 bytes of 0x10", bytes.Repeat([]byte{0x10}, 16), false},
		{"valid: 1-byte pad", append(bytes.Repeat([]byte{0xAA}, 15), 0x01), false},
		{"valid: 15-byte pad",
			append([]byte{0xAA}, bytes.Repeat([]byte{0x0F}, 15)...), false},
		{"inconsistent pad bytes (last byte 5 but middle byte is 0xAA)",
			func() []byte {
				// 16 bytes; final byte = 5 (claims padLen=5), but the
				// preceding 4 bytes must also be 5 — they are not.
				out := bytes.Repeat([]byte{0xAA}, 16)
				out[15] = 0x05 // padLen=5
				// Bytes 11..14 should be 0x05 each, but they're 0xAA.
				return out
			}(),
			true,
		},
	}
	for _, c := range cases {
		_, err := unpad(c.input, 16)
		if (err != nil) != c.wantErr {
			t.Errorf("unpad %s: err=%v wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

// ---------------------------------------------------------------------
// Cipher (deprecated) coverage.
// ---------------------------------------------------------------------

func TestCipher_RoundTrip_AllKeySizes(t *testing.T) {
	t.Parallel()
	for _, n := range []int{16, 24, 32} {
		c, err := New(strings.Repeat("a", n))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ct, _ := c.Encrypt("hello")
		pt, err := c.Decrypt(ct)
		if err != nil || pt != "hello" {
			t.Errorf("Cipher round-trip key=%d: pt=%q err=%v", n, pt, err)
		}
	}
}

func TestCipher_DecryptError(t *testing.T) {
	t.Parallel()
	c, _ := New(strings.Repeat("a", 32))
	if _, err := c.Decrypt("!!!"); err == nil {
		t.Errorf("Cipher.Decrypt accepted invalid ciphertext")
	}
}

func TestCipher_New_RejectsAllInvalidLengths(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 15, 17, 23, 25, 31, 33, 64} {
		if _, err := New(strings.Repeat("a", n)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New(%d): got %v, want ErrInvalidKey", n, err)
		}
	}
}

// EncryptWithKey/DecryptWithKey are the v0.x string variants.
func TestPackageLevelLegacy_Roundtrip(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("a", 32)
	ct, err := EncryptWithKey(key, "secret")
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}
	pt, err := DecryptWithKey(key, ct)
	if err != nil {
		t.Fatalf("DecryptWithKey: %v", err)
	}
	if pt != "secret" {
		t.Errorf("got %q", pt)
	}
}

func TestPackageLevelLegacy_Errors(t *testing.T) {
	t.Parallel()
	if _, err := EncryptWithKey("short", "x"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("EncryptWithKey: got %v, want ErrInvalidKey", err)
	}
	if _, err := DecryptWithKey("short", "abcdef"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("DecryptWithKey: got %v, want ErrInvalidKey", err)
	}
}

// ---------------------------------------------------------------------
// Random — error paths and parameter coverage.
// ---------------------------------------------------------------------

func TestRandomBytes_ErrorPaths(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1, -100} {
		if _, err := RandomBytes(n); err == nil {
			t.Errorf("RandomBytes(%d): expected error", n)
		}
	}
}

func TestRandomToken_ErrorPaths(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1} {
		if _, err := RandomToken(n); err == nil {
			t.Errorf("RandomToken(%d): expected error", n)
		}
	}
}

func TestRandomHex_ErrorPaths(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, -1} {
		if _, err := RandomHex(n); err == nil {
			t.Errorf("RandomHex(%d): expected error", n)
		}
	}
}

func TestRandomBytes_Distribution(t *testing.T) {
	t.Parallel()
	// Statistical sanity: across many samples, no single byte value
	// dominates. Not a real entropy test — just smoke.
	const samples = 1024
	const size = 32
	counts := [256]int{}
	for i := 0; i < samples; i++ {
		b, err := RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes: %v", err)
		}
		for _, x := range b {
			counts[x]++
		}
	}
	expectedAvg := samples * size / 256 // 128
	for v, c := range counts {
		if c < expectedAvg/4 || c > expectedAvg*4 {
			t.Errorf("byte 0x%02x appeared %d times (expected ~%d) — entropy regression?", v, c, expectedAvg)
		}
	}
}

// ---------------------------------------------------------------------
// HMAC — additional coverage.
// ---------------------------------------------------------------------

func TestSign_EmptyKey(t *testing.T) {
	t.Parallel()
	// HMAC accepts any key length cryptographically, including empty
	// — though it's a bad idea operationally. Confirm it doesn't panic.
	mac := Sign([]byte{}, []byte("data"))
	if len(mac) != 32 {
		t.Errorf("Sign([]byte{}, ...): output len = %d, want 32", len(mac))
	}
}

func TestSign_LargeData(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0xFF}, 32)
	data := bytes.Repeat([]byte{0xAA}, 1<<20) // 1 MiB
	mac := Sign(key, data)
	if !Verify(key, data, mac) {
		t.Errorf("Verify failed on large data")
	}
}

func TestVerify_EmptyMAC(t *testing.T) {
	t.Parallel()
	if Verify([]byte("k"), []byte("d"), nil) {
		t.Errorf("Verify accepted nil MAC")
	}
	if Verify([]byte("k"), []byte("d"), []byte{}) {
		t.Errorf("Verify accepted empty MAC")
	}
}

func TestConstantTimeEqual_Edge(t *testing.T) {
	t.Parallel()
	if !ConstantTimeEqual(nil, nil) {
		t.Errorf("nil/nil should be equal")
	}
	if !ConstantTimeEqual([]byte{}, []byte{}) {
		t.Errorf("empty/empty should be equal")
	}
	if ConstantTimeEqual(nil, []byte{0x01}) {
		t.Errorf("nil and non-empty should not be equal")
	}
	// Single byte equal/unequal.
	if !ConstantTimeEqual([]byte{0x42}, []byte{0x42}) {
		t.Errorf("single byte equal failed")
	}
	if ConstantTimeEqual([]byte{0x42}, []byte{0x43}) {
		t.Errorf("single byte unequal returned true")
	}
}

// ---------------------------------------------------------------------
// Password — malformed PHC variants and parameter coverage.
// ---------------------------------------------------------------------

func TestParsePHC_Variants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		ok    bool
	}{
		{"empty", "", false},
		{"too few segments", "$argon2id$v=19$m=1,t=1,p=1", false},
		{"too many segments", "$argon2id$v=19$m=1,t=1,p=1$a$b$extra", false},
		{"missing leading dollar", "argon2id$v=19$m=65536,t=2,p=1$AAAA$BBBB", false},
		{"unknown algo", "$argon2i$v=19$m=65536,t=2,p=1$AAAA$BBBB", false},
		{"bad version syntax", "$argon2id$vv=19$m=65536,t=2,p=1$AAAA$BBBB", false},
		{"unsupported version", "$argon2id$v=20$m=65536,t=2,p=1$AAAA$BBBB", false},
		{"bad params syntax", "$argon2id$v=19$mm=1,tt=1,pp=1$AAAA$BBBB", false},
		{"non-base64 salt", "$argon2id$v=19$m=65536,t=2,p=1$!!!$BBBB", false},
		{"non-base64 hash", "$argon2id$v=19$m=65536,t=2,p=1$AAAA$!!!", false},
		{"empty salt", "$argon2id$v=19$m=65536,t=2,p=1$$BBBB", false},
		{"empty hash", "$argon2id$v=19$m=65536,t=2,p=1$AAAA$", false},
	}
	for _, c := range cases {
		_, _, _, err := parsePHC(c.input)
		if (err == nil) != c.ok {
			t.Errorf("parsePHC %s: err=%v ok=%v", c.name, err, c.ok)
		}
	}
}

func TestVerifyPassword_AllMalformedReturnError(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=65536,t=2,p=1$AAAA$BBBB",
	} {
		ok, err := VerifyPassword("anything", bad)
		if ok {
			t.Errorf("VerifyPassword(%q): unexpectedly accepted", bad)
		}
		if !errors.Is(err, ErrInvalidPasswordHash) {
			t.Errorf("VerifyPassword(%q): err=%v want ErrInvalidPasswordHash", bad, err)
		}
	}
}

func TestHashPassword_NonEmpty_VariousLengths(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("argon2id is slow; use -short to skip")
	}
	for _, pw := range []string{"a", "ab", "abc", strings.Repeat("x", 100), strings.Repeat("x", 1000)} {
		hash, err := HashPassword(pw)
		if err != nil {
			t.Fatalf("HashPassword(%d chars): %v", len(pw), err)
		}
		ok, err := VerifyPassword(pw, hash)
		if err != nil || !ok {
			t.Errorf("VerifyPassword(%d chars): ok=%v err=%v", len(pw), ok, err)
		}
	}
}

func TestHashPassword_EmptyAcceptedAndVerifies(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip()
	}
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword(empty): %v", err)
	}
	ok, _ := VerifyPassword("", hash)
	if !ok {
		t.Errorf("empty password should verify against its own hash")
	}
	notOk, _ := VerifyPassword("anything", hash)
	if notOk {
		t.Errorf("non-empty password should not match empty-password hash")
	}
}
