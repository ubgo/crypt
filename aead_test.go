package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func mustKey(t *testing.T, size int) []byte {
	t.Helper()
	k := make([]byte, size)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

// ---------------------------------------------------------------------
// Seal / Open round-trip
// ---------------------------------------------------------------------

func TestSeal_Open_RoundTrip(t *testing.T) {
	key := mustKey(t, 32)
	cases := []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty plaintext, no AAD", []byte{}, nil},
		{"short plaintext, no AAD", []byte("hello, world"), nil},
		{"long plaintext, no AAD", bytes.Repeat([]byte("x"), 10_000), nil},
		{"plaintext + AAD", []byte("data"), []byte("user:42")},
		{"binary plaintext", []byte{0x00, 0xff, 0x10, 0x20, 0x30}, []byte("ctx")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := Seal(key, tc.plaintext, tc.aad)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			pt, err := Open(key, ct, tc.aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Errorf("plaintext mismatch: got %q want %q", pt, tc.plaintext)
			}
		})
	}
}

func TestSeal_DifferentEachCall(t *testing.T) {
	key := mustKey(t, 32)
	a, err := Seal(key, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := Seal(key, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if a == b {
		t.Errorf("expected distinct ciphertexts (random nonce); got equal")
	}
}

// ---------------------------------------------------------------------
// Key validation
// ---------------------------------------------------------------------

func TestSeal_RejectsInvalidKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 24, 31, 33, 64} {
		key := make([]byte, n)
		if _, err := Seal(key, []byte("x"), nil); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Seal(key=%d bytes): got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestOpen_RejectsInvalidKeyLength(t *testing.T) {
	good := mustKey(t, 32)
	ct, _ := Seal(good, []byte("x"), nil)
	for _, n := range []int{0, 16, 31, 33} {
		bad := make([]byte, n)
		if _, err := Open(bad, ct, nil); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Open(key=%d bytes): got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestNewSealer_RejectsInvalidKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := NewSealer(make([]byte, n)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("NewSealer(key=%d): got %v, want ErrInvalidKey", n, err)
		}
	}
}

// ---------------------------------------------------------------------
// Tamper / wrong key / wrong AAD
// ---------------------------------------------------------------------

func TestOpen_TamperedTag(t *testing.T) {
	key := mustKey(t, 32)
	ct, _ := Seal(key, []byte("hello"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0x01 // flip a bit in the tag
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Open(key, tampered, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered, got %v", err)
	}
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	key := mustKey(t, 32)
	ct, _ := Seal(key, []byte("hello, world, this is a longer payload"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	// Flip a bit in the middle of the ciphertext (not nonce, not tag).
	raw[20] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Open(key, tampered, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered, got %v", err)
	}
}

func TestOpen_WrongKey(t *testing.T) {
	k1 := mustKey(t, 32)
	k2 := mustKey(t, 32)
	ct, _ := Seal(k1, []byte("hello"), nil)
	if _, err := Open(k2, ct, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered with wrong key, got %v", err)
	}
}

func TestOpen_WrongAAD(t *testing.T) {
	key := mustKey(t, 32)
	ct, _ := Seal(key, []byte("hello"), []byte("ctx-1"))
	if _, err := Open(key, ct, []byte("ctx-2")); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered with wrong AAD, got %v", err)
	}
}

func TestOpen_MissingAADWhenSet(t *testing.T) {
	key := mustKey(t, 32)
	ct, _ := Seal(key, []byte("hello"), []byte("ctx"))
	if _, err := Open(key, ct, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered when AAD omitted at Open, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Format errors
// ---------------------------------------------------------------------

func TestOpen_NotBase64(t *testing.T) {
	key := mustKey(t, 32)
	if _, err := Open(key, "!!!not base64!!!", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestOpen_TooShort(t *testing.T) {
	key := mustKey(t, 32)
	short := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	if _, err := Open(key, short, nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("expected ErrCiphertextTooShort, got %v", err)
	}
}

func TestOpen_UnsupportedVersion(t *testing.T) {
	key := mustKey(t, 32)
	// Construct a 29-byte buffer with a version byte we don't know.
	buf := make([]byte, aeadMinSize)
	buf[0] = 0xFF // unknown version
	bad := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := Open(key, bad, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got %v", err)
	}
}

// ---------------------------------------------------------------------
// Sealer
// ---------------------------------------------------------------------

func TestSealer_RoundTrip(t *testing.T) {
	key := mustKey(t, 32)
	s, err := NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	ct, err := s.Seal([]byte("hello, world"), []byte("ctx"))
	if err != nil {
		t.Fatalf("Sealer.Seal: %v", err)
	}
	pt, err := s.Open(ct, []byte("ctx"))
	if err != nil {
		t.Fatalf("Sealer.Open: %v", err)
	}
	if string(pt) != "hello, world" {
		t.Errorf("got %q", pt)
	}
}

func TestSealer_OpenAcceptsSealOutput(t *testing.T) {
	// Cross-check: package-level Seal output should be readable by a Sealer.
	key := mustKey(t, 32)
	ct, err := Seal(key, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s, _ := NewSealer(key)
	pt, err := s.Open(ct, nil)
	if err != nil {
		t.Fatalf("Sealer.Open: %v", err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}

func TestSeal_AcceptsSealerOutput(t *testing.T) {
	// Reverse direction.
	key := mustKey(t, 32)
	s, _ := NewSealer(key)
	ct, _ := s.Seal([]byte("hello"), nil)
	pt, err := Open(key, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}

func TestSealer_ConcurrentUse(t *testing.T) {
	// gcm.AEAD is documented as concurrent-safe; smoke-test it.
	key := mustKey(t, 32)
	s, _ := NewSealer(key)
	const n = 200
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			ct, err := s.Seal([]byte("payload"), nil)
			if err != nil {
				done <- err
				return
			}
			pt, err := s.Open(ct, nil)
			if err != nil {
				done <- err
				return
			}
			if string(pt) != "payload" {
				done <- errors.New("plaintext mismatch")
				return
			}
			done <- nil
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent op: %v", err)
		}
	}
}

// ---------------------------------------------------------------------
// Output shape / size
// ---------------------------------------------------------------------

func TestSeal_OutputSize(t *testing.T) {
	key := mustKey(t, 32)
	for _, n := range []int{0, 1, 16, 100, 1000} {
		pt := bytes.Repeat([]byte{0x42}, n)
		ct, err := Seal(key, pt, nil)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", n, err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(ct)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := aeadMinSize + n // header + tag + plaintext
		if len(raw) != want {
			t.Errorf("plaintext=%d: ciphertext bytes=%d want=%d", n, len(raw), want)
		}
		if raw[0] != VersionAEADv1 {
			t.Errorf("version byte = 0x%02x, want 0x%02x", raw[0], VersionAEADv1)
		}
	}
}

func TestSeal_OutputIsBase64URL(t *testing.T) {
	key := mustKey(t, 32)
	ct, _ := Seal(key, []byte("hello"), nil)
	// base64url-no-pad uses A-Za-z0-9_- and no '='.
	if strings.ContainsAny(ct, "+/=") {
		t.Errorf("output contains non-URL-safe chars: %q", ct)
	}
}

// ---------------------------------------------------------------------
// Test-only deterministic helper (sealWithNonce)
// ---------------------------------------------------------------------

func TestSealWithNonce_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x00}, 32)
	nonce := bytes.Repeat([]byte{0x11}, aeadNonceSize)
	a, err := sealWithNonce(key, []byte("hello"), nil, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}
	b, err := sealWithNonce(key, []byte("hello"), nil, nonce)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}
	if a != b {
		t.Errorf("expected identical ciphertexts with fixed nonce; got %q != %q", a, b)
	}
}

func TestSealWithNonce_RejectsBadNonceLength(t *testing.T) {
	key := mustKey(t, 32)
	if _, err := sealWithNonce(key, []byte("x"), nil, []byte{0x01}); err == nil {
		t.Errorf("expected error for short nonce")
	}
}
