package crypt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func ringKey(b byte) []byte { return bytes.Repeat([]byte{b}, AEADKeySize) }

func TestNewKeyRing_Basic(t *testing.T) {
	r, err := NewKeyRing("v1", ringKey(0x01))
	if err != nil {
		t.Fatal(err)
	}
	if r.ActiveKid() != "v1" {
		t.Errorf("ActiveKid: got %q, want v1", r.ActiveKid())
	}
}

func TestKeyRing_RoundTrip(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	ct, err := r.Seal([]byte("hello"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.Open(ct, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}

func TestKeyRing_Rotation(t *testing.T) {
	r, _ := NewKeyRing("2025", ringKey(0x01))
	ctOld, _ := r.Seal([]byte("encrypted in 2025"), nil)

	if err := r.Add("2026", ringKey(0x02)); err != nil {
		t.Fatal(err)
	}
	if err := r.SetActive("2026"); err != nil {
		t.Fatal(err)
	}

	ctNew, _ := r.Seal([]byte("encrypted in 2026"), nil)

	pt, err := r.Open(ctOld, nil)
	if err != nil || string(pt) != "encrypted in 2025" {
		t.Errorf("old ct: got pt=%q err=%v", pt, err)
	}
	pt, err = r.Open(ctNew, nil)
	if err != nil || string(pt) != "encrypted in 2026" {
		t.Errorf("new ct: got pt=%q err=%v", pt, err)
	}
}

func TestKeyRing_Add_RejectsDuplicate(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if err := r.Add("v1", ringKey(0x02)); err == nil {
		t.Errorf("expected error adding duplicate kid")
	}
}

func TestKeyRing_Add_RejectsBadKey(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if err := r.Add("v2", make([]byte, 16)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
}

func TestKeyRing_Add_RejectsBadKid(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if err := r.Add("", ringKey(0x02)); err == nil {
		t.Errorf("expected error on empty kid")
	}
	if err := r.Add(strings.Repeat("x", 65), ringKey(0x02)); err == nil {
		t.Errorf("expected error on too-long kid")
	}
}

func TestKeyRing_Remove(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if err := r.Add("v2", ringKey(0x02)); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("v1"); err == nil {
		t.Errorf("expected error removing active kid")
	}
	if err := r.Remove("v2"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove("v2"); err == nil {
		t.Errorf("expected error removing missing kid")
	}
}

func TestKeyRing_SetActive_Validation(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if err := r.SetActive("nonexistent"); err == nil {
		t.Errorf("expected error setting unknown kid as active")
	}
}

func TestKeyRing_RejectsUnknownKid(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	ct, _ := r.Seal([]byte("hi"), nil)

	r2, _ := NewKeyRing("v2", ringKey(0x02))
	if _, err := r2.Open(ct, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered for unknown kid", err)
	}
}

func TestKeyRing_OpensV1Ciphertext(t *testing.T) {
	key := ringKey(0x01)
	ct, _ := Seal(key, []byte("v1 data"), nil)

	r, _ := NewKeyRing("active", key)
	pt, err := r.Open(ct, nil)
	if err != nil {
		t.Fatalf("open v1 via ring: %v", err)
	}
	if string(pt) != "v1 data" {
		t.Errorf("got %q", pt)
	}
}

func TestKeyRing_VersionByteIsV3(t *testing.T) {
	r, _ := NewKeyRing("kid", ringKey(0x01))
	ct, _ := r.Seal([]byte("x"), nil)
	raw, err := base64.RawURLEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != VersionAEADv3 {
		t.Errorf("expected v3 byte 0x03, got 0x%02x", raw[0])
	}
}

func TestKeyRing_RejectsBadCiphertext(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	if _, err := r.Open("***", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
	tooShort := base64.RawURLEncoding.EncodeToString([]byte{0x03})
	if _, err := r.Open(tooShort, nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("got %v, want ErrCiphertextTooShort", err)
	}
}

func TestKeyRing_RejectsUnknownVersion(t *testing.T) {
	r, _ := NewKeyRing("v1", ringKey(0x01))
	buf := make([]byte, aeadMinSize)
	buf[0] = 0xFF
	if _, err := r.Open(base64.RawURLEncoding.EncodeToString(buf), nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestKeyRing_OpensV2NotSupported(t *testing.T) {
	// KeyRing only handles v1 + v3. v2 (ChaCha20) requires explicit
	// OpenChaCha20.
	r, _ := NewKeyRing("v1", ringKey(0x01))
	ct, _ := SealChaCha20(ringKey(0x01), []byte("x"), nil) // v2
	if _, err := r.Open(ct, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}
