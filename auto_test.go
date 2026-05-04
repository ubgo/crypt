package crypt_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/crypt"
)

func ringKey32(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestOpenAuto_OpensAEAD(t *testing.T) {
	key := ringKey32(t)
	ct, err := crypt.Seal(key, []byte("hello via aead"), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypt.OpenAuto(key, ct, []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello via aead")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_OpensCBC(t *testing.T) {
	key := ringKey32(t)
	ct, err := crypt.EncryptCBC(key, []byte("hello via cbc"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypt.OpenAuto(key, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("hello via cbc")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_AADIgnoredForCBC(t *testing.T) {
	key := ringKey32(t)
	ct, _ := crypt.EncryptCBC(key, []byte("payload"))
	pt, err := crypt.OpenAuto(key, ct, []byte("ignored"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("payload")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_RejectsGarbage(t *testing.T) {
	key := ringKey32(t)
	if _, err := crypt.OpenAuto(key, "this-is-not-encrypted-anything", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_RejectsWrongKey_AEAD(t *testing.T) {
	good := ringKey32(t)
	bad := ringKey32(t)
	ct, _ := crypt.Seal(good, []byte("x"), nil)
	if _, err := crypt.OpenAuto(bad, ct, nil); err == nil {
		t.Errorf("expected error for wrong key")
	}
}

func TestOpenAuto_EmptyString(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	if _, err := crypt.OpenAuto(key, "", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_BadBase64NotHex(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	if _, err := crypt.OpenAuto(key, "***clearly-neither***", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_HexButNotCBCAligned(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	bad := strings.Repeat("00", 17)
	if _, err := crypt.OpenAuto(key, bad, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_HexShorterThanIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	bad := strings.Repeat("00", 8)
	if _, err := crypt.OpenAuto(key, bad, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_AEADCoincidentalCBCFallthrough(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	too := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	if _, err := crypt.OpenAuto(key, too, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_WithAADOnAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	aad := []byte("ctx")
	ct, _ := crypt.Seal(key, []byte("data"), aad)
	pt, err := crypt.OpenAuto(key, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "data" {
		t.Errorf("got %q", pt)
	}
	if _, err := crypt.OpenAuto(key, ct, []byte("other")); err == nil {
		t.Errorf("expected error with wrong AAD")
	}
}

func TestOpenAuto_AllKeySizesForCBC(t *testing.T) {
	for _, n := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{0x01}, n)
		ct, _ := crypt.EncryptCBC(key, []byte("payload"))
		pt, err := crypt.OpenAuto(key, ct, nil)
		if err != nil {
			t.Errorf("CBC key=%d: %v", n, err)
			continue
		}
		if string(pt) != "payload" {
			t.Errorf("CBC key=%d: got %q", n, pt)
		}
	}
}
