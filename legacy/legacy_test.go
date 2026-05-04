package legacy_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ubgo/crypt"
	"github.com/ubgo/crypt/legacy"
)

func mustKey(t *testing.T, size int) []byte {
	t.Helper()
	k := make([]byte, size)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

func TestOpenAuto_OpensAEAD(t *testing.T) {
	key := mustKey(t, 32)
	ct, err := crypt.Seal(key, []byte("hello via aead"), []byte("ctx"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	pt, err := legacy.OpenAuto(key, ct, []byte("ctx"))
	if err != nil {
		t.Fatalf("OpenAuto on AEAD: %v", err)
	}
	if !bytes.Equal(pt, []byte("hello via aead")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_OpensCBC(t *testing.T) {
	key := mustKey(t, 32)
	ct, err := crypt.EncryptCBC(key, []byte("hello via cbc"))
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}
	pt, err := legacy.OpenAuto(key, ct, nil)
	if err != nil {
		t.Fatalf("OpenAuto on CBC: %v", err)
	}
	if !bytes.Equal(pt, []byte("hello via cbc")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_AADIgnoredForCBC(t *testing.T) {
	// CBC has no AAD; passing one should not affect the result.
	key := mustKey(t, 32)
	ct, _ := crypt.EncryptCBC(key, []byte("payload"))
	pt, err := legacy.OpenAuto(key, ct, []byte("ignored"))
	if err != nil {
		t.Fatalf("OpenAuto: %v", err)
	}
	if !bytes.Equal(pt, []byte("payload")) {
		t.Errorf("got %q", pt)
	}
}

func TestOpenAuto_RejectsGarbage(t *testing.T) {
	key := mustKey(t, 32)
	if _, err := legacy.OpenAuto(key, "this-is-not-encrypted-anything", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("expected ErrUnknownFormat, got %v", err)
	}
}

func TestOpenAuto_RejectsWrongKey_AEAD(t *testing.T) {
	good := mustKey(t, 32)
	bad := mustKey(t, 32)
	ct, _ := crypt.Seal(good, []byte("x"), nil)
	if _, err := legacy.OpenAuto(bad, ct, nil); err == nil {
		t.Errorf("expected error for wrong key")
	}
}
