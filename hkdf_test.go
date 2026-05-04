package crypt

import (
	"bytes"
	"testing"
)

func TestDeriveKey_DifferentInfoProducesDifferentKeys(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	a, err := DeriveKey(master, nil, []byte("tenant:acme"), 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey(master, nil, []byte("tenant:globex"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Errorf("different info should produce different keys")
	}
}

func TestDeriveKey_SameInputsAreDeterministic(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	a, _ := DeriveKey(master, nil, []byte("tenant:acme"), 32)
	b, _ := DeriveKey(master, nil, []byte("tenant:acme"), 32)
	if !bytes.Equal(a, b) {
		t.Errorf("same inputs should produce same key")
	}
}

func TestDeriveKey_LengthRespected(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	for _, n := range []int{16, 24, 32, 64, 128} {
		k, err := DeriveKey(master, nil, []byte("info"), n)
		if err != nil {
			t.Fatalf("DeriveKey(len=%d): %v", n, err)
		}
		if len(k) != n {
			t.Errorf("DeriveKey(len=%d): got len=%d", n, len(k))
		}
	}
}

func TestDeriveKey_RejectsInvalid(t *testing.T) {
	if _, err := DeriveKey(nil, nil, nil, 32); err == nil {
		t.Errorf("expected error on empty masterKey")
	}
	if _, err := DeriveKey([]byte("k"), nil, nil, 0); err == nil {
		t.Errorf("expected error on length=0")
	}
	if _, err := DeriveKey([]byte("k"), nil, nil, -1); err == nil {
		t.Errorf("expected error on negative length")
	}
}

func TestDeriveKey_SaltMatters(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	a, _ := DeriveKey(master, []byte("salt-a"), []byte("info"), 32)
	b, _ := DeriveKey(master, []byte("salt-b"), []byte("info"), 32)
	if bytes.Equal(a, b) {
		t.Errorf("different salts should produce different keys")
	}
}

func TestDeriveKey_UsedAsAEADKey(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	derived, _ := DeriveKey(master, nil, []byte("aead-v1"), AEADKeySize)
	ct, err := Seal(derived, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(derived, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}
