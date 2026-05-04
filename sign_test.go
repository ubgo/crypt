package crypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestSign_OutputSize(t *testing.T) {
	mac := Sign([]byte("key"), []byte("data"))
	if len(mac) != sha256.Size {
		t.Errorf("Sign output: got %d bytes, want %d", len(mac), sha256.Size)
	}
}

func TestSign_DeterministicForSameInputs(t *testing.T) {
	a := Sign([]byte("key"), []byte("data"))
	b := Sign([]byte("key"), []byte("data"))
	if !bytes.Equal(a, b) {
		t.Errorf("Sign should be deterministic for same key+data")
	}
}

func TestSign_DiffersForDifferentKey(t *testing.T) {
	a := Sign([]byte("k1"), []byte("data"))
	b := Sign([]byte("k2"), []byte("data"))
	if bytes.Equal(a, b) {
		t.Errorf("Sign should differ for different keys")
	}
}

func TestSign_DiffersForDifferentData(t *testing.T) {
	a := Sign([]byte("key"), []byte("d1"))
	b := Sign([]byte("key"), []byte("d2"))
	if bytes.Equal(a, b) {
		t.Errorf("Sign should differ for different data")
	}
}

func TestSign_KnownAnswer(t *testing.T) {
	// Compute against std lib directly to confirm we're exposing the
	// same algorithm.
	key := []byte("secret-key")
	data := []byte("the message")

	want := hmac.New(sha256.New, key)
	want.Write(data)
	wantMAC := want.Sum(nil)

	got := Sign(key, data)
	if !bytes.Equal(got, wantMAC) {
		t.Errorf("Sign output diverges from hmac.New(sha256.New, key)")
	}
}

func TestVerify_AcceptsValidMAC(t *testing.T) {
	key := []byte("k")
	data := []byte("payload")
	mac := Sign(key, data)
	if !Verify(key, data, mac) {
		t.Errorf("Verify rejected a valid MAC")
	}
}

func TestVerify_RejectsTamperedData(t *testing.T) {
	key := []byte("k")
	data := []byte("payload")
	mac := Sign(key, data)
	tampered := append([]byte{}, data...)
	tampered[0] ^= 0x01
	if Verify(key, tampered, mac) {
		t.Errorf("Verify accepted MAC against tampered data")
	}
}

func TestVerify_RejectsTamperedMAC(t *testing.T) {
	key := []byte("k")
	data := []byte("payload")
	mac := Sign(key, data)
	tampered := append([]byte{}, mac...)
	tampered[0] ^= 0x01
	if Verify(key, data, tampered) {
		t.Errorf("Verify accepted tampered MAC")
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	data := []byte("payload")
	mac := Sign([]byte("k1"), data)
	if Verify([]byte("k2"), data, mac) {
		t.Errorf("Verify accepted MAC with wrong key")
	}
}

func TestVerify_RejectsWrongLength(t *testing.T) {
	key := []byte("k")
	data := []byte("payload")
	if Verify(key, data, []byte{0x00}) {
		t.Errorf("Verify accepted 1-byte MAC")
	}
	if Verify(key, data, make([]byte, 100)) {
		t.Errorf("Verify accepted 100-byte MAC")
	}
}

func TestConstantTimeEqual_True(t *testing.T) {
	if !ConstantTimeEqual([]byte("abc"), []byte("abc")) {
		t.Errorf("ConstantTimeEqual rejected equal inputs")
	}
	// Empty inputs.
	if !ConstantTimeEqual(nil, nil) {
		t.Errorf("ConstantTimeEqual(nil, nil) should be true")
	}
	if !ConstantTimeEqual([]byte{}, []byte{}) {
		t.Errorf("ConstantTimeEqual(empty, empty) should be true")
	}
}

func TestConstantTimeEqual_False(t *testing.T) {
	if ConstantTimeEqual([]byte("abc"), []byte("abd")) {
		t.Errorf("ConstantTimeEqual accepted differing inputs")
	}
	if ConstantTimeEqual([]byte("abc"), []byte("abcd")) {
		t.Errorf("ConstantTimeEqual accepted different-length inputs")
	}
}
