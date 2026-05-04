package crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func chachaKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, AEADKeySize)
	rand.Read(k)
	return k
}

func TestSealChaCha20_RoundTrip(t *testing.T) {
	key := chachaKey(t)
	ct, err := SealChaCha20(key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := OpenChaCha20(key, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}

func TestChaCha20_VersionByte(t *testing.T) {
	key := chachaKey(t)
	ct, _ := SealChaCha20(key, []byte("x"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	if raw[0] != VersionAEADv2 {
		t.Errorf("first byte = 0x%02x, want 0x02", raw[0])
	}
}

func TestChaCha20_RejectsAESCiphertext(t *testing.T) {
	key := chachaKey(t)
	aesCT, _ := Seal(key, []byte("x"), nil) // version 0x01
	if _, err := OpenChaCha20(key, aesCT, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestAES_RejectsChaChaCiphertext(t *testing.T) {
	key := chachaKey(t)
	chachaCT, _ := SealChaCha20(key, []byte("x"), nil) // version 0x02
	if _, err := Open(key, chachaCT, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestSealChaCha20_RejectsInvalidKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := SealChaCha20(make([]byte, n), []byte("x"), nil); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("key=%d: got %v, want ErrInvalidKey", n, err)
		}
	}
}

func TestOpenChaCha20_TamperedRejected(t *testing.T) {
	key := chachaKey(t)
	ct, _ := SealChaCha20(key, []byte("hello"), nil)
	raw, _ := base64.RawURLEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := OpenChaCha20(key, tampered, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered", err)
	}
}

func TestOpenChaCha20_WrongAAD(t *testing.T) {
	key := chachaKey(t)
	ct, _ := SealChaCha20(key, []byte("hello"), []byte("ctx-1"))
	if _, err := OpenChaCha20(key, ct, []byte("ctx-2")); !errors.Is(err, ErrTampered) {
		t.Errorf("expected ErrTampered")
	}
}

func TestSealChaCha20_DifferentEachCall(t *testing.T) {
	key := chachaKey(t)
	a, _ := SealChaCha20(key, []byte("hello"), nil)
	b, _ := SealChaCha20(key, []byte("hello"), nil)
	if a == b {
		t.Errorf("expected distinct ciphertexts (random nonce)")
	}
}

func TestChaCha20_LongPlaintext(t *testing.T) {
	key := chachaKey(t)
	pt := bytes.Repeat([]byte{0x42}, 100_000)
	ct, _ := SealChaCha20(key, pt, nil)
	got, err := OpenChaCha20(key, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("plaintext mismatch on long input")
	}
}

func TestSealChaCha20WithNonce_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x00}, 32)
	nonce := bytes.Repeat([]byte{0x11}, aeadNonceSize)
	a, _ := sealChaCha20WithNonce(key, []byte("hello"), nil, nonce)
	b, _ := sealChaCha20WithNonce(key, []byte("hello"), nil, nonce)
	if a != b {
		t.Errorf("expected deterministic output with fixed nonce")
	}
}
