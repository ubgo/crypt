package crypt

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

func envelopeKEK() []byte { return bytes.Repeat([]byte{0x99}, AEADKeySize) }

func TestEnvelopeSealer_RoundTrip(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	if err := kms.AddKey("kek-1", envelopeKEK()); err != nil {
		t.Fatal(err)
	}

	sealer := NewEnvelopeSealer(kms, "kek-1")
	ct, err := sealer.Seal(ctx, []byte("regulated-data"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := sealer.Open(ctx, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "regulated-data" {
		t.Errorf("got %q", pt)
	}
}

func TestEnvelopeSealer_UnknownKid(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	sealer := NewEnvelopeSealer(kms, "missing")
	if _, err := sealer.Seal(ctx, []byte("x"), nil); err == nil {
		t.Errorf("expected error sealing under unknown keyID")
	}
}

func TestEnvelopeSealer_RejectsBadCiphertext(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	sealer := NewEnvelopeSealer(kms, "k")

	if _, err := sealer.Open(ctx, "***", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
}

func TestEnvelopeSealer_RejectsUnsupportedVersion(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	sealer := NewEnvelopeSealer(kms, "k")

	// Construct a 0xFF version ciphertext.
	buf := []byte{0xFF, 0, 0, 0, 0}
	bad := base64.RawURLEncoding.EncodeToString(buf)
	if _, err := sealer.Open(ctx, bad, nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestEnvelopeSealer_RejectsTooShort(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	sealer := NewEnvelopeSealer(kms, "k")

	bad := base64.RawURLEncoding.EncodeToString([]byte{0x06, 0x00})
	if _, err := sealer.Open(ctx, bad, nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("got %v, want ErrCiphertextTooShort", err)
	}
}

func TestStaticKMS_AddKey_Validation(t *testing.T) {
	kms := NewStaticKMS()
	if err := kms.AddKey("k", make([]byte, 16)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
}

func TestStaticKMS_Encrypt_Decrypt(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	ct, err := kms.Encrypt(ctx, "k", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := kms.Decrypt(ctx, "k", ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello" {
		t.Errorf("got %q", pt)
	}
}

func TestStaticKMS_UnknownKey(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	if _, _, err := kms.GenerateDataKey(ctx, "missing"); err == nil {
		t.Errorf("expected error on unknown keyID")
	}
	if _, err := kms.Decrypt(ctx, "missing", []byte("x")); err == nil {
		t.Errorf("expected error on unknown keyID")
	}
	if _, err := kms.Encrypt(ctx, "missing", []byte("x")); err == nil {
		t.Errorf("expected error on unknown keyID")
	}
}

func TestEnvelopeSealer_DEKDifferentEachCall(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	sealer := NewEnvelopeSealer(kms, "k")

	a, _ := sealer.Seal(ctx, []byte("hello"), nil)
	b, _ := sealer.Seal(ctx, []byte("hello"), nil)
	if a == b {
		t.Errorf("expected distinct envelope ciphertexts")
	}
}

func TestEnvelopeSealer_AADBound(t *testing.T) {
	ctx := context.Background()
	kms := NewStaticKMS()
	_ = kms.AddKey("k", envelopeKEK())
	sealer := NewEnvelopeSealer(kms, "k")

	ct, _ := sealer.Seal(ctx, []byte("payload"), []byte("ctx-1"))
	if _, err := sealer.Open(ctx, ct, []byte("ctx-2")); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered", err)
	}
}
