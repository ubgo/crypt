package crypt

import (
	"bytes"
	"errors"
	"testing"
)

// ----- Ed25519 -----

func TestGenerateEd25519_Sizes(t *testing.T) {
	pub, priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != Ed25519PublicKeySize {
		t.Errorf("pub len=%d want %d", len(pub), Ed25519PublicKeySize)
	}
	if len(priv) != Ed25519PrivateKeySize {
		t.Errorf("priv len=%d want %d", len(priv), Ed25519PrivateKeySize)
	}
}

func TestEd25519_RoundTrip(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	data := []byte("the message")
	sig, err := SignEd25519(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != Ed25519SignatureSize {
		t.Errorf("sig len=%d want %d", len(sig), Ed25519SignatureSize)
	}
	ok, err := VerifyEd25519(pub, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("verify should succeed")
	}
}

func TestEd25519_RejectsTamperedData(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	sig, _ := SignEd25519(priv, []byte("original"))
	ok, err := VerifyEd25519(pub, []byte("tampered"), sig)
	if err != nil || ok {
		t.Errorf("tampered data should not verify: ok=%v err=%v", ok, err)
	}
}

func TestEd25519_RejectsTamperedSig(t *testing.T) {
	pub, priv, _ := GenerateEd25519()
	sig, _ := SignEd25519(priv, []byte("data"))
	sig[0] ^= 0x01
	ok, err := VerifyEd25519(pub, []byte("data"), sig)
	if err != nil || ok {
		t.Errorf("tampered sig should not verify: ok=%v err=%v", ok, err)
	}
}

func TestEd25519_RejectsWrongKeySize(t *testing.T) {
	if _, err := SignEd25519(make([]byte, 32), []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
	if _, err := VerifyEd25519(make([]byte, 16), []byte("x"), make([]byte, 64)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
}

func TestEd25519_RejectsWrongSigSize(t *testing.T) {
	pub, _, _ := GenerateEd25519()
	if _, err := VerifyEd25519(pub, []byte("x"), make([]byte, 32)); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("got %v, want ErrInvalidSignature", err)
	}
}

// ----- Asymmetric encrypt -----

func TestGenerateKeyPair_Sizes(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != X25519KeySize {
		t.Errorf("pub len=%d want %d", len(pub), X25519KeySize)
	}
	if len(priv) != X25519KeySize {
		t.Errorf("priv len=%d want %d", len(priv), X25519KeySize)
	}
}

func TestSealAsymmetric_RoundTrip(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	plain := []byte("hello, world")

	ct, err := SealAsymmetric(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenAsymmetric(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("got %q want %q", got, plain)
	}
}

func TestSealAsymmetric_DifferentEachCall(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	a, _ := SealAsymmetric(pub, []byte("hello"))
	b, _ := SealAsymmetric(pub, []byte("hello"))
	if a == b {
		t.Errorf("expected distinct ciphertexts (random ephemeral key)")
	}
}

func TestOpenAsymmetric_WrongKey(t *testing.T) {
	pubA, _, _ := GenerateKeyPair()
	_, privB, _ := GenerateKeyPair()

	ct, _ := SealAsymmetric(pubA, []byte("hello"))
	if _, err := OpenAsymmetric(privB, ct); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered", err)
	}
}

func TestSealAsymmetric_RejectsBadKey(t *testing.T) {
	if _, err := SealAsymmetric(make([]byte, 16), []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
	if _, err := OpenAsymmetric(make([]byte, 16), "anything"); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got %v, want ErrInvalidKey", err)
	}
}

func TestOpenAsymmetric_BadCiphertext(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	if _, err := OpenAsymmetric(priv, "***"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("got %v, want ErrInvalidCiphertext", err)
	}
	if _, err := OpenAsymmetric(priv, "AQ"); !errors.Is(err, ErrCiphertextTooShort) {
		t.Errorf("got %v, want ErrCiphertextTooShort", err)
	}
}

func TestOpenAsymmetric_TamperedTag(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	ct, _ := SealAsymmetric(pub, []byte("hello"))
	tampered := ct[:len(ct)-1] + "X"
	if _, err := OpenAsymmetric(priv, tampered); err == nil {
		t.Errorf("expected error on tampered ciphertext")
	}
}
