package crypt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ubgo/crypt"
)

// ExampleDeriveKey shows deriving a per-tenant AEAD key from a
// single application root key.
func ExampleDeriveKey() {
	root := []byte("root-application-key-32-bytes!!!")

	tenantKey, err := crypt.DeriveKey(root, nil, []byte("tenant:acme"), crypt.AEADKeySize)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(tenantKey))
	// Output: 32
}

// ExampleNewKeyRing demonstrates the rotation pattern: active key
// for new writes, retired keys remain readable.
func ExampleNewKeyRing() {
	keyV1 := bytes.Repeat([]byte{0x01}, crypt.AEADKeySize)
	keyV2 := bytes.Repeat([]byte{0x02}, crypt.AEADKeySize)

	ring, _ := crypt.NewKeyRing("2025", keyV1)
	old, _ := ring.Seal([]byte("old data"), nil)

	_ = ring.Add("2026", keyV2)
	_ = ring.SetActive("2026")
	fresh, _ := ring.Seal([]byte("new data"), nil)

	pt1, _ := ring.Open(old, nil)
	pt2, _ := ring.Open(fresh, nil)
	fmt.Printf("%s | %s\n", pt1, pt2)
	// Output: old data | new data
}

// ExampleSealChaCha20 shows the AES-NI-free AEAD alternative.
func ExampleSealChaCha20() {
	key := bytes.Repeat([]byte{0x42}, crypt.AEADKeySize)

	ct, _ := crypt.SealChaCha20(key, []byte("hello"), nil)
	pt, _ := crypt.OpenChaCha20(key, ct, nil)

	fmt.Println(string(pt))
	// Output: hello
}

// ExampleIssueToken shows the stateless time-locked token pattern.
func ExampleIssueToken() {
	key := []byte("01234567890123456789012345678901")

	tok, _ := crypt.IssueToken(key, []byte("usr_42"), time.Hour, []byte("pwreset-v1"))

	payload, err := crypt.VerifyToken(key, tok, []byte("pwreset-v1"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(payload))
	// Output: usr_42
}

// ExampleVerifyToken shows handling expired tokens distinctly.
func ExampleVerifyToken() {
	key := []byte("01234567890123456789012345678901")

	// Hand-craft an expired token.
	past := uint64(time.Now().Add(-time.Hour).Unix())
	wrapped := make([]byte, 8+5)
	for i := 0; i < 8; i++ {
		wrapped[7-i] = byte(past >> (8 * i))
	}
	copy(wrapped[8:], "stale")
	tok, _ := crypt.Seal(key, wrapped, []byte("pwreset-v1"))

	_, err := crypt.VerifyToken(key, tok, []byte("pwreset-v1"))
	fmt.Println(errors.Is(err, crypt.ErrExpired))
	// Output: true
}

// ExampleSealStream shows chunked encryption of a large input.
func ExampleSealStream() {
	key := bytes.Repeat([]byte{0x42}, crypt.AEADKeySize)

	plain := strings.Repeat("payload\n", 1000)
	var enc bytes.Buffer

	if err := crypt.SealStream(key, strings.NewReader(plain), &enc, crypt.DefaultStreamChunkSize); err != nil {
		panic(err)
	}

	var dec bytes.Buffer
	if err := crypt.OpenStream(key, &enc, &dec); err != nil {
		panic(err)
	}
	fmt.Println(dec.Len() == len(plain))
	// Output: true
}

// ExampleSignEd25519 shows public-key signing.
func ExampleSignEd25519() {
	pub, priv, _ := crypt.GenerateEd25519()

	sig, _ := crypt.SignEd25519(priv, []byte("the message"))
	ok, _ := crypt.VerifyEd25519(pub, []byte("the message"), sig)

	fmt.Println(ok)
	// Output: true
}

// ExampleSealAsymmetric shows X25519 + ChaCha20-Poly1305 sealed-box
// encryption.
func ExampleSealAsymmetric() {
	pub, priv, _ := crypt.GenerateKeyPair()

	ct, _ := crypt.SealAsymmetric(pub, []byte("hello"))
	pt, _ := crypt.OpenAsymmetric(priv, ct)

	fmt.Println(string(pt))
	// Output: hello
}

// ExampleNewEnvelopeSealer shows envelope encryption with a KMS.
func ExampleNewEnvelopeSealer() {
	ctx := context.Background()
	kms := crypt.NewStaticKMS()
	_ = kms.AddKey("kek-1", bytes.Repeat([]byte{0x99}, crypt.AEADKeySize))

	sealer := crypt.NewEnvelopeSealer(kms, "kek-1")
	ct, _ := sealer.Seal(ctx, []byte("regulated"), nil)
	pt, _ := sealer.Open(ctx, ct, nil)

	fmt.Println(string(pt))
	// Output: regulated
}

// ExampleHashPasswordBcrypt is for migrating from bcrypt.
func ExampleHashPasswordBcrypt() {
	hash, _ := crypt.HashPasswordBcrypt("password", crypt.DefaultBcryptCost)
	ok, _ := crypt.VerifyPasswordBcrypt("password", hash)
	fmt.Println(ok)
	// Output: true
}
