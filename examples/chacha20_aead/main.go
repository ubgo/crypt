// ChaCha20-Poly1305 AEAD — alternative to AES-256-GCM.
//
// Use when:
//   - Hardware lacks AES-NI (older ARM, embedded, some IoT chips).
//   - You want defense-in-depth diversity (different cipher family).
//
// Otherwise, prefer Seal (AES-256-GCM) — it's the default because
// AES-NI is ubiquitous on modern x86_64 and ARMv8.
//
// Wire format version is 0x02 (vs 0x01 for AES-GCM). Cross-language
// parity guaranteed with the TS counterpart's sealChaCha20 / openChaCha20.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	key := make([]byte, crypt.AEADKeySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	// Round-trip.
	ct, err := crypt.SealChaCha20(key, []byte("hello via chacha20"), []byte("ctx"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext (v2): %s\n", ct)

	pt, err := crypt.OpenChaCha20(key, ct, []byte("ctx"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decrypted: %s\n", pt)

	// AES Open rejects v2 ciphertext (and vice versa).
	if _, err := crypt.Open(key, ct, []byte("ctx")); errors.Is(err, crypt.ErrUnsupportedVersion) {
		fmt.Printf("\nAES Open on v2: %v (correctly rejected)\n", err)
	}

	// Tamper detection works the same.
	tampered := ct[:len(ct)-2] + "XX"
	if _, err := crypt.OpenChaCha20(key, tampered, []byte("ctx")); err != nil {
		fmt.Printf("tamper detected: %v\n", err)
	}
}
