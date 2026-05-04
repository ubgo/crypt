// Cross-language interop demo, Go side.
//
// Run this:    go run ./examples/cross_lang_go
// It prints a ciphertext to stdout encrypted under a fixed shared key.
//
// Then in the @ubgo/crypt-ts repo, paste the ciphertext into
// examples/cross-lang-ts/decrypt.ts and run it. The Node side will
// produce the same plaintext.
//
// Reverse direction: run the TS encrypt example, paste the
// ciphertext into examples/cross_lang_go/decrypt.go (or use the
// snippet at the bottom of this file).
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

const sharedKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func main() {
	key, err := hex.DecodeString(sharedKeyHex)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("Hello from Go! This message will decrypt in Node.")
	aad := []byte("crypt-demo-v1")

	ct, err := crypt.Seal(key, plaintext, aad)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=== Go encrypt ===")
	fmt.Printf("key (hex): %s\n", sharedKeyHex)
	fmt.Printf("aad      : %s\n", aad)
	fmt.Printf("plaintext: %s\n", plaintext)
	fmt.Printf("ciphertext (paste into TS decrypt.ts):\n%s\n", ct)

	// Also demonstrate decrypting our own output (sanity).
	pt, err := crypt.Open(key, ct, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nGo round-trip plaintext: %s\n", pt)
}
