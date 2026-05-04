// Example: generating cryptographically-random tokens for API keys,
// magic-link URLs, CSRF tokens, and short-lived IDs.
package main

import (
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	// API keys — typically 24-32 bytes of entropy.
	apiKey, err := crypt.RandomToken(32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("API key:        %s  (%d chars)\n", apiKey, len(apiKey))

	// Magic-link tokens — 16 bytes is plenty for short-lived (24h) tokens.
	magicToken, _ := crypt.RandomToken(16)
	fmt.Printf("magic token:    %s  (%d chars)\n", magicToken, len(magicToken))

	// CSRF tokens.
	csrf, _ := crypt.RandomToken(24)
	fmt.Printf("CSRF token:     %s  (%d chars)\n", csrf, len(csrf))

	// Short hex IDs for log correlation.
	logID, _ := crypt.RandomHex(8)
	fmt.Printf("log id:         %s  (%d chars)\n", logID, len(logID))

	// Raw bytes for use as a key.
	keyBytes, _ := crypt.RandomBytes(crypt.AEADKeySize)
	fmt.Printf("AEAD key bytes: %d bytes (hex: %x)\n", len(keyBytes), keyBytes[:8])
}
