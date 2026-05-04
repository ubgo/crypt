// Example: encrypt-at-rest of a database column.
//
// Pattern: an application key is loaded once at boot. A long-lived
// Sealer is constructed from that key. Every write encrypts; every
// read decrypts.
//
// This is the direct replacement for the v0.x AES-CBC pattern that
// lived in lace/enttypes/Password.
package main

import (
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

// fakeRow stands in for an Ent row or sql.Rows scan target.
type fakeRow struct {
	ID           string
	ClientSecret string // stored ciphertext
}

func main() {
	// In production, load the key from PKL config / KMS / env. Never
	// hard-code in source.
	appKey := []byte("01234567890123456789012345678901") // 32 bytes

	sealer, err := crypt.NewSealer(appKey)
	if err != nil {
		log.Fatalf("init sealer: %v", err)
	}

	// --- Save path: plaintext → ciphertext for storage ---
	plaintext := "sk_live_4242deadbeef"

	encrypted, err := sealer.Seal([]byte(plaintext), nil)
	if err != nil {
		log.Fatalf("seal: %v", err)
	}
	row := fakeRow{ID: "prtn_001", ClientSecret: encrypted}
	fmt.Printf("stored row:\n  id=%s\n  client_secret=%s\n\n", row.ID, row.ClientSecret)

	// --- Load path: read row, decrypt for use ---
	decrypted, err := sealer.Open(row.ClientSecret, nil)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	fmt.Printf("loaded plaintext: %s\n", decrypted)

	// --- Tamper detection: any modification surfaces as an error ---
	tampered := row.ClientSecret[:len(row.ClientSecret)-1] + "X"
	if _, err := sealer.Open(tampered, nil); err != nil {
		fmt.Printf("\ntamper detected: %v\n", err)
	}
}
