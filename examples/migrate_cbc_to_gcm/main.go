// Example: one-shot migration script reading legacy AES-CBC
// ciphertext and rewriting as AEAD AES-GCM.
//
// Pattern: iterate every row in a table that holds CBC-encrypted
// data. For each row, decrypt with DecryptCBC, re-encrypt with
// Seal, write the new ciphertext back. After the script completes,
// the table contains only AEAD ciphertexts and the application can
// switch its read path to crypt.Open exclusively.
//
// In a real migration you would:
//
//   - Use crypt.OpenAuto if some rows might already be AEAD
//     (idempotent re-runs).
//   - Run inside a transaction, batch updates, log row-by-row.
//   - Run during low traffic / off-hours.
//   - Keep a backup before starting.
//
// This example uses an in-memory map to stand in for the database.
package main

import (
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

// fakeDB is a stand-in for a real table.
type fakeDB struct {
	rows map[string]string // id -> ciphertext (CBC or AEAD)
}

func main() {
	key := []byte("01234567890123456789012345678901") // 32 bytes

	// --- Setup: pretend these rows were written with the old CBC
	// encrypter at some point in the past. ---
	db := &fakeDB{rows: make(map[string]string)}
	for i, plaintext := range []string{
		"sk_live_aaaa1111", "sk_live_bbbb2222", "sk_live_cccc3333",
	} {
		ct, err := crypt.EncryptCBC(key, []byte(plaintext))
		if err != nil {
			log.Fatalf("setup CBC: %v", err)
		}
		db.rows[fmt.Sprintf("row_%d", i)] = ct
	}

	// One row already migrated to AEAD (e.g., re-saved after a recent
	// edit). Demonstrates that OpenAuto is safe on mixed data.
	aeadCt, _ := crypt.Seal(key, []byte("sk_live_dddd4444"), nil)
	db.rows["row_3"] = aeadCt

	fmt.Println("--- before migration ---")
	for id, ct := range db.rows {
		fmt.Printf("  %s = %s...\n", id, truncate(ct, 32))
	}

	// --- Migration script ---
	migrated, skipped, errored := 0, 0, 0
	for id, oldCt := range db.rows {
		// Decrypt regardless of format.
		plain, err := crypt.OpenAuto(key, oldCt, nil)
		if err != nil {
			fmt.Printf("  %s: decrypt error: %v\n", id, err)
			errored++
			continue
		}

		// Re-encrypt as AEAD.
		newCt, err := crypt.Seal(key, plain, nil)
		if err != nil {
			fmt.Printf("  %s: re-encrypt error: %v\n", id, err)
			errored++
			continue
		}

		// Detect whether anything actually needed migration. (Cheap
		// heuristic: AEAD outputs are base64url; CBC outputs are hex.)
		if oldCt == newCt {
			skipped++ // shouldn't happen — random nonce always differs
			continue
		}

		db.rows[id] = newCt
		migrated++
	}

	fmt.Printf("\n--- migration result ---\n")
	fmt.Printf("migrated: %d\nskipped:  %d\nerrored:  %d\n\n", migrated, skipped, errored)

	fmt.Println("--- after migration ---")
	for id, ct := range db.rows {
		fmt.Printf("  %s = %s...\n", id, truncate(ct, 32))
	}

	// Sanity check: every row now opens via the modern path.
	fmt.Println("\n--- sanity check (all rows decrypt with crypt.Open) ---")
	for id, ct := range db.rows {
		pt, err := crypt.Open(key, ct, nil)
		if err != nil {
			fmt.Printf("  %s: %v\n", id, err)
			continue
		}
		fmt.Printf("  %s = %s\n", id, pt)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
