// Encrypt a file before writing it to disk / object storage.
//
// Pattern: read the file into memory (or stream — see future
// streaming AEAD), seal under the application key, write the
// ciphertext bytes. To read, reverse.
//
// This example uses the local filesystem for storage. The exact same
// shape applies to S3, GCS, Azure Blob, R2, or any byte-addressable
// store.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ubgo/crypt"
)

func writeEncrypted(sealer *crypt.Sealer, path string, plaintext []byte, aad []byte) error {
	ct, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(ct), 0o644)
}

func readEncrypted(sealer *crypt.Sealer, path string, aad []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sealer.Open(string(raw), aad)
}

func main() {
	sealer, _ := crypt.NewSealer([]byte("01234567890123456789012345678901"))

	tmp, err := os.MkdirTemp("", "crypt-file-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	// Encrypt + write.
	plain := []byte("This is the contents of a sensitive document.\n" +
		"Anyone with the encryption key can decrypt; everyone else sees ciphertext.")
	encPath := filepath.Join(tmp, "report.enc")
	aad := []byte("file:report-2026-05") // bind to a logical filename + period

	if err := writeEncrypted(sealer, encPath, plain, aad); err != nil {
		log.Fatal(err)
	}

	info, _ := os.Stat(encPath)
	fmt.Printf("wrote %s (%d bytes ciphertext, %d bytes plaintext)\n", encPath, info.Size(), len(plain))

	// Read + decrypt.
	got, err := readEncrypted(sealer, encPath, aad)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\ndecrypted contents:\n%s\n", got)

	// AAD mismatch (filename binding violated) — fails.
	if _, err := readEncrypted(sealer, encPath, []byte("file:wrong-name")); err != nil {
		fmt.Printf("\nAAD mismatch: %v\n", err)
	}
}
