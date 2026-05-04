// Streaming AEAD for arbitrary-size files.
//
// Pattern: read a file (or any io.Reader) chunk-by-chunk, seal each
// chunk under the application key, write to an io.Writer (S3,
// disk, network). To decrypt, reverse.
//
// SealStream / OpenStream handle nonce derivation, chunk
// authentication, and truncation detection. Each chunk is bound to
// its position via AAD, so attackers cannot reorder or remove
// chunks without the open call detecting it.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ubgo/crypt"
)

func main() {
	key := make([]byte, crypt.AEADKeySize)
	rand.Read(key)

	tmp, err := os.MkdirTemp("", "crypt-stream-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	plainPath := filepath.Join(tmp, "input.txt")
	encPath := filepath.Join(tmp, "input.enc")
	decPath := filepath.Join(tmp, "input.dec")

	// Write a 1 MB plaintext file.
	plaintext := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog\n", 25_000))
	os.WriteFile(plainPath, plaintext, 0o644)
	fmt.Printf("plaintext: %d bytes\n", len(plaintext))

	// Encrypt streaming.
	in, _ := os.Open(plainPath)
	defer in.Close()
	enc, _ := os.Create(encPath)
	defer enc.Close()
	if err := crypt.SealStream(key, in, enc, crypt.DefaultStreamChunkSize); err != nil {
		log.Fatal(err)
	}
	encInfo, _ := os.Stat(encPath)
	fmt.Printf("ciphertext: %d bytes (%.1fx larger due to per-chunk tags)\n",
		encInfo.Size(), float64(encInfo.Size())/float64(len(plaintext)))

	// Decrypt streaming.
	encR, _ := os.Open(encPath)
	defer encR.Close()
	dec, _ := os.Create(decPath)
	defer dec.Close()
	if err := crypt.OpenStream(key, encR, dec); err != nil {
		log.Fatal(err)
	}
	dec.Close()

	got, _ := os.ReadFile(decPath)
	if !bytes.Equal(got, plaintext) {
		log.Fatal("plaintext mismatch")
	}
	fmt.Printf("decrypted: %d bytes (matches original)\n", len(got))

	// Truncation detection — drop the trailing chunk marker.
	encBytes, _ := os.ReadFile(encPath)
	truncated := encBytes[:len(encBytes)-100]
	var sink bytes.Buffer
	if err := crypt.OpenStream(key, bytes.NewReader(truncated), &sink); errors.Is(err, crypt.ErrTruncated) {
		fmt.Printf("\ntruncation detected: %v\n", err)
	}

	_ = io.Discard
}
