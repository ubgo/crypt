// Key rotation pattern using a multi-key reader.
//
// Pattern: at any given time, ONE active key signs new ciphertexts
// while a small set of recent retired keys remain readable. As old
// data naturally turns over (or via batch re-encrypt), the older keys
// can be retired entirely.
//
// This file shows the pattern by hand. v1.1 will ship a built-in
// `KeyRing` type that automates this with a key-id field in the
// ciphertext header.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

// MultiKeyReader holds an ordered list of (active first, then retired
// keys to try). Open tries each key in turn until one succeeds.
type MultiKeyReader struct {
	keys [][]byte
}

func NewMultiKeyReader(active []byte, retired ...[]byte) *MultiKeyReader {
	all := make([][]byte, 0, 1+len(retired))
	all = append(all, active)
	all = append(all, retired...)
	return &MultiKeyReader{keys: all}
}

func (m *MultiKeyReader) Open(ciphertext string, aad []byte) ([]byte, error) {
	var lastErr error
	for _, k := range m.keys {
		pt, err := crypt.Open(k, ciphertext, aad)
		if err == nil {
			return pt, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no keys configured")
	}
	return nil, lastErr
}

func main() {
	keyV1 := bytes.Repeat([]byte{0x01}, 32) // old key
	keyV2 := bytes.Repeat([]byte{0x02}, 32) // current active key

	// Ciphertexts in production: some written long ago with v1, some
	// recent with v2. The reader handles both transparently.
	oldCT, _ := crypt.Seal(keyV1, []byte("encrypted with old key"), nil)
	newCT, _ := crypt.Seal(keyV2, []byte("encrypted with new key"), nil)

	reader := NewMultiKeyReader(keyV2, keyV1)

	for label, ct := range map[string]string{"old data": oldCT, "new data": newCT} {
		pt, err := reader.Open(ct, nil)
		if err != nil {
			log.Fatalf("%s: %v", label, err)
		}
		fmt.Printf("%s: %s\n", label, pt)
	}

	// New writes always use the active key.
	freshCT, _ := crypt.Seal(keyV2, []byte("just written"), nil)
	pt, _ := reader.Open(freshCT, nil)
	fmt.Printf("fresh write: %s\n", pt)

	// After all old data has been re-encrypted to v2, the v1 key can
	// be removed from the reader.
}
