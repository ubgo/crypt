package crypt_test

import (
	"fmt"

	"github.com/ubgo/crypt"
)

// ExampleOpenAuto demonstrates dispatching transparently between
// AES-GCM and AES-CBC ciphertext formats — useful in a one-shot
// migration script that walks a table containing both.
func ExampleOpenAuto() {
	key := []byte("01234567890123456789012345678901")

	aead, _ := crypt.Seal(key, []byte("modern"), nil)
	cbc, _ := crypt.EncryptCBC(key, []byte("legacy-format"))

	for _, ct := range []string{aead, cbc} {
		pt, err := crypt.OpenAuto(key, ct, nil)
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		fmt.Println(string(pt))
	}
	// Output:
	// modern
	// legacy-format
}
