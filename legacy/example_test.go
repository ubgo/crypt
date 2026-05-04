package legacy_test

import (
	"fmt"

	"github.com/ubgo/crypt"
	"github.com/ubgo/crypt/legacy"
)

// ExampleOpenAuto demonstrates dispatching transparently between
// modern AEAD and legacy CBC ciphertext formats — useful in a
// migration script that walks a table containing both.
func ExampleOpenAuto() {
	key := []byte("01234567890123456789012345678901")

	// Two ciphertexts in production: one AEAD, one CBC.
	aead, _ := crypt.Seal(key, []byte("modern"), nil)
	cbc, _ := crypt.EncryptCBC(key, []byte("legacy"))

	for _, ct := range []string{aead, cbc} {
		pt, err := legacy.OpenAuto(key, ct, nil)
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		fmt.Println(string(pt))
	}
	// Output:
	// modern
	// legacy
}
