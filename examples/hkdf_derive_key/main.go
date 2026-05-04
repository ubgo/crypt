// HKDF key derivation: derive sub-keys from a single master.
//
// Pattern: one application root key in secrets manager. Derive
// per-tenant or per-purpose sub-keys at runtime using HKDF-SHA256.
// Compromise of one tenant's data doesn't expose other tenants —
// even though the root key is shared, the derived keys are
// cryptographically independent.
package main

import (
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	root := []byte("root-application-key-32-bytes!!!")

	// Per-tenant derived keys.
	for _, tenant := range []string{"acme", "globex", "initech"} {
		k, err := crypt.DeriveKey(root, nil, []byte("tenant:"+tenant), crypt.AEADKeySize)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("tenant %-7s key prefix (8 bytes): %x...\n", tenant, k[:8])

		// Use as an AEAD key.
		ct, _ := crypt.Seal(k, []byte("tenant data"), nil)
		pt, _ := crypt.Open(k, ct, nil)
		fmt.Printf("  round-trip: %s\n", pt)
	}

	// Per-purpose sub-keys from one master.
	aeadKey, _ := crypt.DeriveKey(root, nil, []byte("aead-v1"), crypt.AEADKeySize)
	macKey, _ := crypt.DeriveKey(root, nil, []byte("mac-v1"), crypt.AEADKeySize)
	fmt.Printf("\nAEAD-purpose key prefix: %x...\n", aeadKey[:8])
	fmt.Printf("MAC-purpose key prefix:  %x...\n", macKey[:8])

	// Salt option: useful for per-environment binding.
	prodKey, _ := crypt.DeriveKey(root, []byte("env:prod"), []byte("aead-v1"), crypt.AEADKeySize)
	devKey, _ := crypt.DeriveKey(root, []byte("env:dev"), []byte("aead-v1"), crypt.AEADKeySize)
	fmt.Printf("\nprod aead key prefix: %x...\n", prodKey[:8])
	fmt.Printf("dev  aead key prefix: %x... (independent of prod)\n", devKey[:8])
}
