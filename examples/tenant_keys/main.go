// Per-tenant encryption keys derived from a single root key.
//
// Pattern: a single application root key is loaded from secure
// config. Per-tenant sub-keys are derived using HKDF-SHA256, with
// the tenant ID as the "info" parameter. Compromise of one tenant's
// data does not expose other tenants — even though the root key is
// shared, each derived key is independent.
//
// HKDF is part of golang.org/x/crypto. v1.1 of this package will
// expose a built-in DeriveKey helper.
package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"

	"github.com/ubgo/crypt"
	"golang.org/x/crypto/hkdf"
)

// deriveTenantKey derives a 32-byte AEAD key for the given tenant.
// The "salt" parameter to HKDF is unused here (nil); a per-deployment
// salt would add an extra layer of context binding if desired.
func deriveTenantKey(rootKey []byte, tenantID string) ([]byte, error) {
	h := hkdf.New(sha256.New, rootKey, nil, []byte("tenant:"+tenantID))
	out := make([]byte, crypt.AEADKeySize)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func main() {
	rootKey := []byte("root-application-key-32-bytes!!!") // 32 bytes

	tenants := []string{"acme", "globex", "initech"}
	keys := make(map[string][]byte)

	for _, t := range tenants {
		k, err := deriveTenantKey(rootKey, t)
		if err != nil {
			log.Fatal(err)
		}
		keys[t] = k
		fmt.Printf("derived key for tenant %q (first 8 bytes): %x...\n", t, k[:8])
	}

	// Each tenant's data is encrypted with their own derived key.
	plaintext := []byte("tenant-private-data")
	enc := make(map[string]string)
	for _, t := range tenants {
		ct, err := crypt.Seal(keys[t], plaintext, nil)
		if err != nil {
			log.Fatal(err)
		}
		enc[t] = ct
	}

	// Each tenant can decrypt their own data.
	for _, t := range tenants {
		pt, err := crypt.Open(keys[t], enc[t], nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("tenant %q decrypted: %s\n", t, pt)
	}

	// Acme's key cannot decrypt Globex's data — keys are independent.
	if _, err := crypt.Open(keys["acme"], enc["globex"], nil); err != nil {
		fmt.Printf("\ncross-tenant decrypt blocked: %v\n", err)
	}
}
