// Built-in KeyRing for graceful key rotation.
//
// Wire format embeds a key id (kid) so reads dispatch to the right
// historical key. Compare with examples/key_rotation/ which shows the
// hand-rolled multi-key reader pattern — this one uses the v1.1
// built-in.
//
// The ring exposes:
//   - NewKeyRing(activeKid, activeKey)
//   - Add(kid, key)
//   - SetActive(kid)
//   - Remove(kid)
//   - Seal: tags ciphertext with active kid
//   - Open: dispatches by kid
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	keyV1 := bytes.Repeat([]byte{0x01}, crypt.AEADKeySize)
	keyV2 := bytes.Repeat([]byte{0x02}, crypt.AEADKeySize)

	// Boot in 2025: only one key.
	ring, err := crypt.NewKeyRing("2025", keyV1)
	if err != nil {
		log.Fatal(err)
	}

	old, _ := ring.Seal([]byte("encrypted in 2025"), nil)
	fmt.Printf("2025 ciphertext active=%s: %s\n", ring.ActiveKid(), old[:32]+"...")

	// 2026: rotate. Add the new key, mark active. Old data still
	// readable; new writes use 2026.
	if err := ring.Add("2026", keyV2); err != nil {
		log.Fatal(err)
	}
	if err := ring.SetActive("2026"); err != nil {
		log.Fatal(err)
	}

	new2026, _ := ring.Seal([]byte("encrypted in 2026"), nil)
	fmt.Printf("2026 ciphertext active=%s: %s\n", ring.ActiveKid(), new2026[:32]+"...")

	// Read both formats transparently.
	pt, _ := ring.Open(old, nil)
	fmt.Printf("\nopened old: %s\n", pt)
	pt, _ = ring.Open(new2026, nil)
	fmt.Printf("opened new: %s\n", pt)

	// After all 2025 data has been re-encrypted (via batch script or
	// natural turnover), drop the 2025 key.
	if err := ring.Remove("2025"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nremoved 2025 — now ring has only %s\n", ring.ActiveKid())

	// 2025-tagged ciphertexts now fail.
	if _, err := ring.Open(old, nil); err != nil {
		fmt.Printf("opening orphaned 2025 ct: %v\n", err)
	}
}
