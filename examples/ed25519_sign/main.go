// Ed25519 public-key signatures.
//
// Use case: emit a signed artifact (webhook, software update,
// licence file) where verifiers don't have access to the signing
// key. Signer holds the private key; verifiers hold the public key.
//
// Compare with HMAC (Sign / Verify): HMAC requires both sides to
// share the secret. Ed25519 separates the roles: the signer's
// private key never leaves the signing service.
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	// Boot: generate (or load from secrets manager) a keypair.
	pub, priv, err := crypt.GenerateEd25519()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("public key  (publish freely): %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("private key (keep secret):    %s\n\n", base64.StdEncoding.EncodeToString(priv)[:24]+"...")

	// Signer side.
	body := []byte(`{"event":"order.created","id":"ord_42"}`)
	sig, err := crypt.SignEd25519(priv, body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("--- outgoing webhook ---\n")
	fmt.Printf("X-Signature-Algorithm: ed25519\n")
	fmt.Printf("X-Signature: %s\n", base64.StdEncoding.EncodeToString(sig))
	fmt.Printf("Body: %s\n\n", body)

	// Verifier side. Has only the public key.
	ok, err := crypt.VerifyEd25519(pub, body, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("verified: %v\n", ok)

	// Tamper.
	tampered := []byte(`{"event":"order.created","id":"ord_99"}`)
	ok, _ = crypt.VerifyEd25519(pub, tampered, sig)
	fmt.Printf("verify tampered body: %v\n", ok)

	// Wrong public key.
	otherPub, _, _ := crypt.GenerateEd25519()
	ok, _ = crypt.VerifyEd25519(otherPub, body, sig)
	fmt.Printf("verify wrong public key: %v\n", ok)
}
