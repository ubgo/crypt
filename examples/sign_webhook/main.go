// Example: sign and verify outgoing webhooks with HMAC-SHA256.
//
// Pattern: signer and verifier share a secret. Signer computes
// HMAC over the request body, sends it as a header. Verifier
// reproduces the HMAC, compares constant-time.
//
// This is the same pattern Stripe, GitHub, Slack, and most webhook-
// emitting services use.
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/ubgo/crypt"
)

func main() {
	// Shared secret negotiated with the partner integration.
	secret := []byte("partner-webhook-secret")

	// --- Signer side: emitting a webhook ---
	body := []byte(`{"event":"order.created","data":{"id":"ord_42","amount":99.50}}`)

	mac := crypt.Sign(secret, body)
	signature := base64.StdEncoding.EncodeToString(mac)

	fmt.Println("--- outgoing request ---")
	fmt.Printf("X-Signature-Algorithm: hmac-sha256\n")
	fmt.Printf("X-Signature: %s\n", signature)
	fmt.Printf("Body: %s\n\n", body)

	// --- Verifier side: receiving a webhook ---
	receivedBody := body
	receivedSig, _ := base64.StdEncoding.DecodeString(signature)

	if crypt.Verify(secret, receivedBody, receivedSig) {
		fmt.Println("verified — process event")
	} else {
		fmt.Println("rejected — return 401")
	}

	// --- Demonstrate tamper detection ---
	tamperedBody := append([]byte{}, body...)
	tamperedBody[10] ^= 0x01
	if !crypt.Verify(secret, tamperedBody, receivedSig) {
		fmt.Println("\ntampered body rejected — would return 401")
	}

	// --- Demonstrate wrong-key rejection ---
	if !crypt.Verify([]byte("wrong-secret"), receivedBody, receivedSig) {
		fmt.Println("wrong secret rejected — would return 401")
	}
}
