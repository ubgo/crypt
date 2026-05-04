// Asymmetric (sealed-box) encryption: X25519 ECDH + ChaCha20-Poly1305.
//
// Anyone with the recipient's public key can encrypt. Only the
// recipient (with the matching private key) can decrypt. The
// sender's identity is NOT authenticated by this operation — to
// authenticate the sender, sign the plaintext with Ed25519 first.
//
// Use case: end-to-end encrypted messages, distributing config
// files with secrets, age-style sealed messages.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	// Recipient publishes their public key. Keeps private key.
	recipientPub, recipientPriv, err := crypt.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("recipient public key (publish):  %s\n", base64.StdEncoding.EncodeToString(recipientPub))
	fmt.Printf("recipient private key (keep):    %s\n\n",
		base64.StdEncoding.EncodeToString(recipientPriv)[:24]+"...")

	// Sender encrypts using only the public key.
	plaintext := []byte("only the recipient can read this")
	ct, err := crypt.SealAsymmetric(recipientPub, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ciphertext (anyone can produce, only recipient can open):\n  %s\n\n", ct)

	// Recipient decrypts.
	pt, err := crypt.OpenAsymmetric(recipientPriv, ct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decrypted by recipient: %s\n", pt)

	// Different private key cannot decrypt.
	_, otherPriv, _ := crypt.GenerateKeyPair()
	if _, err := crypt.OpenAsymmetric(otherPriv, ct); errors.Is(err, crypt.ErrTampered) {
		fmt.Printf("\nwrong recipient: %v (correctly rejected)\n", err)
	}

	// To authenticate the SENDER, sign first then encrypt.
	senderPub, senderPriv, _ := crypt.GenerateEd25519()
	sig, _ := crypt.SignEd25519(senderPriv, plaintext)
	signed := append(sig, plaintext...)
	signedCT, _ := crypt.SealAsymmetric(recipientPub, signed)

	// Recipient: open, then verify the signature against the sender's
	// known public key.
	openedSigned, _ := crypt.OpenAsymmetric(recipientPriv, signedCT)
	gotSig := openedSigned[:crypt.Ed25519SignatureSize]
	gotMsg := openedSigned[crypt.Ed25519SignatureSize:]
	ok, _ := crypt.VerifyEd25519(senderPub, gotMsg, gotSig)
	fmt.Printf("\nsigned + encrypted message:\n  authenticated sender: %v\n  message: %s\n", ok, gotMsg)
}
