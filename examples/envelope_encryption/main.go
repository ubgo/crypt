// Envelope encryption with KMS.
//
// Pattern: a Key Management Service (AWS KMS, GCP KMS, Vault, etc.)
// holds the master Key Encryption Key (KEK). For each row, the app
// generates a fresh Data Encryption Key (DEK), encrypts the
// plaintext under the DEK with AES-256-GCM, and stores the
// DEK-wrapped-under-KEK alongside the ciphertext.
//
// This example uses StaticKMS for demo purposes — it holds the KEK
// in process memory. In production, plug in a real KMS adapter
// (AWS/GCP/Vault SDKs) that implements the crypt.KMS interface.
//
// Wire format version 0x06 — embeds the wrapped DEK in the
// ciphertext so the caller doesn't store it separately.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

func main() {
	ctx := context.Background()

	// In production: connect to AWS/GCP/Vault and pass that adapter
	// in here.
	kms := crypt.NewStaticKMS()
	kek := bytes.Repeat([]byte{0xA1}, crypt.AEADKeySize)
	if err := kms.AddKey("kek-prod-2026", kek); err != nil {
		log.Fatal(err)
	}

	// EnvelopeSealer is bound to a KEK by id; the KEK never leaves
	// the KMS in production.
	sealer := crypt.NewEnvelopeSealer(kms, "kek-prod-2026")

	// Each Seal makes one KMS round-trip (GenerateDataKey).
	plaintext := []byte("PCI-regulated card metadata")
	ct, err := sealer.Seal(ctx, plaintext, []byte("table:transactions"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("envelope ciphertext: %s...\n", ct[:48])

	// Each Open makes one KMS round-trip (Decrypt).
	pt, err := sealer.Open(ctx, ct, []byte("table:transactions"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decrypted: %s\n", pt)

	// Two ciphertexts of the same plaintext have different wrapped
	// DEKs — distinct envelope outputs each time.
	a, _ := sealer.Seal(ctx, plaintext, nil)
	b, _ := sealer.Seal(ctx, plaintext, nil)
	fmt.Printf("\ntwo seals of same plaintext are distinct: %v\n", a != b)

	// Production sketch (not runnable here):
	//
	//   import "github.com/aws/aws-sdk-go-v2/service/kms"
	//   awsClient := kms.NewFromConfig(awscfg)
	//   adapter := awskmsadapter.New(awsClient) // your code; implements crypt.KMS
	//   sealer := crypt.NewEnvelopeSealer(adapter, "arn:aws:kms:...:key/...")
	//
	// Same Seal/Open API; just a different KMS adapter behind it.

	fmt.Printf("\nthe interface is what crypt provides; KMS-specific\nadapter packages plug in by implementing crypt.KMS.\n")
}
