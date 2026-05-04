# Example: envelope_encryption

Envelope encryption with a Key Management Service (KMS). Each ciphertext gets a fresh per-row Data Encryption Key (DEK), wrapped under a master Key Encryption Key (KEK) held by the KMS.

## When to use this pattern

- Regulated data (PCI, HIPAA, SOC2) where keys must be managed by a KMS, never plaintext-resident in the application.
- Defense-in-depth: even if the database is exfiltrated, the attacker still needs KMS access to decrypt.
- Per-row key isolation: rotate one row's DEK independently of others if needed.

## When NOT to use

- Throughput-sensitive paths. Each Seal makes one KMS round-trip (~10-50ms). For hot paths, use a regular `Sealer` with a single application key.
- Local development. KMS round-trips slow down test suites; use `Seal/Open` directly in tests.

## Run

```sh
cd examples/envelope_encryption
go run .
```

This example uses `StaticKMS`, which holds the KEK in process memory (suitable for tests/dev only).

## What it does

1. Builds a `StaticKMS` with one KEK.
2. Constructs an `EnvelopeSealer` bound to that KEK by id.
3. Encrypts a plaintext — internally:
   - Calls `kms.GenerateDataKey` → fresh 32-byte DEK + DEK wrapped under KEK.
   - Encrypts the plaintext under the DEK with AES-256-GCM.
   - Embeds the wrapped DEK in the output, so the caller stores one blob.
4. Decrypts — internally calls `kms.Decrypt` to unwrap the DEK, then decrypts the plaintext.
5. Demonstrates that two seals of the same plaintext yield distinct ciphertexts (different DEKs).
6. Demonstrates AAD binding.

## Production: real KMS adapter

`crypt.KMS` is an interface. To plug in AWS KMS / GCP KMS / HashiCorp Vault, write a small adapter:

```go
import (
    awskms "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/ubgo/crypt"
)

type AWSKMS struct{ client *awskms.Client }

func (a *AWSKMS) GenerateDataKey(ctx context.Context, keyID string) (plain, wrapped []byte, err error) {
    out, err := a.client.GenerateDataKey(ctx, &awskms.GenerateDataKeyInput{
        KeyId:   &keyID,
        KeySpec: types.DataKeySpecAes256,
    })
    if err != nil {
        return nil, nil, err
    }
    return out.Plaintext, out.CiphertextBlob, nil
}

func (a *AWSKMS) Decrypt(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
    out, err := a.client.Decrypt(ctx, &awskms.DecryptInput{
        KeyId:          &keyID,
        CiphertextBlob: wrapped,
    })
    if err != nil {
        return nil, err
    }
    return out.Plaintext, nil
}

func (a *AWSKMS) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
    out, err := a.client.Encrypt(ctx, &awskms.EncryptInput{KeyId: &keyID, Plaintext: plaintext})
    if err != nil {
        return nil, err
    }
    return out.CiphertextBlob, nil
}
```

Then:

```go
sealer := crypt.NewEnvelopeSealer(&AWSKMS{client: awskmsClient}, "arn:aws:kms:us-east-1:123:key/abc")
ct, _ := sealer.Seal(ctx, plaintext, aad)
```

GCP KMS and Vault adapters follow the same shape.
