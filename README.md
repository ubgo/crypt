# crypt

AES-CBC + PKCS#7 encryption with hex-encoded ciphertext output. Designed for storing short secrets (API keys, tokens) at rest.

Zero third-party dependencies — uses `crypto/aes`, `crypto/cipher`, `crypto/rand` from the standard library.

## Install

```sh
go get github.com/ubgo/crypt
```

## Quick start

```go
package main

import (
    "fmt"

    "github.com/ubgo/crypt"
)

func main() {
    c, err := crypt.New("12345678901234567890123456789012") // 32-byte AES-256 key
    if err != nil { panic(err) }

    encrypted, _ := c.Encrypt("api-secret-123")
    fmt.Println(encrypted) // hex-encoded ciphertext

    decrypted, _ := c.Decrypt(encrypted)
    fmt.Println(decrypted) // "api-secret-123"
}
```

## Key sizes

The key length selects the AES variant:

| Key length | Variant |
|-----------|---------|
| 16 bytes | AES-128 |
| 24 bytes | AES-192 |
| **32 bytes** | **AES-256 (recommended)** |

Any other length returns an error from `New`.

## Cipher vs. one-shot

```go
// Reuse a Cipher across calls (constructs fresh AES blocks per Encrypt/Decrypt — safe to share).
c, _ := crypt.New(key)
out1, _ := c.Encrypt("a")
out2, _ := c.Encrypt("b")

// Or use the package-level helpers if you don't want to keep a Cipher around.
out, _ := crypt.EncryptWithKey(key, "secret")
```

## Notes

- Each `Encrypt` call uses a fresh random IV from `crypto/rand`. The IV is prepended to the ciphertext, so two encryptions of the same plaintext produce different outputs (semantically secure).
- Output is hex-encoded for easy storage in `TEXT` columns. If you want base64, swap the encoder — it's the only line involved.
- AES-CBC alone provides confidentiality but **not authenticity**. For threat models where ciphertext tampering matters, prefer AES-GCM (authenticated encryption) — `crypt` will grow a GCM mode in a future release.
- The package validates PKCS#7 padding strictly on decryption: a tampered ciphertext that produces invalid padding returns `ErrInvalidPadding` rather than garbage plaintext.

## API

| Symbol | Purpose |
|--------|---------|
| `New(key string) (*Cipher, error)` | Construct a Cipher from a 16/24/32-byte key. |
| `(*Cipher).Encrypt(plaintext string) (string, error)` | Encrypt; returns hex(IV ‖ ciphertext). |
| `(*Cipher).Decrypt(ciphertext string) (string, error)` | Decrypt and unpad. |
| `EncryptWithKey(key, plaintext string) (string, error)` | One-shot Encrypt. |
| `DecryptWithKey(key, ciphertext string) (string, error)` | One-shot Decrypt. |
| `ErrCiphertextTooShort`, `ErrCiphertextNotBlockAligned`, `ErrInvalidPadding` | Sentinel errors for use with `errors.Is`. |

## License

Apache License 2.0. See [`LICENSE`](./LICENSE).
