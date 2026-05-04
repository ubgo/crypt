# Examples

Runnable example programs for `github.com/ubgo/crypt`. Each subdirectory is a standalone `main` package — `cd` in and `go run .`.

| Example | Demonstrates |
|---|---|
| [`encrypt_field/`](./encrypt_field) | Encrypt-at-rest pattern for a database column (the canonical use case for `Sealer`). |
| [`sign_webhook/`](./sign_webhook) | Sign an outgoing webhook with HMAC-SHA256 and verify on the receiving side. |
| [`hash_password/`](./hash_password) | Register/login flow with argon2id password hashing. |
| [`random_token/`](./random_token) | Generate API keys, magic-link tokens, and CSRF tokens. |
| [`seal_with_aad/`](./seal_with_aad) | Bind ciphertext to a context using additional authenticated data (AAD). |
| [`sealer/`](./sealer) | Application-wide bound-key `Sealer` injected via dependency. |
| [`migrate_cbc_to_gcm/`](./migrate_cbc_to_gcm) | One-shot migration script from legacy AES-CBC to AEAD AES-GCM. |

## Running

From the repository root:

```sh
cd examples/encrypt_field
go run .
```

Or from the example directory directly:

```sh
go run github.com/ubgo/crypt/examples/encrypt_field
```

## Pattern

Each example follows the same shape:

1. A short comment block at the top of `main.go` explaining the use case.
2. A `main()` that runs end-to-end with output to stdout.
3. A `README.md` with copy-pasteable explanation of the pattern.

You can adapt these directly into your own application code.
