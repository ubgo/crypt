# Example: random_token

Generate cryptographically-random tokens, IDs, and keys.

## Run

```sh
cd examples/random_token
go run .
```

## API quick reference

| Function | Output | Use case |
|---|---|---|
| `crypt.RandomBytes(n)` | `n` raw bytes | AEAD keys, HMAC keys, salts |
| `crypt.RandomToken(n)` | base64url-no-pad string from `n` random bytes | API keys, magic links, CSRF |
| `crypt.RandomHex(n)` | lowercase hex string from `n` random bytes | IDs, filenames, log correlation |

## Sizing guide

| Use case | Recommended bytes | Resulting string |
|---|---|---|
| Short-lived tokens (≤24h) | 16 | 22 base64url chars |
| API keys | 24–32 | 32–43 base64url chars |
| AEAD encryption keys | 32 (`crypt.AEADKeySize`) | use raw `RandomBytes` |
| HMAC signing keys | 32 | use raw `RandomBytes` |
| Log correlation IDs | 8 | 16 hex chars |
| Long-lived secrets | 32 | 43 base64url chars |

## Why URL-safe base64?

`RandomToken` uses `base64.RawURLEncoding`:

- Uses `-` and `_` instead of `+` and `/` (no URL escaping needed)
- No `=` padding (no special handling in URLs or HTTP headers)
- Decodes back to exact same bytes via `base64.RawURLEncoding.DecodeString`

If you copy a `RandomToken` output into a URL like `https://example.com/verify?t=...`, no encoding is needed.

## Why not `math/rand`?

Never use `math/rand` for any of the above. It's pseudo-random and predictable from a seed. `crypt.RandomBytes` (and all helpers built on it) sources from `crypto/rand`, which reads from the OS-level CSPRNG (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows).
