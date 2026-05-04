# Example: hkdf_derive_key

HKDF-SHA256 key derivation. Derive sub-keys from a single application root key.

## When to use this pattern

- Per-tenant isolation: one root key, independent derived keys per tenant. Compromise of one tenant's data doesn't expose others.
- Per-purpose split: derive separate keys for AEAD encryption vs HMAC signing from one master.
- Per-environment binding: salt with `env:prod` / `env:dev` so dev data can't be opened with prod keys (or vice versa).

## When NOT to use

- Hashing user passwords. HKDF assumes a high-entropy input. For passwords (low entropy), use `HashPassword` (argon2id).
- As a key-stretching KDF on a low-entropy seed. HKDF is for *expansion*, not stretching.

## Run

```sh
cd examples/hkdf_derive_key
go run .
```

## What it does

1. From one root key, derives a unique 32-byte AEAD key per tenant ("acme", "globex", "initech").
2. Each tenant encrypts with their own derived key.
3. Demonstrates per-purpose split (`aead-v1` vs `mac-v1` info parameters).
4. Demonstrates salt binding (`env:prod` vs `env:dev`).

## Cross-language

`crypt.DeriveKey` produces byte-identical output to crypt-ts's `deriveKey` for the same `(masterKey, salt, info, length)`. The Go example outputs `tenant "acme" key prefix: 67429899cfd14887...` — paste the same root + tenant info into the TS example and you get the same bytes.

## Adapting to your code

```go
type TenantKeys struct {
    root []byte
}

func (t *TenantKeys) Sealer(tenantID string) (*crypt.Sealer, error) {
    k, err := crypt.DeriveKey(t.root, nil, []byte("tenant:"+tenantID), crypt.AEADKeySize)
    if err != nil {
        return nil, err
    }
    return crypt.NewSealer(k)
}

// Per-request:
sealer, _ := tenantKeys.Sealer(req.TenantID)
ct, _ := sealer.Seal(payload, nil)
```

For high-throughput services, cache derived `Sealer`s with an LRU keyed on tenantID — derivation is fast (~µs) but constructing AEAD instances per-request adds up.
