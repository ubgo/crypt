# Example: tenant_keys

Per-tenant encryption keys derived from a single root key using HKDF.

This example uses `golang.org/x/crypto/hkdf` directly to demonstrate the underlying primitive. For new code, prefer the built-in [`hkdf_derive_key`](../hkdf_derive_key) example which uses `crypt.DeriveKey` (one line, same result).

## When to use this pattern

- Multi-tenant SaaS where each tenant's data is encrypted under an independent key.
- Compromise of one tenant's data should not expose other tenants — even though all derived keys come from the same root.
- Per-tenant key rotation: rotate one tenant's derived key by changing the `info` parameter; other tenants are unaffected.

## Run

```sh
cd examples/tenant_keys
go run .
```

## What it does

1. From one root key, derives a unique 32-byte AEAD key per tenant ("acme", "globex", "initech") using `hkdf.New(sha256.New, root, salt=nil, info="tenant:" + tenantID)`.
2. Each tenant encrypts with their own derived key.
3. Demonstrates that one tenant's key cannot decrypt another tenant's data.

## Production-ready version (using built-in `crypt.DeriveKey`)

```go
func tenantKey(rootKey []byte, tenantID string) ([]byte, error) {
    return crypt.DeriveKey(rootKey, nil, []byte("tenant:"+tenantID), crypt.AEADKeySize)
}

func tenantSealer(rootKey []byte, tenantID string) (*crypt.Sealer, error) {
    k, err := tenantKey(rootKey, tenantID)
    if err != nil {
        return nil, err
    }
    return crypt.NewSealer(k)
}
```

For high-throughput services, cache the derived `Sealer` per tenantID with an LRU — derivation is fast (~µs) but constructing a `cipher.AEAD` per request adds up.

## Salt vs info

- **info** (the context-binding parameter): use for tenant ID, purpose, version. Different `info` → independent keys.
- **salt** (the optional second-level binding): use for environment binding (`env:prod`, `env:dev`) so dev keys can't be used to decrypt prod data even if the same root key were leaked.

## Cross-language

Output is byte-identical to crypt-ts's `deriveKey` for the same `(root, salt, info, length)`. Both implementations use HKDF-SHA256 from their language's stdlib.
