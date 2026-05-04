# Example: key_rotation

Hand-rolled multi-key reader pattern, predating the built-in `KeyRing`. Keep this example for understanding — for new code, use the [`keyring_rotation`](../keyring_rotation) example with the built-in `KeyRing` type.

## When to use this pattern

- You need rotation but your wire format predates the v3 (kid-tagged) `KeyRing` ciphertext layout.
- You're working with v1-format ciphertext and want to keep historical readability without re-encrypting.

## When to use `KeyRing` instead

- New code. The built-in tags ciphertext with the kid, so reads dispatch O(1) instead of trying each key.

## Run

```sh
cd examples/key_rotation
go run .
```

## What it does

1. Defines a `MultiKeyReader` that holds an ordered list of keys.
2. Tries each key on Open until one succeeds (try-each pattern).
3. Demonstrates reading old + new ciphertexts with the same reader.

## Adapting to your code

For brand-new code:

```go
ring, _ := crypt.NewKeyRing("v1", oldKey)
ring.Add("v2", newKey)
ring.SetActive("v2")

// Auto-dispatches by embedded kid.
pt, _ := ring.Open(ct, nil)
```

For reading legacy v1-format (no kid) where you just need fallback:

```go
type MultiKeyReader struct{ keys [][]byte }

func (m *MultiKeyReader) Open(ct string, aad []byte) ([]byte, error) {
    for _, k := range m.keys {
        if pt, err := crypt.Open(k, ct, aad); err == nil {
            return pt, nil
        }
    }
    return nil, errors.New("no key opens this ciphertext")
}
```

## See also

- [`keyring_rotation`](../keyring_rotation) — built-in `KeyRing` (recommended)
- `MIGRATION.md` for full rotation playbook
