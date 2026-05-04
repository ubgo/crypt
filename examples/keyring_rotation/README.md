# Example: keyring_rotation

Built-in `KeyRing` for graceful key rotation. Wire format embeds a key id (kid) in each ciphertext, so reads dispatch O(1) by kid.

## When to use this pattern

- Annual or scheduled key rotation (compliance: SOC2, PCI).
- Compromise response: add a new active key, leave the old key in for read-only fallback, migrate as natural turnover happens, drop the old key.
- Multi-tenant SaaS where each tenant has a kid identifying their key version.

## Run

```sh
cd examples/keyring_rotation
go run .
```

## What it does

1. Boots a ring with one active key tagged "2025".
2. Seals data — ciphertext is tagged with "2025" in the wire format (version byte 0x03 + kid).
3. Adds a "2026" key, sets it active.
4. New seals are tagged "2026"; old seals still read because the ring still holds the "2025" key.
5. Removes "2025" — orphaned 2025-tagged ciphertexts now fail with `ErrTampered`.

## Comparison with hand-rolled try-each

The [`key_rotation`](../key_rotation) example shows the older try-each pattern: iterate every key on Open until one works. That works on plain v1 ciphertext (no kid) but is O(n) on the number of keys.

`KeyRing` reads the embedded kid and dispatches directly — O(1). Plus, `KeyRing.Open` ALSO accepts plain v1 ciphertexts (try-each fallback) for transitional periods.

## Adapting to your code

```go
// Boot once at app startup. Load keys from secrets manager.
ring, _ := crypt.NewKeyRing(activeKid, activeKey)
for kid, key := range historicalKeys {
    _ = ring.Add(kid, key)
}

// Inject as a service dependency.
type Service struct{ ring *crypt.KeyRing }

func (s *Service) Encrypt(plaintext []byte) (string, error) {
    return s.ring.Seal(plaintext, nil)
}

func (s *Service) Decrypt(ct string) ([]byte, error) {
    return s.ring.Open(ct, nil)
}
```

## Rotation playbook

1. Generate new key, add to KMS / secrets manager.
2. Deploy: include the new key as `Add(newKid, newKey)` but leave the old kid as active.
3. Once all replicas have the new key loaded: deploy with `SetActive(newKid)`.
4. Watch metrics for old-kid reads. They'll drop off as data naturally rotates (sessions: hours; client secrets: weeks).
5. After the rotation window: deploy with `Remove(oldKid)`. Any leftover old-kid ciphertext becomes unreadable (or run a batch migration first).
