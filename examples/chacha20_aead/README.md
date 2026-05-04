# Example: chacha20_aead

ChaCha20-Poly1305 AEAD as an alternative to AES-256-GCM.

## When to use this pattern

- Hardware without AES-NI (older ARM, embedded, some IoT chips). ChaCha20 is faster than software AES on these CPUs.
- Defense-in-depth: mixing cipher families across services so a flaw in one doesn't compromise everything.

For typical x86_64 / ARMv8 cloud servers, prefer `Seal` (AES-256-GCM) — AES-NI makes it faster.

## Run

```sh
cd examples/chacha20_aead
go run .
```

## What it does

1. Generates a 32-byte key.
2. Round-trips plaintext through `SealChaCha20` / `OpenChaCha20`.
3. Demonstrates that `Open` (AES-GCM) rejects v2 (ChaCha20) ciphertext, and vice versa — wire format version byte distinguishes them.
4. Shows tamper detection.

## Wire format

Version byte `0x02` (vs `0x01` for AES-GCM). Same nonce + tag layout. See [`WIRE_FORMAT.md`](../../WIRE_FORMAT.md).

## Adapting to your code

```go
// In your config:
useAES := runtime.GOARCH != "arm" && runtime.GOARCH != "arm64-without-aes"

if useAES {
    ct, _ = crypt.Seal(key, plaintext, nil)
} else {
    ct, _ = crypt.SealChaCha20(key, plaintext, nil)
}

// Decrypt path uses version-detection — auto-route:
if /* first byte after base64-decode == 0x02 */ {
    return crypt.OpenChaCha20(key, ct, nil)
}
return crypt.Open(key, ct, nil)
```

For most apps, just pick one consistently. Wire-format dispatch is for mixed environments.
