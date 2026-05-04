# FAQ

## What does this package replace?

Hand-rolled wrappers around `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/rand`, `crypto/subtle`, and `golang.org/x/crypto/argon2`. Most Go applications need a small subset of these to do encrypt-at-rest, sign webhooks, hash passwords, and generate API tokens. This package provides the wrappers, audited and tested.

## Why not just use `crypto/aes` directly?

You can. But you'll likely get the small details wrong: nonce reuse, no version tag, manual base64, no AAD, no const-time comparison helper. The whole point of `crypt` is to provide one well-thought-out shape so callers don't have to think about those details.

## Can I use AES-CBC, or is it forbidden?

Use it freely. `EncryptCBC` and `DecryptCBC` are first-class peers of `Seal` and `Open`. Pick CBC when you need to interoperate with an existing system that uses AES-CBC (PHP `openssl_encrypt`, Java `javax.crypto`, older Python/Ruby code), when you have specific compliance constraints, or when reading ciphertext your application already wrote in this format.

The trade-off vs AES-GCM: CBC has no built-in message authentication, so a tampered ciphertext either fails PKCS#7 unpadding (~99.6% of the time) or produces silent garbage plaintext (~0.4%). If you care about tamper detection on CBC output, layer HMAC on top (encrypt-then-MAC pattern). Or use `Seal/Open` which builds in authentication.

The v0.x string-typed wrappers (`Cipher`, `New`, `EncryptWithKey`, `DecryptWithKey`) ARE marked `Deprecated` — that's about preferring the byte-typed API, not avoiding CBC. The byte-typed `EncryptCBC`/`DecryptCBC` are not deprecated.

## Why AES-256-GCM, not ChaCha20-Poly1305?

GCM is hardware-accelerated on every modern x86_64 server (AES-NI) and ARMv8 mobile CPU. It's the NIST standard for authenticated encryption. Both Go and Node std libs implement it identically, enabling our cross-language wire format.

ChaCha20-Poly1305 is faster than software-only AES, so v1.1 will add it for edge devices without AES-NI. For typical cloud servers, GCM wins.

## Why argon2id, not bcrypt?

Argon2id is OWASP-recommended (2023+). It's memory-hard, GPU-resistant, and has a tunable trade-off between time and memory cost. Bcrypt is acceptable for compatibility but not the modern choice; if you're migrating from a system that already uses bcrypt, [F-13 in `FEATURES.md`](https://github.com/ubgo/crypt/blob/main/FEATURES.md) tracks adding bcrypt support.

## Why no JWT?

JWT has well-documented foot-guns: `alg=none`, algorithm confusion, header injection. Our `examples/session_token` shows how to build the same stateless-token shape (small payload + expiry) using `Seal` directly — no JOSE header, no algorithm negotiation, smaller output. If you need standard JWT for interop with another service, use `paseto-go` or `go-jose` directly.

## What if I lose the key?

You lose the data. There is no recovery path. This is a feature, not a bug. Operationally:

- Store keys in a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) with backup/replication.
- Have a key-rotation policy so loss of one key doesn't lose all data (see `MIGRATION.md` and `examples/key_rotation`).
- Don't store keys in env vars on a single machine without backup.

## Can I encrypt in Go and decrypt in the browser?

Not with this package directly — it targets Node.js, not browsers. The wire format is portable, so a future browser build using WebCrypto would interop, but it's not on the roadmap. For now, decrypt server-side and send plaintext over HTTPS to the browser.

## Can I use this on AWS Lambda / Cloudflare Workers / Vercel?

- **AWS Lambda:** yes, runs anywhere Go runs. Cold start adds ~50ms regardless.
- **Cloudflare Workers:** Go support is experimental. Workers also typically prefer the JS counterpart (`@ubgo/crypt`).
- **Vercel Edge:** Edge runs JS only — use `@ubgo/crypt`.
- **Vercel Serverless:** yes, runs Go fine.

`HashPassword` (argon2id) uses 64 MiB memory by default. On Lambda with 128 MB allocated this works but is tight; bump Lambda memory or accept slow cold starts.

## How do I rotate keys without breaking existing data?

See `examples/key_rotation` for a working pattern. Short answer: hold the old key as a "fallback" reader for a window, write new data with the new key, naturally turn over data, then drop the old key.

`v1.1` will ship a built-in `KeyRing` type that automates this with a key-id field in the ciphertext header.

## Why isn't `Seal` a method on a `Key` type?

Because most callers use a single bound key for the lifetime of an application — that's `Sealer`. The package-level `Seal` exists for one-shot calls (CLI tools, migration scripts, tests). Keep them separate; both have idiomatic uses.

## Why does `Verify` return `bool` instead of `error`?

A failed signature isn't an error in the Go-idiomatic sense — it's a normal outcome that the caller is checking for. Returning `bool` makes the call site cleaner: `if !Verify(...) { abort }`. We do return `error` from `Open` because there are several distinct failure modes (tamper, wrong key, malformed input).

## Why do you allocate so much per `Seal` call?

Each call creates: the `cipher.Block`, the `cipher.AEAD`, the nonce buffer, the output buffer, and the base64 string. The `Sealer` type amortizes block + AEAD creation. Further allocation reduction would require an opaque streaming API that's harder to misuse — we declined.

## Can I use a 16-byte (AES-128) key for `Seal`?

No. `Seal` requires exactly 32 bytes (AES-256-GCM). If you have only 16 bytes of key material, derive 32 bytes with `crypt.DeriveKey` (HKDF). 16-byte keys ARE accepted by `EncryptCBC` for AES-128 — use that path if you specifically need AES-128 for interop with another system.

## What's the difference between AAD and AAD-bound IDs in the plaintext?

AAD is authenticated by the GCM tag but not encrypted. If you put a user ID in the plaintext alone, an attacker who captures the ciphertext for user A and modifies the user ID in transit will fail the tag check (good) but you also can't read the ID without decrypting. Putting the user ID in AAD (or both) lets you bind the ciphertext to a context that's visible at decrypt time without an extra round-trip.

Common pattern:

```go
// Bind to a user; user ID is also in plaintext for convenience.
ct, _ := sealer.Seal(payloadJSON, []byte("user:"+userID))
// At decrypt time, AAD must match — caller supplies userID from session.
pt, err := sealer.Open(ct, []byte("user:"+userID))
```

## Is this package FIPS-140 certified?

No. The Go standard library has FIPS-validated builds (`crypto/fips140`), and our package uses those primitives transitively, but our wrapper itself is not separately certified. If you have a FIPS requirement, use Go's std lib directly (or open an issue describing your requirement).

## Why is the wire format byte 0x01 instead of a header string?

Compactness. A 1-byte version tag costs 1 byte; a string like `"$crypt-v1$"` costs 11 bytes. Over millions of ciphertexts, the savings add up. The trade-off is human-readability — base64-decode a ciphertext and the first byte tells you the algorithm.

## Can I use this from C / Python / Rust / Java?

Anyone can target the wire format documented in `WIRE_FORMAT.md`. If you build a sibling library in another language, validate it against `testdata/vectors.json` for byte-identical output. We'd happily link your repo.

## Why no streaming AEAD for files?

Coming in v1.2 (F-15 in `FEATURES.md`). Until then, `examples/encrypted_file` shows a buffer-based approach that works for files up to a few hundred MB.

## Is there a CLI?

No. v0.x had a `crypt -e/-d` CLI; we removed it because it encouraged unsafe key-on-CLI patterns. If you need a CLI, write a tiny wrapper that loads the key from a secrets manager.

## How do I report a security vulnerability?

Open a private security advisory: https://github.com/ubgo/crypt/security/advisories/new

We aim to acknowledge within 48 hours and patch P0 issues within 7 days.

## Where can I see the design rationale?

`SECURITY.md` for the threat model, `WIRE_FORMAT.md` for byte-level details, `MIGRATION.md` for the v0 → v1 path, `RECIPES.md` for common patterns, `USAGE.md` for the long-form guide.
