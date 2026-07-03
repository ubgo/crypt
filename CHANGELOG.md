# Changelog

All notable changes are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-07-03

First coherent release on `main`. (The earlier `v0.1.0` tag points at an orphaned initial-implementation history and is not an ancestor of this line.) The wire format is considered stable from here; the Go API may still see minor refinements before `v1.0.0`.

### Fixed

- **`EnvelopeSealer.Open` integer-overflow guard**: a crafted envelope whose wrapped-key length was near `math.MaxUint32` overflowed the `5 + wrappedLen` bounds check (computed in `uint32`), slipped past the guard, and panicked on an out-of-range slice — an attacker-triggerable denial of service reachable from any base64-decodable input. The length is now compared in `uint64`. No wire-format change.

### Added — asymmetric & envelope

- **Ed25519 signatures**: `GenerateEd25519`, `SignEd25519`, `VerifyEd25519` for asymmetric (public-key) signing.
- **Asymmetric encryption** (sealed-box style): `GenerateKeyPair`, `SealAsymmetric`, `OpenAsymmetric` using X25519 ECDH + ChaCha20-Poly1305. Anonymous-sender semantics; sign with Ed25519 first if you need sender authentication. Wire format version 0x05.
- **KMS adapter interface**: `KMS` interface (`GenerateDataKey`, `Decrypt`, `Encrypt`) and `EnvelopeSealer` for envelope encryption (per-row DEK wrapped under a KMS-managed KEK). Wire format version 0x06.
- **In-memory `StaticKMS`** adapter for dev and tests.

### Added — streaming & tokens

- **Streaming AEAD**: `SealStream` / `OpenStream` for chunked file encryption with truncation detection. Each chunk binds its position and final-flag into AAD.
- **Time-locked tokens**: `IssueToken` / `VerifyToken` with embedded expiry. Stateless one-time tokens for password reset, email verify, magic login. Returns `ErrExpired` on expiry.

### Added — derivation, rotation & alternative AEAD

- **HKDF key derivation**: `DeriveKey` (SHA-256) for per-tenant or per-purpose sub-keys from a master key.
- **KeyRing for rotation**: `NewKeyRing`, `Add`, `Remove`, `SetActive`, `ActiveKid`. Wire format version 0x03 with embedded kid; old v1 ciphertexts still readable via try-each fallback.
- **ChaCha20-Poly1305 AEAD**: `SealChaCha20` / `OpenChaCha20` for non-AES-NI hardware. Wire format version 0x02.
- **Bcrypt password hashing**: `HashPasswordBcrypt` / `VerifyPasswordBcrypt` for compatibility with systems migrating from bcrypt. Marked `Deprecated`; new code should use argon2id `HashPassword`.

### Added — core baseline

- **AEAD authenticated encryption** with AES-256-GCM: `Seal`, `Open`, `Sealer`, `NewSealer`. AAD support for context binding. Wire format version 0x01.
- **Argon2id password hashing**: `HashPassword`, `VerifyPassword` with PHC-format output.
- **HMAC signing**: `Sign` (HMAC-SHA256), `Verify` (constant-time), `ConstantTimeEqual` wrapper.
- **Random helpers**: `RandomBytes`, `RandomToken` (URL-safe base64 no-pad), `RandomHex`.
- **AES-CBC** as a first-class peer of AES-GCM — `EncryptCBC` / `DecryptCBC` for interop with existing CBC systems (PHP/Java/Python) or reading ciphertext your application already wrote in this format. No built-in authentication; pair with HMAC if needed.
- **Migration helper** at `crypt.OpenAuto` for transitional reads across formats.
- **Cross-language test vectors** at `testdata/vectors.json` shared with the TypeScript counterpart crypt-ts.
- **Sentinel errors**: `ErrInvalidKey`, `ErrTampered`, `ErrUnsupportedVersion`, `ErrInvalidCiphertext`, `ErrInvalidPasswordHash`, `ErrTruncated`, `ErrExpired`, etc.
- **Documentation**: `USAGE.md`, `SECURITY.md`, `WIRE_FORMAT.md`, `MIGRATION.md`, `RECIPES.md`, `FAQ.md`, `BENCHMARKS.md`.
- **Runnable examples** in `examples/` covering encryption-at-rest, magic links, session tokens, webhook signing, encrypted cookies, CSRF tokens, key rotation, audit log integrity, file encryption, API key checks, per-tenant HKDF, cross-language interop.

### Deprecated

- `Cipher`, `New`, `Cipher.Encrypt`, `Cipher.Decrypt` — v0.x type-based string-input wrappers. Use the byte-typed `EncryptCBC` / `DecryptCBC` directly.
- `EncryptWithKey` / `DecryptWithKey` — same v0.x string-typed wrappers. Use byte-typed forms.

(Note: `EncryptCBC` and `DecryptCBC` themselves are NOT deprecated — they are first-class peers of `Seal` / `Open`. Only the older string-typed wrappers are.)

[Unreleased]: https://github.com/ubgo/crypt/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ubgo/crypt/releases/tag/v0.2.0
