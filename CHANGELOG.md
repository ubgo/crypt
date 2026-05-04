# Changelog

All notable changes are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v2 features

- **Ed25519 signatures**: `GenerateEd25519`, `SignEd25519`, `VerifyEd25519` for asymmetric (public-key) signing.
- **Asymmetric encryption** (sealed-box style): `GenerateKeyPair`, `SealAsymmetric`, `OpenAsymmetric` using X25519 ECDH + ChaCha20-Poly1305. Anonymous-sender semantics; sign with Ed25519 first if you need sender authentication. Wire format version 0x05.
- **KMS adapter interface**: `KMS` interface (`GenerateDataKey`, `Decrypt`, `Encrypt`) and `EnvelopeSealer` for envelope encryption (per-row DEK wrapped under a KMS-managed KEK). Wire format version 0x06.
- **In-memory `StaticKMS`** adapter for dev and tests.

### Added — v1.2 features

- **Streaming AEAD**: `SealStream` / `OpenStream` for chunked file encryption with truncation detection. Each chunk binds its position and final-flag into AAD.
- **Time-locked tokens**: `IssueToken` / `VerifyToken` with embedded expiry. Stateless one-time tokens for password reset, email verify, magic login. Returns `ErrExpired` on expiry.

### Added — v1.1 features

- **HKDF key derivation**: `DeriveKey` (SHA-256) for per-tenant or per-purpose sub-keys from a master key.
- **KeyRing for rotation**: `NewKeyRing`, `Add`, `Remove`, `SetActive`, `ActiveKid`. Wire format version 0x03 with embedded kid; old v1 ciphertexts still readable via try-each fallback.
- **ChaCha20-Poly1305 AEAD**: `SealChaCha20` / `OpenChaCha20` for non-AES-NI hardware. Wire format version 0x02.
- **Bcrypt password hashing**: `HashPasswordBcrypt` / `VerifyPasswordBcrypt` for compatibility with systems migrating from bcrypt. Marked `Deprecated`; new code should use argon2id `HashPassword`.

### Added — v1.0 baseline

- **AEAD authenticated encryption** with AES-256-GCM: `Seal`, `Open`, `Sealer`, `NewSealer`. AAD support for context binding. Wire format version 0x01.
- **Argon2id password hashing**: `HashPassword`, `VerifyPassword` with PHC-format output.
- **HMAC signing**: `Sign` (HMAC-SHA256), `Verify` (constant-time), `ConstantTimeEqual` wrapper.
- **Random helpers**: `RandomBytes`, `RandomToken` (URL-safe base64 no-pad), `RandomHex`.
- **Legacy AES-CBC** support for v0.x backward compatibility. Marked `Deprecated`.
- **Migration helper** at `legacy.OpenAuto` for transitional reads across formats.
- **Cross-language test vectors** at `testdata/vectors.json` shared with the TypeScript counterpart at `@ubgo/crypt`.
- **Sentinel errors**: `ErrInvalidKey`, `ErrTampered`, `ErrUnsupportedVersion`, `ErrInvalidCiphertext`, `ErrInvalidPasswordHash`, `ErrTruncated`, `ErrExpired`, etc.
- **Documentation**: `USAGE.md`, `SECURITY.md`, `WIRE_FORMAT.md`, `MIGRATION.md`, `RECIPES.md`, `FAQ.md`, `BENCHMARKS.md`.
- **Runnable examples** in `examples/` covering encryption-at-rest, magic links, session tokens, webhook signing, encrypted cookies, CSRF tokens, key rotation, audit log integrity, file encryption, API key checks, per-tenant HKDF, cross-language interop.

### Deprecated

- `EncryptCBC` / `DecryptCBC` — AES-CBC has no message authentication. Use `Seal` / `Open` for new code. Retained for backward compatibility with existing v0.x data.
- `EncryptWithKey` / `DecryptWithKey` — same Deprecated status.
- `Cipher`, `New`, `Cipher.Encrypt`, `Cipher.Decrypt` — v0.x type-based CBC API. Same Deprecated status.
- `HashPasswordBcrypt` / `VerifyPasswordBcrypt` — only for migrating from bcrypt-using systems.

[Unreleased]: https://github.com/ubgo/crypt
