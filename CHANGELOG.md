# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v1 baseline

### Added

- **AEAD authenticated encryption** with AES-256-GCM via `Seal` / `Open` (package-level) and `Sealer` / `NewSealer` (bound-key form).
- **AAD support** for binding ciphertext to a context (user ID, tenant ID, etc.).
- **Random helpers**: `RandomBytes`, `RandomToken` (URL-safe base64 no-pad), `RandomHex`.
- **HMAC signing**: `Sign` (HMAC-SHA256), `Verify` (constant-time), `ConstantTimeEqual` wrapper.
- **Password hashing**: `HashPassword` / `VerifyPassword` using argon2id with OWASP-recommended parameters; PHC-format string output for forward parameter compatibility.
- **Migration helper**: `legacy.OpenAuto` in subpackage for one-shot or rollover-window reads of mixed CBC/AEAD data.
- **Cross-language test vectors** at `testdata/vectors.json` shared with the TypeScript counterpart at `@ubgo/crypt`.
- **Wire format spec** at `WIRE_FORMAT.md` with byte-by-byte ciphertext layout.
- **Sentinel errors**: `ErrInvalidKey`, `ErrTampered`, `ErrUnsupportedVersion`, `ErrInvalidCiphertext`, `ErrInvalidPasswordHash`, `ErrUnknownFormat`, plus the existing CBC errors.
- **Runnable examples** in `examples/` covering encrypt-at-rest, webhook signing, password hashing, random tokens, AAD binding, application-wide Sealer, and CBC→GCM migration.
- **Long-form documentation**: `USAGE.md`, `SECURITY.md`, `MIGRATION.md`, `WIRE_FORMAT.md`.

### Deprecated

- `EncryptCBC` / `DecryptCBC` — AES-CBC has no message authentication. Use `Seal` / `Open` for new code. Retained for backward compatibility with existing data.
- `EncryptWithKey` / `DecryptWithKey` — wrap `EncryptCBC` / `DecryptCBC` with string types. Same Deprecated status.
- `Cipher`, `New`, `Cipher.Encrypt`, `Cipher.Decrypt` — v0.x type-based CBC API. Same Deprecated status.

### Changed

- The original `crypt.go` source file has been split into `aead.go`, `legacy_cbc.go`, `random.go`, `sign.go`, `password.go`, `errors.go`, `format.go`, `doc.go`. No public API behavior changed.

## [0.0.0] — initial scaffold (pre-release)

### Added

- Initial implementation extracted from `lace/crypt` in boilerplate-golang (AES-CBC only).
- Test suite under race detector with coverage targets met.
- Taskfile, CI workflows, README, NOTICE.
- Licensed under Apache License 2.0.

[Unreleased]: https://github.com/ubgo/crypt/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/ubgo/crypt/releases/tag/v0.0.0
