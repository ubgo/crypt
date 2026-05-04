# crypt

[![Go Reference](https://pkg.go.dev/badge/github.com/ubgo/crypt.svg)](https://pkg.go.dev/github.com/ubgo/crypt) [![CI](https://github.com/ubgo/crypt/actions/workflows/test.yml/badge.svg)](https://github.com/ubgo/crypt/actions) [![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> Authenticated encryption, password hashing, webhook signing, and secure random — wrapped around the Go standard library with safe defaults and byte-for-byte interop with the TypeScript counterpart at [`@ubgo/crypt`](https://github.com/ubgo/crypt-ts).

```go
import "github.com/ubgo/crypt"

key, _ := crypt.RandomBytes(crypt.AEADKeySize)
ct, _ := crypt.Seal(key, []byte("hello, world"), nil)
pt, _ := crypt.Open(key, ct, nil)
// pt == []byte("hello, world")
```

That's the whole API for the most common case. Need more? Read on.

---

## Is this for you?

`crypt` is built for Go applications that need a small set of cryptography primitives done well, with safe defaults, no foot-guns, and optionally a Node.js sibling that produces byte-identical output. **Reach for it when you're about to write any of the following:**

- I need to encrypt a database column at rest (API client secrets, PII, encryption keys, webhook secrets) and decrypt it back later.
- I need to sign outgoing webhooks with HMAC and verify incoming ones (Stripe, GitHub, etc. style).
- I need to hash user passwords correctly with modern parameters (argon2id) — and not get the PHC string wrong.
- I need to generate cryptographically-random API keys, magic-link tokens, CSRF tokens, session IDs.
- I need a stateless session token (a JWT-like pattern, smaller, no algorithm confusion).
- I need a Node.js service to decrypt data my Go service encrypted (or vice versa).
- I need to compare an API key in constant time, without leaking timing.
- I need to migrate AES-CBC ciphertext from a previous system to authenticated AES-GCM.

If any of those are on your plate, this is the package.

**Not for you if:** you need TLS, PKI, X.509, JWT/JOSE, certificate management, KMS adapters (v2), browser/WebCrypto, or post-quantum crypto. Use the std library or a specialized package for those.

---

## 30-second tour

### Encrypt a database column at rest

```go
sealer, _ := crypt.NewSealer(appKey) // 32 bytes from secrets manager

enc, _ := sealer.Seal([]byte(secret), nil)
db.Exec(`UPDATE partners SET client_secret = $1 WHERE id = $2`, enc, id)

plain, _ := sealer.Open(row.ClientSecret, nil)
```

### Bind a token to a user (so it can't be replayed for another)

```go
ct, _ := sealer.Seal(payload, []byte("user:"+userID))

pt, err := sealer.Open(ct, []byte("user:"+userID))
// err == ErrTampered if userID differs from issue time
```

### Sign and verify a webhook

```go
mac := crypt.Sign(secret, body)              // signer
ok := crypt.Verify(secret, body, mac)        // verifier (constant-time)
```

### Hash and verify a password

```go
hash, _ := crypt.HashPassword(plaintext)
ok, _   := crypt.VerifyPassword(plaintext, hash)
```

### Generate an API token

```go
token, _ := crypt.RandomToken(32) // 43-char URL-safe string
```

### Cross-language: Go encrypts, Node decrypts

```go
// Go side
ct, _ := crypt.Seal(sharedKey, payload, nil)
return ct
```

```ts
// Node side, using @ubgo/crypt
import { open } from "@ubgo/crypt"
const plaintext = open(sharedKey, ct)
```

Same wire format, byte-for-byte. Verified by shared test vectors in CI.

---

## Why this exists

Every Go service ends up reinventing the same five wrappers around `crypto/aes`, `crypto/hmac`, `crypto/rand`, `crypto/subtle`, and `golang.org/x/crypto/argon2`. Each reinvention gets some part wrong:

- AES-CBC instead of GCM (no authentication).
- A "default" key string committed to source.
- `bytes.Equal` for HMAC verification (timing leak).
- Argon2 with hand-tuned parameters that drift from OWASP recommendations.
- A wire format that the Node sibling decodes wrong for any plaintext > 16 bytes.

The last one is not theoretical: a hand-rolled wrapper in a Node.js codebase shipped silent corruption for any plaintext over 16 bytes before this package existed. `crypt` is one wrapper covering both languages, with shared test vectors enforcing wire-format parity in CI so divergence is caught at PR review rather than in production.

---

## What's included

**Authenticated encryption (AES-256-GCM)** — `Seal`, `Open`, `Sealer`. Modern AEAD with a versioned wire format so future algorithms slot in without breaking decrypt of old data.

**Password hashing (argon2id)** — `HashPassword`, `VerifyPassword`. OWASP-recommended parameters; PHC string output so future re-tunes are backward-compatible.

**HMAC signing** — `Sign`, `Verify`. Constant-time verification.

**Secure random** — `RandomBytes`, `RandomToken` (URL-safe base64), `RandomHex`. OS CSPRNG.

**Constant-time compare** — `ConstantTimeEqual`. Wraps `crypto/subtle`.

**Legacy AES-CBC support** — `EncryptCBC`, `DecryptCBC`, plus a `legacy.OpenAuto` migration helper that detects format and dispatches. For reading existing v0.x data only — new code uses AEAD.

**Cross-language wire format** — every AEAD and HMAC output is byte-identical to the TypeScript counterpart, validated by `testdata/vectors.json` consumed by both repos' tests.

For the full feature catalog with use cases, see [`FEATURES.md`](https://github.com/ubgo/crypt/blob/main/FEATURES.md).

---

## API at a glance

```go
// AEAD
func Seal(key, plaintext, aad []byte) (string, error)
func Open(key []byte, ciphertext string, aad []byte) ([]byte, error)

type Sealer struct { /* ... */ }
func NewSealer(key []byte) (*Sealer, error)
func (s *Sealer) Seal(plaintext, aad []byte) (string, error)
func (s *Sealer) Open(ciphertext string, aad []byte) ([]byte, error)

// Random
func RandomBytes(n int) ([]byte, error)
func RandomToken(n int) (string, error)   // URL-safe base64-no-pad
func RandomHex(n int) (string, error)

// Signing
func Sign(key, data []byte) []byte
func Verify(key, data, mac []byte) bool
func ConstantTimeEqual(a, b []byte) bool

// Password
func HashPassword(plaintext string) (string, error)
func VerifyPassword(plaintext, hash string) (bool, error)

// Legacy CBC (Deprecated — for migration only)
func EncryptCBC(key []byte, plaintext []byte) (string, error)
func DecryptCBC(key []byte, ciphertext string) ([]byte, error)
import "github.com/ubgo/crypt/legacy"
func legacy.OpenAuto(key []byte, ciphertext string, aad []byte) ([]byte, error)
```

Full reference at [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/crypt).

---

## Documentation

- **[USAGE.md](./USAGE.md)** — long-form guide, every common pattern explained
- **[RECIPES.md](./RECIPES.md)** — short copy-pasteable snippets, organized by task
- **[examples/](./examples)** — 17 runnable end-to-end programs (sessions, magic links, CSRF, audit logs, encrypted files, key rotation, multi-tenant, ...)
- **[SECURITY.md](./SECURITY.md)** — threat model, what's defended, what isn't
- **[WIRE_FORMAT.md](./WIRE_FORMAT.md)** — byte-by-byte ciphertext spec for cross-language interop
- **[MIGRATION.md](./MIGRATION.md)** — moving from v0.x AES-CBC to v1 AES-GCM
- **[BENCHMARKS.md](./BENCHMARKS.md)** — real numbers and what they mean
- **[FAQ.md](./FAQ.md)** — answers to questions you'll have
- **[CHANGELOG.md](./CHANGELOG.md)**

---

## TypeScript counterpart

[`@ubgo/crypt`](https://github.com/ubgo/crypt-ts) — same API surface (minus password hashing — server-side only), same wire format, byte-for-byte interoperable.

```ts
import { seal, open } from "@ubgo/crypt"
const ct = seal(sharedKey, "hello")
const pt = open(sharedKey, ct).toString("utf8") // identical to Go
```

---

## Install

```sh
go get github.com/ubgo/crypt
```

Requires Go 1.25 or later.

---

## Status

- **v1.0.0** — frozen API. AEAD, random, sign, password, legacy CBC, migration helper.
- **v1.1+** — additive features per [`FEATURES.md`](https://github.com/ubgo/crypt/blob/main/FEATURES.md): HKDF helper, multi-key `KeyRing` for rotation, ChaCha20-Poly1305 for non-AES-NI hardware. No breaking changes.
- **v2.0** — KMS adapter interface, asymmetric primitives (X25519, Ed25519). Roadmap.

## Reporting vulnerabilities

Open a private security advisory: https://github.com/ubgo/crypt/security/advisories/new

We aim to acknowledge within 48 hours and patch P0 issues within 7 days.

## License

[Apache License 2.0](./LICENSE)
