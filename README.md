# crypt

[![Go Reference](https://pkg.go.dev/badge/github.com/ubgo/crypt.svg)](https://pkg.go.dev/github.com/ubgo/crypt) [![Go Report Card](https://goreportcard.com/badge/github.com/ubgo/crypt)](https://goreportcard.com/report/github.com/ubgo/crypt) [![test](https://github.com/ubgo/crypt/actions/workflows/test.yml/badge.svg)](https://github.com/ubgo/crypt/actions/workflows/test.yml) [![lint](https://github.com/ubgo/crypt/actions/workflows/lint.yml/badge.svg)](https://github.com/ubgo/crypt/actions/workflows/lint.yml) ![coverage](https://img.shields.io/badge/coverage-95%25-brightgreen) [![tag](https://img.shields.io/github/v/tag/ubgo/crypt?sort=semver)](https://github.com/ubgo/crypt/tags) [![license](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE) ![Go](https://img.shields.io/badge/go-1.25-00ADD8?logo=go)

> Authenticated encryption, password hashing, webhook signing, and secure random — wrapped around the Go standard library with safe defaults and byte-for-byte interop with the TypeScript counterpart [`crypt-ts`](https://github.com/ubgo/crypt-ts).

**crypt** is a batteries-included **Go cryptography library**: AES-256-GCM and ChaCha20-Poly1305 authenticated encryption (AEAD), argon2id and bcrypt password hashing, HMAC and Ed25519 signing, HKDF key derivation, graceful key rotation, KMS envelope encryption, streaming file encryption, and a CSPRNG-backed secure-random toolkit — all with safe defaults, a versioned wire format, and byte-for-byte interoperability with Node.js via `crypt-ts`.

```go
import "github.com/ubgo/crypt"

key, _ := crypt.RandomBytes(crypt.AEADKeySize)
ct, _ := crypt.Seal(key, []byte("hello, world"), nil)
pt, _ := crypt.Open(key, ct, nil)
// pt == []byte("hello, world")
```

That's the whole API for the most common case. Need more? Read on.

## Contents

- [Is this for you?](#is-this-for-you)
- [30-second tour](#30-second-tour)
- [Why crypt?](#why-crypt)
- [What's included](#whats-included)
- [API at a glance](#api-at-a-glance)
- [Binding & rotating keys — design notes](#binding--rotating-keys--design-notes)
- [FAQ](#faq)
- [Documentation](#documentation)
- [TypeScript counterpart](#typescript-counterpart)
- [Install](#install)
- [Status](#status)
- [Reporting vulnerabilities](#reporting-vulnerabilities)
- [License](#license)

## Is this for you?

`crypt` is built for Go applications that need a curated set of cryptography primitives done well, with safe defaults, no foot-guns, and optionally a Node.js sibling that produces byte-identical output. **Reach for it when you're about to write any of the following:**

- Encrypt a database column at rest (API client secrets, PII, encryption keys, webhook secrets) and decrypt it back later.
- Sign outgoing webhooks with HMAC (or Ed25519 public-key) and verify incoming ones — Stripe-style with timestamp tolerance, etc.
- Hash user passwords correctly with modern parameters (argon2id, or bcrypt for compatibility).
- Generate cryptographically-random API keys, magic-link tokens, CSRF tokens, session IDs.
- Issue stateless time-locked tokens (password reset, email verify, magic login) with embedded expiry.
- Decrypt in Node.js what a Go service encrypted (or vice versa) — same wire format on both sides.
- Compare an API key in constant time without leaking timing.
- Interoperate with an existing AES-CBC system, or read ciphertext you already wrote in CBC.
- Encrypt large files in chunks (`SealStream` / `OpenStream`) with per-chunk authentication and truncation detection.
- Derive per-tenant or per-purpose sub-keys from a single master with HKDF.
- Rotate keys gracefully — `KeyRing` with embedded kid; old data still readable, new writes use the active key.
- Use ChaCha20-Poly1305 instead of AES-GCM (no AES-NI hardware, or defense-in-depth diversity).
- Encrypt to a recipient's public key — X25519 + ChaCha20-Poly1305 (sealed-box), age-style.
- Sign with Ed25519 — public-key signatures where verifiers don't share the signing key.
- Envelope encryption with a KMS — per-row DEK wrapped under a KMS-managed KEK.

If any of those are on your plate, this is the package.

**Not for you if:** you need TLS, PKI, X.509, JWT/JOSE, certificate management, browser/WebCrypto, or post-quantum crypto. Use the std library or a specialized package for those.

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

## Why crypt?

Every Go service ends up reinventing the same five wrappers around `crypto/aes`, `crypto/hmac`, `crypto/rand`, `crypto/subtle`, and `golang.org/x/crypto/argon2`. Each reinvention gets some part wrong:

- AES-CBC instead of GCM (no authentication).
- A "default" key string committed to source.
- `bytes.Equal` for HMAC verification (timing leak).
- Argon2 with hand-tuned parameters that drift from OWASP recommendations.
- A wire format that the Node sibling decodes wrong for any plaintext > 16 bytes.

The last one is not theoretical: a hand-rolled wrapper in a Node.js codebase shipped silent corruption for any plaintext over 16 bytes before this package existed. `crypt` is one wrapper covering both languages, with shared test vectors enforcing wire-format parity in CI so divergence is caught at PR review rather than in production.

| | **crypt** | Go stdlib (DIY) | Hand-rolled wrappers |
|---|---|---|---|
| Authenticated encryption by default | ✅ AEAD out of the box | ⚠️ you must choose GCM and wire the nonce | ⚠️ often CBC without a MAC |
| Versioned wire format (future algos, safe upgrades) | ✅ | ❌ | ❌ |
| Cross-language (Go ↔ Node) byte parity | ✅ shared vectors in CI | ❌ | ⚠️ hand-matched, drifts |
| Key rotation with a grace window | ✅ `KeyRing` | ❌ | ❌ |
| Envelope encryption / KMS | ✅ `EnvelopeSealer` | ❌ | ⚠️ |
| Password hashing (argon2id + bcrypt) | ✅ OWASP params, PHC output | ⚠️ tune it yourself | ⚠️ |
| Constant-time compare wired in | ✅ | ⚠️ easy to forget `subtle` | ❌ |
| Third-party dependencies | ✅ stdlib + `x/crypto` only | ✅ | ⚠️ varies |

If you want to assemble the primitives yourself, the standard library is right there and it's excellent. If you want the *correct assembly* — authenticated, versioned, rotatable, and readable from Node — that's `crypt`.

## What's included

**Authenticated encryption (AES-256-GCM)** — `Seal`, `Open`, `Sealer`. Modern AEAD with a versioned wire format so future algorithms slot in without breaking decrypt of old data.

**Password hashing (argon2id)** — `HashPassword`, `VerifyPassword`. OWASP-recommended parameters; PHC string output so future re-tunes are backward-compatible.

**HMAC signing** — `Sign`, `Verify`. Constant-time verification.

**Secure random** — `RandomBytes`, `RandomToken` (URL-safe base64), `RandomHex`. OS CSPRNG.

**Constant-time compare** — `ConstantTimeEqual`. Wraps `crypto/subtle`.

**AES-CBC** — `EncryptCBC`, `DecryptCBC` (16/24/32-byte keys for AES-128/192/256). First-class peer of AES-GCM — use it when interop with an existing AES-CBC system is required (PHP/Java/Python), or when reading ciphertext your application already wrote in this format. CBC has no built-in authentication; layer HMAC on top (encrypt-then-MAC) or use `Seal/Open` if you need tamper detection. A `crypt.OpenAuto` helper auto-detects AEAD vs CBC for migration scripts.

**Cross-language wire format** — every AEAD and HMAC output is byte-identical to the TypeScript counterpart, validated by `testdata/vectors.json` consumed by both repos' tests.

For the full feature catalog with use cases, see the [long-form guide](./USAGE.md) and the [27 runnable examples](./examples).

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

// AES-CBC (16/24/32-byte keys; no built-in auth — pair with HMAC if needed)
func EncryptCBC(key []byte, plaintext []byte) (string, error)
func DecryptCBC(key []byte, ciphertext string) ([]byte, error)
func OpenAuto(key []byte, ciphertext string, aad []byte) ([]byte, error)

// ChaCha20-Poly1305 (alternative AEAD; wire version 0x02)
func SealChaCha20(key, plaintext, aad []byte) (string, error)
func OpenChaCha20(key []byte, ciphertext string, aad []byte) ([]byte, error)

// Bcrypt password hashing (compatibility with bcrypt-using systems)
func HashPasswordBcrypt(plaintext string, cost int) (string, error)
func VerifyPasswordBcrypt(plaintext, hash string) (bool, error)

// HKDF key derivation
func DeriveKey(masterKey, salt, info []byte, length int) ([]byte, error)

// KeyRing for rotation (wire version 0x03 with embedded kid)
type KeyRing struct { /* ... */ }
func NewKeyRing(activeKid string, activeKey []byte) (*KeyRing, error)
func (r *KeyRing) Add(kid string, key []byte) error
func (r *KeyRing) Remove(kid string) error
func (r *KeyRing) SetActive(kid string) error
func (r *KeyRing) ActiveKid() string
func (r *KeyRing) Seal(plaintext, aad []byte) (string, error)
func (r *KeyRing) Open(ciphertext string, aad []byte) ([]byte, error)

// Time-locked tokens (embedded expiry; ErrExpired sentinel)
func IssueToken(key, payload []byte, ttl time.Duration, aad []byte) (string, error)
func VerifyToken(key []byte, token string, aad []byte) ([]byte, error)

// Streaming AEAD (chunked file encryption with truncation detection)
func SealStream(key []byte, r io.Reader, w io.Writer, chunkSize int) error
func OpenStream(key []byte, r io.Reader, w io.Writer) error

// Ed25519 public-key signatures
func GenerateEd25519() (publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, err error)
func SignEd25519(priv ed25519.PrivateKey, data []byte) ([]byte, error)
func VerifyEd25519(pub ed25519.PublicKey, data, sig []byte) (bool, error)

// X25519 + ChaCha20-Poly1305 sealed-box (asymmetric encrypt; wire version 0x05)
func GenerateKeyPair() (publicKey, privateKey []byte, err error)
func SealAsymmetric(recipientPublicKey, plaintext []byte) (string, error)
func OpenAsymmetric(recipientPrivateKey []byte, ciphertext string) ([]byte, error)

// Envelope encryption (KMS-wrapped DEK; wire version 0x06)
type KMS interface { /* ... */ }
type StaticKMS struct { /* ... */ }       // in-memory adapter for tests/dev
func NewStaticKMS() *StaticKMS
type EnvelopeSealer struct { /* ... */ }
func NewEnvelopeSealer(kms KMS, keyID string) *EnvelopeSealer
```

Full reference at [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/crypt).

## Binding & rotating keys — design notes

A few questions come up often enough to answer here, since the choices are deliberate.

**"Can I set one global encrypt key instead of passing it everywhere?"** Use a `Sealer`, not a global. `NewSealer(key)` binds the key once at startup; downstream code then calls `sealer.Seal(pt, aad)` / `sealer.Open(ct, aad)` with no key argument. That gives you the "set once, call bare" ergonomics without a package-level default. There is intentionally no `SetDefaultKey` / `SealDefault`: a global would be hidden mutable state — hard to test (parallel tests share it), impossible to run two keys at once, and a silent zero-key footgun if used before it's set. Prefer storing the `Sealer` on your app/DI struct over hand-rolling `encryptToken(key, ...)` wrapper functions.

**"Can a Sealer update its key on the fly?"** No — a `Sealer` is immutable by design and has no `Rekey` method. The key is bound at `NewSealer` and never changes, which is exactly what makes a `Sealer` safe to share across goroutines with no lock. A mutable key would force a mutex or atomic load on every `Seal`/`Open` to serve a swap that happens rarely, and a hard swap would instantly make all previously-sealed ciphertext undecryptable.

**"Then how do I rotate keys?"** Pick by need:

- **`KeyRing`** — restart-free rotation with a grace window. Writes use the active key; reads dispatch by the `kid` embedded in each ciphertext, so old data stays readable while it migrates. This is the right tool for compliance rotation and compromise response.
- **Swap the whole `Sealer`** at a safe boundary (e.g. config reload) behind `atomic.Pointer[Sealer]`. Cheap and race-free, but single-key only — old ciphertext isn't readable after the swap unless you keep the old `Sealer` around. Note: reassigning a plain `*Sealer` variable while other goroutines are calling it is a data race; use `atomic.Pointer`.

## FAQ

**Is crypt safe to use in production?** It's a thin, auditable set of wrappers over Go's standard library and `golang.org/x/crypto` — no custom primitives — with authenticated encryption by default, ~95% test coverage, and a shared known-answer vector file that enforces cross-language wire-format parity in CI. Review the [threat model](./SECURITY.md) for exactly what is and isn't defended.

**Does crypt roll its own cryptography?** No. Encryption is `crypto/cipher` AES-GCM and `golang.org/x/crypto/chacha20poly1305`; hashing is `argon2` / `bcrypt`; signatures are `crypto/ed25519`; key agreement is `curve25519`. crypt only supplies safe defaults, a versioned wire format, and ergonomics — never a novel algorithm.

**Should I use AES-GCM or ChaCha20-Poly1305?** Default to AES-256-GCM (`Seal`/`Open`) — it's fastest on any CPU with AES-NI, which is nearly all server hardware. Reach for ChaCha20-Poly1305 (`SealChaCha20`) on hardware without AES-NI (some ARM/embedded) or when you want algorithm diversity for defense-in-depth. Both share the same versioned format.

**How do I rotate encryption keys without downtime?** Use `KeyRing`: new writes use the active key, and reads dispatch by the key id embedded in each ciphertext, so previously-encrypted data stays readable throughout the migration. See [Binding & rotating keys](#binding--rotating-keys--design-notes).

**Can Node.js decrypt what a Go service encrypted?** Yes. The [`crypt-ts`](https://github.com/ubgo/crypt-ts) package produces and consumes the exact same bytes; both repos run against the same `testdata/vectors.json` so any divergence fails CI.

**How is this different from just using `crypto/aes` myself?** The standard library gives you the primitives; crypt gives you the correct assembly — authentication wired in, a versioned nonce/header layout, constant-time verification, KDFs with vetted parameters, key rotation, and Node interoperability — so the parts you'd otherwise get subtly wrong are already right.

**Does crypt support public-key (asymmetric) encryption?** Yes — `SealAsymmetric` / `OpenAsymmetric` implement an age-style X25519 + ChaCha20-Poly1305 sealed box, and `SignEd25519` / `VerifyEd25519` provide Ed25519 signatures for verifiers that don't hold the signing key.

**Is AES-CBC deprecated?** No — it's a first-class peer kept for interop with existing AES-CBC systems and for reading ciphertext you already wrote. It has no built-in authentication, so pair it with HMAC (encrypt-then-MAC) or use `Seal`/`Open` when you need tamper detection.

**What Go version does crypt need?** Go 1.25 or later; the only dependency is `golang.org/x/crypto`.

## Documentation

- **[USAGE.md](./USAGE.md)** — long-form guide, every common pattern explained
- **[RECIPES.md](./RECIPES.md)** — short copy-pasteable snippets, organized by task
- **[examples/](./examples)** — 27 runnable end-to-end programs (sessions, magic links, CSRF, audit logs, encrypted files, key rotation, multi-tenant, ...)
- **[SECURITY.md](./SECURITY.md)** — threat model, what's defended, what isn't
- **[WIRE_FORMAT.md](./WIRE_FORMAT.md)** — byte-by-byte ciphertext spec for cross-language interop
- **[MIGRATION.md](./MIGRATION.md)** — moving from the legacy string-typed AES-CBC wrappers to AES-GCM
- **[BENCHMARKS.md](./BENCHMARKS.md)** — real numbers and what they mean
- **[FAQ.md](./FAQ.md)** — answers to questions you'll have
- **[CHANGELOG.md](./CHANGELOG.md)**

## TypeScript counterpart

[`crypt-ts`](https://github.com/ubgo/crypt-ts) — same API surface (minus password hashing — server-side only), same wire format, byte-for-byte interoperable.

```ts
import { seal, open } from "@ubgo/crypt"
const ct = seal(sharedKey, "hello")
const pt = open(sharedKey, ct).toString("utf8") // identical to Go
```

## Install

```sh
go get github.com/ubgo/crypt
```

Requires Go 1.25 or later.

## Status

**Current release: `v0.2.0`.** The entire surface documented above is implemented, tested (~95% coverage), and covered by cross-language known-answer vectors: AEAD (AES-256-GCM and ChaCha20-Poly1305), argon2id/bcrypt password hashing, HMAC and Ed25519 signing, HKDF, `KeyRing` rotation, KMS envelope encryption, streaming AEAD, time-locked tokens, and secure random.

Pre-1.0, so: the **wire format is stable** and pinned by the shared vectors (ciphertext written today stays readable), but the Go API may still see small refinements before `v1.0.0`. Pin a version and check the [CHANGELOG](./CHANGELOG.md) before upgrading. See [`MIGRATION.md`](./MIGRATION.md) for moving off the legacy string-typed AES-CBC wrappers.

## Reporting vulnerabilities

Open a private security advisory: https://github.com/ubgo/crypt/security/advisories/new

We aim to acknowledge within 48 hours and patch P0 issues within 7 days.

## License

[Apache License 2.0](./LICENSE)

<sub>crypt — a Go cryptography library for authenticated encryption (AES-256-GCM, ChaCha20-Poly1305 / AEAD), password hashing (argon2id, bcrypt), HMAC and Ed25519 signing, HKDF key derivation, key rotation, KMS envelope encryption, streaming file encryption, and secure random tokens. Apache-2.0, standard-library-only, with a byte-for-byte TypeScript / Node.js counterpart (crypt-ts).</sub>
