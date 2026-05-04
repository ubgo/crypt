# Security Model

This document describes what `github.com/ubgo/crypt` defends against, what it doesn't, and the design choices behind its security guarantees.

## Threat model

We assume an adversary who can:

- Read network traffic between services (i.e., is on the wire).
- Read or modify the database where ciphertexts are stored.
- Submit arbitrary inputs to the application.
- Make timing observations on responses.

We assume the adversary cannot:

- Read process memory of a running server (different threat — KMS would address it).
- Subvert the Go or Node standard library implementations of AES, HMAC, etc.
- Compromise the kernel-level CSPRNG (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows).

## Guarantees

### Confidentiality

Anything sealed with `Seal` (or `Sealer.Seal`) is computationally indistinguishable from random to anyone without the key. AES-256 in GCM mode provides 256-bit security against brute-force attack — well beyond any feasible attack budget.

### Authenticity

Anything sealed with `Seal` is bound to its key, nonce, and AAD via a 128-bit GCM authentication tag. Modifying any part of the ciphertext, key, or AAD before `Open` fails with `ErrTampered`. The tag has a 2^-128 false-positive rate for an attacker guessing tags blindly.

### Replay resistance via AAD

Binding ciphertext to a context (user ID, tenant ID, message type) using AAD prevents cross-context replay. A token issued for user A is not valid as user B if AAD is `"user:<id>"`. See [USAGE.md](./USAGE.md#binding-ciphertext-to-a-context-aad).

### Constant-time operations

- `Verify` (HMAC) uses `hmac.Equal` (constant-time).
- `ConstantTimeEqual` wraps `crypto/subtle.ConstantTimeCompare`.
- `VerifyPassword` uses `subtle.ConstantTimeCompare` after re-deriving the argon2 hash.

### Key length validation

- AEAD operations require exactly 32 bytes. Other lengths fail with `ErrInvalidKey` rather than silently downgrading.
- AES-CBC accepts 16/24/32 bytes (AES-128/192/256). Choose the size that matches the system you're interoperating with; AES-256 is the conservative default for new CBC use.

### Modern algorithms

- AEAD: AES-256-GCM (NIST SP 800-38D)
- Password: argon2id (RFC 9106, OWASP-recommended)
- MAC: HMAC-SHA256 (RFC 2104)
- Random: OS CSPRNG via `crypto/rand`

No deprecated algorithms ship in v1.0+:
- No MD5, no SHA-1
- No DES, no 3DES
- No ECB mode (ever)
- No raw RSA

## Non-guarantees

### Compromised process memory

If an attacker has read access to the process's memory, every key in memory is exposed. We do not zero buffers proactively; Go's GC will eventually reclaim them but the timing is non-deterministic.

If your threat model includes memory disclosure (e.g., Heartbleed-class vulnerabilities, side-channel attacks on shared infrastructure), use a Key Management Service (AWS KMS, GCP KMS, HashiCorp Vault) with envelope encryption. v2 will ship a KMS adapter; v1 does not.

### Side-channel attacks on AES

We rely on Go's `crypto/aes` implementation. On modern Intel and AMD CPUs (post-2010), AES-NI provides hardware-implemented constant-time AES. On older or non-x86 CPUs, Go falls back to a software AES implementation that is not constant-time and may be vulnerable to cache-timing attacks if an attacker shares the CPU.

For high-security deployments on shared infrastructure, ChaCha20-Poly1305 (planned in v1.1) is preferred. Its software implementation is naturally constant-time.

### Quantum cryptography

AES-256 is post-quantum-secure for confidentiality. Grover's algorithm halves the effective key length to 128 bits, which remains computationally infeasible.

We do not currently address post-quantum signatures. When Go std lib stabilizes ML-KEM and ML-DSA, we will add support.

### Operational concerns

The package does not protect against:

- Logging plaintext passwords
- Storing keys in environment variables that get printed
- Sharing keys via unencrypted channels (Slack, email)
- Reusing the same key across environments (dev/staging/prod)

These are operational disciplines outside the library's scope.

### Length leakage

Ciphertexts have a fixed overhead of 29 bytes plus the plaintext length. An attacker who sees a ciphertext can determine the plaintext's length within 1 byte. If your threat model requires hiding length (e.g., distinguishing "yes" from "no" answers), pad the plaintext to a fixed size before encryption.

## Security design choices

### Why no global mutable key

The v0.x package had a package-level `cipherKey` mutable via `LoadKey(string)`. This was removed in v1 because:

1. **Default key footgun.** If `LoadKey` was never called, encryption used a public alphabet `"abcdefghijklmnopqrstuvwxyz012345"`. Anyone reading the package source could decrypt production data.
2. **Race conditions.** `LoadKey` could be called concurrently with encryption, producing undefined behavior.
3. **Hostile to testing.** Tests had to monkey-patch the global, breaking when run in parallel.

In v1, `Sealer` requires a key in its constructor and validates immediately. There is no way to encrypt without an explicitly-supplied key.

### Why version-tag the wire format

Cryptographic agility: when an algorithm needs to be upgraded (a flaw is found in AES-GCM, a faster alternative arrives), we add a new version byte. Decoders explicitly enumerate which versions they accept. Old ciphertexts continue to work; new writes use the new algorithm.

The version byte costs 1 byte per ciphertext — cheap insurance.

### Why argon2id (not bcrypt)

| Concern | bcrypt | argon2id |
|---|---|---|
| Memory hardness | low | high |
| GPU resistance | weak | strong |
| Side-channel resistance | medium | strong (id variant) |
| 72-byte input limit | yes (silent truncation) | no |
| OWASP recommendation 2023+ | acceptable | preferred |

argon2id is the modern choice. bcrypt may be added in v1.1 as a compatibility option for migrating from bcrypt-using systems, but it is not a security recommendation.

### Why HMAC-SHA256 (not raw SHA-256)

Raw SHA-256 is vulnerable to length extension attacks: given `H(secret || message)`, an attacker can compute `H(secret || message || padding || extension)` without knowing the secret. HMAC structurally prevents this.

### Why hex (not base64) for legacy CBC

The v0.x package emitted hex output. We preserve this exactly to ensure backward compat. New code should use AEAD (base64url) — the choice between hex and base64 is purely aesthetic for new code.

### Why base64url-no-pad for AEAD

- URL-safe characters (`A-Z`, `a-z`, `0-9`, `-`, `_`) — no escaping in URLs or HTTP headers.
- No `=` padding — no special handling in URL parsers.
- Compact: 4 chars per 3 bytes vs hex's 2 chars per 1 byte.
- Decodes byte-identical via Go's `base64.RawURLEncoding` and Node's `Buffer.from(s, "base64url")`.

## Reporting a vulnerability

We use GitHub Private Security Advisories. To report a vulnerability:

1. Visit https://github.com/ubgo/crypt/security/advisories/new
2. Describe the issue, reproduction, impact.

We aim to:

- Acknowledge within 48 hours
- Assess severity within 7 days
- Ship a patch for P0 issues within 7 days of confirmed reproduction

Please do not file public GitHub issues for security vulnerabilities.

## Audit status

`crypt` v1.0 has not been independently audited. The implementation is small (under 1000 lines of code excluding tests and examples) and uses only Go standard library and `golang.org/x/crypto/argon2`. Both have been independently audited.

We welcome external review. If you have audit experience and find issues, please report via the security advisory process.

## References

- [NIST SP 800-38D — GCM specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 9106 — Argon2](https://datatracker.ietf.org/doc/rfc9106/)
- [RFC 2104 — HMAC](https://datatracker.ietf.org/doc/rfc2104/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Go crypto package documentation](https://pkg.go.dev/crypto)
