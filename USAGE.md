# Usage Guide

Long-form recipes for `github.com/ubgo/crypt`. For each common task, the right function plus a copy-pasteable snippet.

For runnable end-to-end programs, see [`examples/`](./examples). For the full API reference, see [godoc](https://pkg.go.dev/github.com/ubgo/crypt).

## Table of contents

- [Authenticated encryption](#authenticated-encryption)
- [Application-wide Sealer](#application-wide-sealer)
- [Binding ciphertext to a context (AAD)](#binding-ciphertext-to-a-context-aad)
- [Random bytes, tokens, IDs](#random-bytes-tokens-ids)
- [HMAC signing and verification](#hmac-signing-and-verification)
- [Constant-time comparison](#constant-time-comparison)
- [Password hashing](#password-hashing)
- [Reading legacy AES-CBC data](#reading-legacy-aes-cbc-data)
- [Mixed-format reads with OpenAuto](#mixed-format-reads-with-openauto)
- [Cross-language interop with Node.js](#cross-language-interop-with-nodejs)
- [Testing patterns](#testing-patterns)

---

## Authenticated encryption

Use `Seal` and `Open` for AES-256-GCM authenticated encryption. The output is a base64url-no-pad string suitable for any DB column or HTTP header.

```go
key, _ := crypt.RandomBytes(crypt.AEADKeySize) // 32 bytes from CSPRNG

ciphertext, err := crypt.Seal(key, []byte("hello"), nil)
if err != nil {
    return err
}

plaintext, err := crypt.Open(key, ciphertext, nil)
if err != nil {
    return err
}
```

### Key requirements

- **Exactly 32 bytes.** Other lengths return `ErrInvalidKey`.
- **Sourced from a CSPRNG.** Use `crypt.RandomBytes(crypt.AEADKeySize)` or load from secure config.
- **Same key for Seal and Open.** Different keys → `ErrTampered`.

### Output size

```
ciphertext bytes = 1 (version) + 12 (nonce) + N (plaintext) + 16 (tag)
                = N + 29 bytes (binary)
                ≈ N * 4/3 + 39 chars (after base64url encoding)
```

For an empty plaintext, the ciphertext is 29 bytes / 39 base64url chars. For a 100-byte plaintext, ~172 chars.

---

## Application-wide Sealer

For a service that encrypts repeatedly with the same key, construct one `Sealer` at boot and inject it.

```go
type Plugin struct {
    Sealer *crypt.Sealer
    DB     *ent.Client
}

func New(cfg *Config) (*Plugin, error) {
    sealer, err := crypt.NewSealer(cfg.EncryptionKey)
    if err != nil {
        return nil, fmt.Errorf("init sealer: %w", err)
    }
    return &Plugin{
        Sealer: sealer,
        DB:     openDB(cfg),
    }, nil
}
```

Why a `Sealer` over the package-level `Seal`/`Open`:

- **One key validation, not N.** `NewSealer` validates the key length once at boot.
- **One AEAD construction, not N.** Reuses `cipher.AEAD` across calls.
- **Concurrent-safe.** Share across goroutines without locks.
- **Testable.** Inject a sealer with a fixed test key in unit tests.

The package-level functions are convenient for one-shot calls (CLIs, scripts, tests). Use a Sealer in long-running services.

---

## Binding ciphertext to a context (AAD)

AAD (additional authenticated data) lets you bind a ciphertext to a specific context without encrypting the context itself.

```go
// Issue a session token bound to user ID.
token, _ := sealer.Seal([]byte(payload), []byte("user:"+userID))

// At decrypt time, the same userID must be supplied.
pt, err := sealer.Open(token, []byte("user:"+userID))
// err == ErrTampered if userID differs from issue-time
```

### Common AAD shapes

| Pattern | AAD value |
|---|---|
| Per-user data | `[]byte("user:" + userID)` |
| Per-tenant data | `[]byte("tenant:" + tenantID)` |
| Per-row encryption | `[]byte(tableName + ":" + primaryKey)` |
| Per-version data | `[]byte("v=1")` (helps detect format upgrades) |

### What AAD protects

- **Token replay across contexts.** A token issued for user A is not valid as user B.
- **Cross-table replay.** A `users.token` value pasted into `partners.token` won't decrypt with the partner's AAD.
- **Format confusion.** AAD `"v=1"` distinguishes version-1 ciphertexts from future v2 with different semantics.

### What AAD does NOT protect

- **Replay against the same user.** Use a one-time nonce or timestamp inside the plaintext.
- **Token leakage via logs.** Operational concern, separate from AEAD.

---

## Random bytes, tokens, IDs

```go
keyBytes, _   := crypt.RandomBytes(32)       // raw bytes for AEAD/HMAC keys
apiKey,    _   := crypt.RandomToken(32)       // 43 chars, URL-safe base64
shortToken, _  := crypt.RandomToken(16)       // 22 chars, for short-lived tokens
logCorrID, _   := crypt.RandomHex(8)          // 16 chars, hex
```

| Need | Use | Output length |
|---|---|---|
| AEAD key | `RandomBytes(32)` | 32 bytes |
| HMAC key | `RandomBytes(32)` | 32 bytes |
| Long-lived API key | `RandomToken(32)` | 43 chars |
| Short-lived (≤24h) token | `RandomToken(16)` | 22 chars |
| CSRF token | `RandomToken(24)` | 32 chars |
| Log correlation ID | `RandomHex(8)` | 16 chars |
| Filename / path-safe ID | `RandomHex(16)` | 32 chars |

All helpers source from `crypto/rand`. Never use `math/rand` for any cryptographic purpose — it's pseudo-random and predictable.

### Token storage pattern

```go
// At issue time:
plain, _ := crypt.RandomToken(32)
showOnce(plain)
hash := sha256.Sum256([]byte(plain))
db.SaveAPIKey(user.ID, hex.EncodeToString(hash[:]))

// At verify time:
provided := c.GetHeader("X-API-Key")
hash := sha256.Sum256([]byte(provided))
if !crypt.ConstantTimeEqual(hash[:], db.LoadAPIKeyHash(...)) {
    c.AbortWithStatus(401)
    return
}
```

A SHA-256 hash is sufficient here because the input is high-entropy random. For passwords (low-entropy), use `HashPassword` (argon2id) instead.

---

## HMAC signing and verification

For symmetric authentication where signer and verifier share a secret.

```go
secret := []byte("partner-webhook-secret")

// Signer
mac := crypt.Sign(secret, body)

// Verifier
if !crypt.Verify(secret, body, mac) {
    return errInvalidSignature
}
```

### Webhook outgoing

```go
func (h *Handler) sendWebhook(ctx context.Context, p *PartnerApp, e Event) error {
    body, err := json.Marshal(e)
    if err != nil {
        return err
    }
    mac := crypt.Sign(p.WebhookSecret, body)

    req, _ := http.NewRequestWithContext(ctx, "POST", p.WebhookURL, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(mac))
    req.Header.Set("X-Signature-Algorithm", "hmac-sha256")

    resp, err := h.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}
```

### Webhook incoming (Gin middleware)

```go
func WebhookVerify(secret []byte) gin.HandlerFunc {
    return func(c *gin.Context) {
        body, err := io.ReadAll(c.Request.Body)
        if err != nil {
            c.AbortWithStatusJSON(400, gin.H{"error": "read body"})
            return
        }
        c.Request.Body = io.NopCloser(bytes.NewReader(body))

        sig := c.GetHeader("X-Signature")
        mac, err := base64.StdEncoding.DecodeString(sig)
        if err != nil || !crypt.Verify(secret, body, mac) {
            c.AbortWithStatusJSON(401, gin.H{"error": "invalid signature"})
            return
        }
        c.Next()
    }
}
```

### Why share the body

The MAC is computed over the *exact bytes* the verifier will see. If you re-marshal between signing and sending, the MAC may not match (whitespace, key order can differ). Always sign the bytes you actually transmit.

---

## Constant-time comparison

Always use for any comparison involving secret material.

```go
provided := c.GetHeader("X-Internal-Key")
if !crypt.ConstantTimeEqual([]byte(provided), []byte(internalKey)) {
    c.AbortWithStatus(401)
    return
}
```

Naive `==` short-circuits at the first differing byte. An attacker measuring response time can recover the secret one byte at a time.

The function reports false in constant time when inputs are equal-length-but-different. Length difference itself isn't constant-time (it can't be), but in nearly all practical applications inputs already have a known fixed length (32-byte HMAC tag, 36-char UUID, etc.).

---

## Password hashing

For storing user-supplied passwords. Use `HashPassword` on registration, `VerifyPassword` on login.

```go
// Registration
hash, err := crypt.HashPassword(password)
if err != nil {
    return err
}
db.User.Create().SetEmail(email).SetPasswordHash(hash).Save(ctx)

// Login
user, _ := db.User.Query().Where(user.Email(email)).Only(ctx)
ok, err := crypt.VerifyPassword(password, user.PasswordHash)
if err != nil || !ok {
    return errInvalidCredentials
}
```

### Output format

The stored string is OWASP-recommended PHC format:

```
$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
```

Parameters are encoded in the string itself. You can re-tune memory or time costs in future without breaking existing hashes — `VerifyPassword` reads parameters from the stored value.

### Performance

Argon2id is **intentionally slow** (~10–100 ms per hash on a typical server). This is the entire point: it makes brute-force attacks expensive. Don't be tempted to lower the parameters below OWASP recommendations.

For high-throughput systems where login latency matters, consider:
- Caching successful auth in a session token (encrypted with `Seal`) so repeat requests don't re-hash.
- Rate-limiting login endpoints (e.g., 10 attempts per IP per minute).

### When NOT to hash

If you need to retrieve the original value later (API keys you display once, encrypted credentials), use `Seal`/`Open` instead. Hashing is one-way.

---

## Reading legacy AES-CBC data

If you have data already encrypted with `EncryptCBC` (or the deprecated `EncryptWithKey` from v0.x), decrypt with `DecryptCBC`:

```go
plaintext, err := crypt.DecryptCBC(key, ciphertext)
if err != nil {
    return err
}
```

CBC has no message authentication. A tampered ciphertext that produces invalid PKCS7 padding returns `ErrInvalidPadding`, but a tamper landing on valid padding returns silent garbage plaintext. **Don't write new code with CBC.** Only use it to read existing data.

See [MIGRATION.md](./MIGRATION.md) for the full migration playbook.

---

## Mixed-format reads with OpenAuto

During a migration window when some rows are AEAD and others are still CBC:

```go
import "github.com/ubgo/crypt/legacy"

plain, err := legacy.OpenAuto(key, row.Ciphertext, nil)
```

`OpenAuto` detects the format (base64url+0x01 → AEAD; hex → CBC) and dispatches.

Treat any `import "github.com/ubgo/crypt/legacy"` line as a smell. Production reads should call `crypt.Open` directly. The `legacy` subpackage exists to make migration tooling easy to grep for and clean up post-migration.

---

## Cross-language interop with Node.js

The TypeScript package [`@ubgo/crypt`](https://github.com/ubgo/crypt-ts) produces byte-for-byte identical AEAD ciphertexts. Common patterns:

### Go signs, Node verifies

```go
// Go service issues a session token
token, _ := sealer.Seal([]byte(payload), []byte("user:"+userID))
return token
```

```ts
// Node service receives and verifies
import { open } from "@ubgo/crypt"
const plaintext = open(sharedKey, token, Buffer.from("user:" + userID))
const session = JSON.parse(plaintext.toString("utf8"))
```

### Node signs, Go verifies

```ts
import { sign } from "@ubgo/crypt"
const mac = sign(serviceKey, body)
fetch(goAPI, { headers: { "X-Sig": mac.toString("hex") }, body })
```

```go
sigHex := c.GetHeader("X-Sig")
sig, _ := hex.DecodeString(sigHex)
if !crypt.Verify(serviceKey, body, sig) {
    c.AbortWithStatus(401)
    return
}
```

### What's parity-tested

- AEAD `Seal`/`Open` (round-trip and wire bytes)
- HMAC `Sign`/`Verify`
- Legacy CBC `EncryptCBC`/`DecryptCBC`

Both repos consume the same [`testdata/vectors.json`](./testdata/vectors.json). Any change to one side that breaks parity fails CI on both.

---

## Testing patterns

### Inject a Sealer with a fixed test key

```go
func TestService_Encrypt(t *testing.T) {
    testKey := bytes.Repeat([]byte{0x01}, crypt.AEADKeySize)
    sealer, err := crypt.NewSealer(testKey)
    require.NoError(t, err)

    svc := NewService(sealer)
    ct, err := svc.Encrypt("test data")
    require.NoError(t, err)

    pt, err := svc.Decrypt(ct)
    require.NoError(t, err)
    require.Equal(t, "test data", pt)
}
```

### Skip slow tests in CI fast lane

argon2id tests are intentionally slow. If you have a fast-lane test runner:

```go
func TestPasswordHash(t *testing.T) {
    if testing.Short() {
        t.Skip("argon2id is slow; skipped under -short")
    }
    // ...
}
```

Then run `go test -short ./...` for the fast lane and `go test ./...` for the full suite.

### Don't mock crypt

The package has no I/O — every call is pure CPU. Just call it directly in tests. Mocking introduces drift between the mock and the real behavior; nothing about `Seal` or `Sign` is slow enough to need mocking.
