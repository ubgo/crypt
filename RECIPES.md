# Recipes

Short, copy-pasteable patterns for common tasks. For end-to-end runnable demos see [`examples/`](./examples). For the full guide see [`USAGE.md`](./USAGE.md).

## Index

- [Encrypting and decrypting](#encrypting-and-decrypting)
- [Key management](#key-management)
- [Tokens and signing](#tokens-and-signing)
- [Authentication patterns](#authentication-patterns)
- [Sessions and cookies](#sessions-and-cookies)
- [Webhooks](#webhooks)
- [Files and blobs](#files-and-blobs)
- [Multi-tenancy](#multi-tenancy)
- [Migrating legacy data](#migrating-legacy-data)
- [Operational patterns](#operational-patterns)

---

## Encrypting and decrypting

### Encrypt a string

```go
key, _ := crypt.RandomBytes(crypt.AEADKeySize)
ct, _ := crypt.Seal(key, []byte("hello"), nil)
pt, _ := crypt.Open(key, ct, nil)
```

### Encrypt a struct (JSON-serialize first)

```go
data, _ := json.Marshal(myStruct)
ct, _ := sealer.Seal(data, nil)
// ...
pt, _ := sealer.Open(ct, nil)
var got MyStruct
_ = json.Unmarshal(pt, &got)
```

### Encrypt with context binding

```go
// Seal binds to user ID — token cannot be replayed for another user.
ct, _ := sealer.Seal(payload, []byte("user:"+userID))
pt, err := sealer.Open(ct, []byte("user:"+userID))
// err == ErrTampered if userID differs from issue time
```

### Encrypt a database column

```go
// Save
enc, _ := sealer.Seal([]byte(value), nil)
db.Exec(`UPDATE users SET secret_field = $1 WHERE id = $2`, enc, userID)

// Load
var enc string
db.QueryRow(`SELECT secret_field FROM users WHERE id = $1`, userID).Scan(&enc)
plain, _ := sealer.Open(enc, nil)
```

### Use a Sealer for repeated ops (recommended)

```go
sealer, err := crypt.NewSealer(appKey) // validate once at boot
if err != nil {
    return fmt.Errorf("init sealer: %w", err)
}
// Reuse `sealer` for every Seal/Open — concurrent-safe.
```

---

## Key management

### Load a key from environment safely

```go
keyHex := os.Getenv("APP_ENCRYPTION_KEY")
if keyHex == "" {
    log.Fatal("APP_ENCRYPTION_KEY required")
}
key, err := hex.DecodeString(keyHex)
if err != nil || len(key) != crypt.AEADKeySize {
    log.Fatal("APP_ENCRYPTION_KEY must be 64 hex chars (32 bytes)")
}
sealer, _ := crypt.NewSealer(key)
// Avoid logging keyHex — set up a redaction filter in your logger.
```

### Generate a fresh key

```sh
# 32 random bytes, hex-encoded — paste into your secrets manager.
go run -v -ldflags='-w' - <<'EOF'
package main
import ("crypto/rand"; "encoding/hex"; "fmt")
func main() { b := make([]byte, 32); rand.Read(b); fmt.Println(hex.EncodeToString(b)) }
EOF
```

### Derive per-tenant key from a master

```go
// Requires golang.org/x/crypto/hkdf
import "golang.org/x/crypto/hkdf"

h := hkdf.New(sha256.New, masterKey, nil, []byte("tenant:"+tenantID))
tenantKey := make([]byte, crypt.AEADKeySize)
io.ReadFull(h, tenantKey)
sealer, _ := crypt.NewSealer(tenantKey)
```

### Rotate keys with a fallback reader

```go
type MultiKeyReader struct{ keys [][]byte }

func (m *MultiKeyReader) Open(ct string, aad []byte) ([]byte, error) {
    for _, k := range m.keys {
        if pt, err := crypt.Open(k, ct, aad); err == nil {
            return pt, nil
        }
    }
    return nil, errors.New("no key opens this ciphertext")
}

// Active key first; older keys after.
reader := &MultiKeyReader{keys: [][]byte{newKey, oldKey}}
```

See [`examples/key_rotation`](./examples/key_rotation) for a full demo.

---

## Tokens and signing

### Generate an API key

```go
token, _ := crypt.RandomToken(32)
// Show to user once — store hash for verification.
hash := sha256.Sum256([]byte(token))
db.Exec(`INSERT INTO api_keys(user_id, hash) VALUES($1, $2)`, userID, hex.EncodeToString(hash[:]))
return token
```

### Verify an API key

```go
provided := r.Header.Get("Authorization")
provided = strings.TrimPrefix(provided, "Bearer ")
hash := sha256.Sum256([]byte(provided))
var stored string
err := db.QueryRow(`SELECT hash FROM api_keys WHERE hash = $1`, hex.EncodeToString(hash[:])).Scan(&stored)
if err != nil {
    return errInvalidKey
}
```

### Generate a magic-link token

```go
type linkPayload struct {
    UserID string `json:"u"`
    Exp    int64  `json:"e"`
}

func issueMagicLink(sealer *crypt.Sealer, userID string, ttl time.Duration) (string, error) {
    pt, _ := json.Marshal(linkPayload{UserID: userID, Exp: time.Now().Add(ttl).Unix()})
    return sealer.Seal(pt, []byte("magic-link-v1"))
}
```

### Sign URL parameters

```go
// /unsubscribe?u=usr_42&exp=1700000000&sig=<base64>
data := fmt.Sprintf("u=%s&exp=%d", userID, expiry.Unix())
mac := crypt.Sign(serverSecret, []byte(data))
url := fmt.Sprintf("/unsubscribe?%s&sig=%s", data, base64.URLEncoding.EncodeToString(mac))
```

---

## Authentication patterns

### Constant-time API key check

```go
if !crypt.ConstantTimeEqual([]byte(provided), expectedKey) {
    http.Error(w, "unauthorized", 401)
    return
}
```

### Hash a user password

```go
hash, _ := crypt.HashPassword(plaintext)
db.Exec(`UPDATE users SET password_hash = $1 WHERE id = $2`, hash, userID)
```

### Verify a user password

```go
ok, err := crypt.VerifyPassword(provided, user.PasswordHash)
if err != nil {
    return errMalformedHash // stored value got corrupted somehow
}
if !ok {
    return errInvalidCredentials
}
```

### Password change flow

```go
ok, _ := crypt.VerifyPassword(oldPassword, user.PasswordHash)
if !ok {
    return errCurrentPasswordWrong
}
newHash, _ := crypt.HashPassword(newPassword)
db.Exec(`UPDATE users SET password_hash = $1 WHERE id = $2`, newHash, user.ID)
```

---

## Sessions and cookies

### Stateless session token

```go
type Session struct {
    UserID string `json:"u"`
    Exp    int64  `json:"e"`
}

func issueSession(sealer *crypt.Sealer, userID string, ttl time.Duration) (string, error) {
    pt, _ := json.Marshal(Session{UserID: userID, Exp: time.Now().Add(ttl).Unix()})
    return sealer.Seal(pt, []byte("session-v1"))
}

func readSession(sealer *crypt.Sealer, token string) (*Session, error) {
    pt, err := sealer.Open(token, []byte("session-v1"))
    if err != nil { return nil, err }
    var s Session
    if err := json.Unmarshal(pt, &s); err != nil { return nil, err }
    if time.Now().Unix() >= s.Exp { return nil, errors.New("expired") }
    return &s, nil
}
```

See [`examples/session_token`](./examples/session_token).

### Encrypted session cookie

```go
http.SetCookie(w, &http.Cookie{
    Name:     "_session",
    Value:    sealedSessionValue,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
    Path:     "/",
    Expires:  time.Now().Add(ttl),
})
```

See [`examples/encrypted_cookie`](./examples/encrypted_cookie).

### CSRF token (double-submit)

```go
// On render: generate + set cookie + embed in form
csrf, _ := sealer.Seal([]byte(sessionID), []byte("csrf-v1"))
http.SetCookie(w, &http.Cookie{Name: "csrf", Value: csrf, ...})
templates.Render(w, "form", csrf)

// On submit: compare form value to cookie value
formVal := r.FormValue("_csrf")
cookieVal, _ := r.Cookie("csrf")
if formVal != cookieVal.Value { return errCSRF }
// Then optionally verify the seal still opens with the right session
if _, err := sealer.Open(formVal, []byte("csrf-v1")); err != nil { return errCSRF }
```

See [`examples/csrf_token`](./examples/csrf_token).

---

## Webhooks

### Sign an outgoing webhook

```go
mac := crypt.Sign(partner.WebhookSecret, body)
req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(mac))
req.Header.Set("X-Signature-Algorithm", "hmac-sha256")
```

### Verify an incoming webhook

```go
sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Signature"))
body, _ := io.ReadAll(r.Body)
if !crypt.Verify(secret, body, sig) {
    http.Error(w, "invalid signature", 401)
    return
}
```

### Webhook with timestamp tolerance (Stripe-style)

```go
// Sign:   t=1234567890,v1=<hex-mac>
// Signed payload: "<unix-seconds>.<body>"
ts := strconv.FormatInt(time.Now().Unix(), 10)
signed := append([]byte(ts+"."), body...)
mac := crypt.Sign(secret, signed)
header := fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(mac))

// Verify: parse, check timestamp within tolerance, verify mac.
```

See [`examples/webhook_with_timestamp`](./examples/webhook_with_timestamp).

---

## Files and blobs

### Encrypt a file before writing

```go
ct, _ := sealer.Seal(fileBytes, []byte("file:"+filename))
os.WriteFile(path, []byte(ct), 0o644)
```

### Decrypt a file

```go
raw, _ := os.ReadFile(path)
plain, err := sealer.Open(string(raw), []byte("file:"+filename))
```

### Encrypt before S3 upload

```go
ct, _ := sealer.Seal(fileBytes, []byte("s3:"+bucket+":"+key))
_, err := s3.PutObject(ctx, &s3.PutObjectInput{
    Bucket: &bucket,
    Key:    &key,
    Body:   strings.NewReader(ct),
})
```

See [`examples/encrypted_file`](./examples/encrypted_file).

---

## Multi-tenancy

### Per-tenant derived keys (HKDF)

```go
import "golang.org/x/crypto/hkdf"

func tenantSealer(rootKey []byte, tenantID string) (*crypt.Sealer, error) {
    h := hkdf.New(sha256.New, rootKey, nil, []byte("tenant:"+tenantID))
    k := make([]byte, crypt.AEADKeySize)
    if _, err := io.ReadFull(h, k); err != nil { return nil, err }
    return crypt.NewSealer(k)
}
```

See [`examples/tenant_keys`](./examples/tenant_keys).

### Bind ciphertext to a tenant via AAD (without separate keys)

```go
// Cheaper than per-tenant keys. Cross-tenant decrypt fails.
ct, _ := sealer.Seal(payload, []byte("tenant:"+tenantID))
pt, err := sealer.Open(ct, []byte("tenant:"+tenantID))
```

---

## Migrating legacy data

### Read mixed-format ciphertexts

```go
import "github.com/ubgo/crypt/legacy"

// During rollover window: handles both AEAD and CBC.
plain, err := legacy.OpenAuto(key, row.Ciphertext, nil)
```

### One-shot batch migration

```go
rows, _ := db.Query(`SELECT id, ciphertext FROM partner_apps`)
for rows.Next() {
    var id, ct string
    rows.Scan(&id, &ct)
    plain, err := legacy.OpenAuto(key, ct, nil)
    if err != nil { continue }
    sealed, _ := crypt.Seal(key, plain, nil)
    db.Exec(`UPDATE partner_apps SET ciphertext = $1 WHERE id = $2`, sealed, id)
}
```

See [`MIGRATION.md`](./MIGRATION.md) and [`examples/migrate_cbc_to_gcm`](./examples/migrate_cbc_to_gcm).

---

## Operational patterns

### Audit log integrity (HMAC-chained)

```go
prev := []byte{}
for _, e := range entries {
    signed := append(append([]byte{}, prev...), e.Payload...)
    e.MAC = crypt.Sign(auditSecret, signed)
    prev = e.MAC
}
// Verifier walks the chain, recomputing MACs forward; any modification
// breaks the chain.
```

See [`examples/audit_log_chain`](./examples/audit_log_chain).

### Inject Sealer for testing

```go
type Service struct{ sealer *crypt.Sealer }

func TestEncryptField(t *testing.T) {
    testKey := bytes.Repeat([]byte{0x01}, crypt.AEADKeySize)
    sealer, _ := crypt.NewSealer(testKey)
    svc := &Service{sealer: sealer}
    // ... test svc methods
}
```

### Decrypt error handling in HTTP handlers

```go
pt, err := sealer.Open(ct, aad)
if err != nil {
    // Don't leak which kind of error to the client.
    log.WithFields(log.Fields{
        "err":      err,
        "endpoint": r.URL.Path,
        "ip":       r.RemoteAddr,
    }).Warn("decrypt failed")
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

### Avoid logging plaintext keys

```go
// Mark sensitive fields in your structured logger:
logger.Info("plugin init",
    zap.String("env", env),
    zap.String("encryption_key", "REDACTED"))
```

### Detect format upgrades

```go
// If you ever add a v2 format, version-byte detection helps:
if buf, _ := base64.RawURLEncoding.DecodeString(ct); len(buf) > 0 && buf[0] != crypt.VersionAEADv1 {
    // Schedule for re-encryption with the active format.
}
```

---

## Anti-patterns to avoid

| Don't | Do instead |
|---|---|
| Hard-code keys in source | Load from secrets manager / env |
| Use `bytes.Equal` to compare secrets | Use `crypt.ConstantTimeEqual` |
| Decrypt on every request when you can cache | Carefully — caching plaintext defeats encryption |
| Encrypt a password instead of hashing | Use `HashPassword` |
| Log decryption errors with full plaintext | Log error code + correlation ID only |
| Use the same key in dev and prod | Per-environment keys |
| Accept arbitrary AEAD inputs without bounds check | Use `Open` only on trusted inputs |
| Reuse a nonce manually | Use `Seal` (it generates a random nonce) |
