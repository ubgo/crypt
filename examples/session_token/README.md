# Example: session_token

Stateless session token with embedded expiry — JWT-like pattern, smaller, no algorithm-confusion foot-gun.

## When to use this pattern

- API tokens for service-to-service auth where you want statelessness.
- Browser session tokens (often paired with the [`encrypted_cookie`](../encrypted_cookie) pattern).
- Mobile app session tokens stored on-device.
- Any case where you'd reach for JWT but don't need standard JOSE interop.

## Why not JWT

JWT has well-documented foot-guns:
- `alg=none` — historical attacks where a verifier accepted unsigned tokens.
- Algorithm confusion — sending an `alg=HS256` token to a verifier expecting `alg=RS256`, who then uses the public key as the HMAC key.
- JOSE header complexity.

Sealing a struct with `Seal` avoids all of this: there's no algorithm header, no negotiation, no "trust the header for which key to use."

If you need standard JWT for interop with another service, use `paseto-go` or `go-jose`.

## Run

```sh
cd examples/session_token
go run .
```

## What it does

1. Issues a session token sealing `{user_id, scopes, issued_at, expires_at}`.
2. Opens, validates expiry + clock-skew tolerance.
3. Demonstrates tamper rejection.

## Adapting to your code

```go
type Session struct {
    UserID string   `json:"u"`
    Scopes []string `json:"s,omitempty"`
    Issued int64    `json:"i"`
    Expiry int64    `json:"e"`
}

func IssueSession(sealer *crypt.Sealer, userID string, scopes []string, ttl time.Duration) (string, error) {
    now := time.Now()
    pt, _ := json.Marshal(Session{
        UserID: userID, Scopes: scopes,
        Issued: now.Unix(), Expiry: now.Add(ttl).Unix(),
    })
    return sealer.Seal(pt, []byte("session-v1"))
}

func OpenSession(sealer *crypt.Sealer, token string) (*Session, error) {
    pt, err := sealer.Open(token, []byte("session-v1"))
    if err != nil { return nil, errors.New("invalid session") }
    var s Session
    if err := json.Unmarshal(pt, &s); err != nil { return nil, errors.New("invalid session") }
    if time.Now().Unix() >= s.Expiry { return nil, errors.New("session expired") }
    return &s, nil
}
```

## Built-in alternative

For shorter code, see the [`time_locked_token`](../time_locked_token) example which uses `crypt.IssueToken` / `crypt.VerifyToken`. Same result; binary expiry encoding instead of JSON.
