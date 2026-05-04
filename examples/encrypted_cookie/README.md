# Example: encrypted_cookie

Encrypted session cookie — entire session payload lives in the cookie value, sealed with the server's key. No DB / Redis lookups per request.

## When to use this pattern

- Stateless web apps where the session is small (< 4KB after sealing) and you want zero session-store latency.
- Horizontally-scaled services without sticky sessions.
- Edge functions where DB hops are expensive.

## When NOT to use

- Sessions that need server-side revocation (logout-all-devices, force re-login). Sealed cookies cannot be invalidated server-side without a denylist.
- Sessions with large payloads (> a few KB). Cookies are sent on every request — pay for it.
- Cases where you need a server-side audit trail of session events.

## Run

```sh
cd examples/encrypted_cookie
go run .
```

## What it does

1. Spins up an in-memory `httptest` server with `/login` and `/me` endpoints.
2. `/login` seals a `{user_id, expires_at}` payload, sets it as an `HttpOnly` cookie.
3. `/me` reads the cookie, opens the seal, returns the user ID.
4. Demonstrates the unauthenticated case (no cookie → 401).

## Cookie attribute checklist for production

- `HttpOnly` — prevents JS access (no XSS exfiltration).
- `Secure` — HTTPS-only (prevents MITM theft on plain HTTP).
- `SameSite=Lax` (or `Strict`) — limits cross-origin sending.
- `Path=/` (or scoped) — limits where the cookie is sent.
- `Expires` or `Max-Age` — short-lived; matches the embedded payload TTL.

## Adapting to your code

```go
type SessionMiddleware struct {
    sealer *crypt.Sealer
}

func (s *SessionMiddleware) Authenticated() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        sess, err := getSession(r, s.sealer)
        if err != nil {
            http.Error(w, "unauthorized", 401)
            return
        }
        ctx := context.WithValue(r.Context(), userCtxKey{}, sess.UserID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```
