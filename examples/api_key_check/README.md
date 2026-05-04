# Example: api_key_check

Constant-time API key authentication middleware using only `net/http` (no framework).

## When to use this pattern

- Internal service-to-service auth where a static shared key gates a route group.
- Webhook receivers where the partner sends a fixed key in a header.
- Admin endpoints behind an `X-Internal-Key` check (replace with your DB-backed scheme for end-user keys).

For end-user API keys you almost always want a database-backed key store with hashed values — this example shows the constant-time comparison primitive that any such scheme depends on.

## Run

```sh
cd examples/api_key_check
go run .
```

## What it does

1. Wraps an HTTP handler with `requireAPIKey(expectedKey, next)`.
2. Each request reads `X-API-Key` and calls `crypt.ConstantTimeEqual` against the configured key.
3. Demonstrates the three outcomes: correct key (200), wrong key (401), missing header (401).

## Why constant-time

Using `bytes.Equal` or `==` short-circuits at the first differing byte. An attacker measuring response time can recover the key one byte at a time. `ConstantTimeEqual` always processes both inputs in full.

## Adapting to your code

```go
func RequireInternalKey(expected []byte) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            got := r.Header.Get("X-API-Key")
            if !crypt.ConstantTimeEqual([]byte(got), expected) {
                http.Error(w, "unauthorized", 401)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

mux := http.NewServeMux()
mux.Handle("/internal/", RequireInternalKey(cfg.InternalKey)(internalAPI))
```
