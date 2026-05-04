# Example: csrf_token

CSRF token issue + verify, double-submit pattern with a sealed-value token.

## When to use this pattern

- Web app with HTML forms that mutate state. Standard defense against cross-site request forgery.
- Any case where you set a cookie and want to confirm the form submitter has it (origin check).

## Run

```sh
cd examples/csrf_token
go run .
```

## What it does

1. Issues a CSRF token sealed with the user's session ID + issued-at timestamp.
2. Verifies on submission: opens the seal, checks the embedded session ID matches the current session, checks the token isn't past TTL.
3. Demonstrates rejection paths: foreign session, tampered token.

## Why a sealed token, not a random nonce

A random nonce is fine for CSRF — sealing is overkill. But sealing buys:
- **Stateless verification.** No DB / Redis lookup; the session ID is encoded in the token.
- **Expiry binding.** Old tokens fail automatically.
- **Audit traceability.** Open the token to see which session generated it.

## Adapting to your code

```go
// Issue at form render:
csrf, _ := IssueCSRF(sealer, session.ID)
http.SetCookie(w, &http.Cookie{
    Name:     "csrf",
    Value:    csrf,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    Path:     "/",
})
templates.Render(w, "form", map[string]string{"csrf": csrf})

// Verify on submission (form value matches cookie value AND seal still opens):
formCSRF := r.FormValue("_csrf")
cookieCSRF, _ := r.Cookie("csrf")
if formCSRF != cookieCSRF.Value {
    http.Error(w, "csrf mismatch", 403)
    return
}
if err := VerifyCSRF(sealer, formCSRF, session.ID); err != nil {
    http.Error(w, err.Error(), 403)
    return
}
```
