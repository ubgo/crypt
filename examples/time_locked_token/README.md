# Example: time_locked_token

Built-in `IssueToken` / `VerifyToken` for stateless one-time tokens with embedded expiry.

## When to use this pattern

- Password reset emails (~1h TTL).
- Email verification on signup (~24h TTL).
- Magic-link / passwordless login (~5min TTL).
- Any single-use one-time-action token where you don't want a server-side store.

## Run

```sh
cd examples/time_locked_token
go run .
```

## What it does

1. Issues a token: payload + 1-hour TTL, sealed with a purpose-binding AAD ("pwreset-v1").
2. Verifies on the click endpoint: opens, checks the embedded expiry.
3. Demonstrates cross-purpose replay rejection (using a "pwreset-v1" token at an "email-verify-v1" endpoint fails — AAD mismatch).
4. Demonstrates expired-token rejection — distinct `ErrExpired` so the caller can return a specific error to the user ("link expired") different from a tampered-token error ("invalid link").

## How it works

Internally, `IssueToken` packs the expiry as 8 BE bytes ahead of the payload, then seals the combined buffer:

```
sealed = Seal(key, [expiry:8 BE][payload:N], aad)
```

`VerifyToken` opens the seal, checks the expiry, returns the payload. Wire format on the network is the same as plain `Seal` output — version 0x01, base64url-no-pad.

## Comparison with `magic_link`

The [`magic_link`](../magic_link) example shows the same shape built by hand: JSON-encode `{user_id, expires_at}`, seal, parse on verify. `IssueToken/VerifyToken` is the built-in (less boilerplate) version. For new code, use the built-in.

## Adapting to your code

```go
const (
    pwresetAAD = "pwreset-v1"
    pwresetTTL = time.Hour
)

func (s *Service) sendResetEmail(email string) error {
    user, err := s.findUserByEmail(email)
    if err != nil { return nil } // don't leak existence
    tok, err := crypt.IssueToken(s.key, []byte(user.ID), pwresetTTL, []byte(pwresetAAD))
    if err != nil { return err }
    return s.email.Send(email, "Reset password", "https://app.example.com/reset?t="+tok)
}

func (s *Service) handleReset(token, newPassword string) error {
    payload, err := crypt.VerifyToken(s.key, token, []byte(pwresetAAD))
    if err != nil {
        if errors.Is(err, crypt.ErrExpired) {
            return errLinkExpired
        }
        return errInvalidLink
    }
    userID := string(payload)
    hash, _ := crypt.HashPassword(newPassword)
    return s.updatePassword(userID, hash)
}
```
