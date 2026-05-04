# Example: magic_link

Stateless password-reset / email-verify links built by hand around `Seal` / `Open`. For a built-in helper that does the same thing in fewer lines, see the [`time_locked_token`](../time_locked_token) example.

## When to use this pattern

- Password reset emails (~1h TTL).
- Email verification on signup (~24h TTL).
- Passwordless login (~5min TTL).
- Any single-use one-time-action link where you don't want a server-side token store.

## Run

```sh
cd examples/magic_link
go run .
```

## What it does

1. Issues a token by JSON-encoding `{user_id, expires_at}` and sealing with a purpose-binding AAD ("pwreset-v1").
2. Verifies on click: opens, parses, checks expiry.
3. Demonstrates cross-purpose replay rejection (a "pwreset-v1" token used at the email-verify endpoint fails because AAD differs).
4. Demonstrates expired-token rejection.

## When to use `time_locked_token` instead

The built-in `crypt.IssueToken` / `crypt.VerifyToken` (v1.2) packages this pattern: embeds expiry in the wrapped plaintext for you, returns `ErrExpired` distinctly. Less boilerplate, same result. Use it for new code.

## Adapting to your code

```go
const (
    purposePasswordReset = "pwreset-v1"
    resetTokenTTL        = 1 * time.Hour
)

func (s *Service) SendResetEmail(ctx context.Context, email string) error {
    user, err := s.db.User.Query().Where(user.Email(email)).Only(ctx)
    if err != nil {
        // Don't leak whether the email exists.
        return nil
    }

    payload, _ := json.Marshal(struct {
        UserID string `json:"u"`
        Exp    int64  `json:"e"`
    }{
        UserID: user.ID,
        Exp:    time.Now().Add(resetTokenTTL).Unix(),
    })

    tok, err := s.sealer.Seal(payload, []byte(purposePasswordReset))
    if err != nil {
        return err
    }
    url := fmt.Sprintf("https://app.example.com/reset?t=%s", tok)
    return s.email.Send(email, "Reset your password", url)
}

func (s *Service) HandleResetClick(ctx context.Context, token, newPassword string) error {
    pt, err := s.sealer.Open(token, []byte(purposePasswordReset))
    if err != nil {
        return errors.New("invalid or expired link")
    }
    var p struct {
        UserID string `json:"u"`
        Exp    int64  `json:"e"`
    }
    if err := json.Unmarshal(pt, &p); err != nil {
        return errors.New("invalid link")
    }
    if time.Now().Unix() >= p.Exp {
        return errors.New("link expired")
    }
    hash, _ := crypt.HashPassword(newPassword)
    return s.db.User.UpdateOneID(p.UserID).SetPassword(hash).Exec(ctx)
}
```
