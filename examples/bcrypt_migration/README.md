# Example: bcrypt_migration

Migrate user password hashes from bcrypt to argon2id over time. Each user's hash is upgraded the next time they log in successfully.

## When to use this pattern

- You're inheriting a `users` table with bcrypt password hashes (Rails, Django, Node bcrypt) and want to move to argon2id without forcing a password reset.
- You're consolidating two systems' user tables and one used bcrypt while the other used argon2id.

## Run

```sh
cd examples/bcrypt_migration
go run .
```

The bcrypt round-trip is intentionally slow (default cost 12 → ~100 ms). The example will pause briefly during the initial setup.

## What it does

1. Sets up a fake user with a bcrypt-format hash (starts with `$2`).
2. Login attempt: detects bcrypt format, verifies, then re-hashes with argon2id and updates the user row in place.
3. Subsequent login attempts hit the argon2id branch directly.
4. Wrong-password attempts are still rejected at the verify step.

## Pattern

```go
func loginAndMaybeRehash(u *User, plaintext string) error {
    switch {
    case strings.HasPrefix(u.PasswordHash, "$2"):
        ok, err := crypt.VerifyPasswordBcrypt(plaintext, u.PasswordHash)
        if err != nil { return err }
        if !ok { return errInvalidCreds }

        // Auto-upgrade.
        newHash, err := crypt.HashPassword(plaintext)
        if err != nil { return err }
        u.PasswordHash = newHash
        return saveUser(u)

    case strings.HasPrefix(u.PasswordHash, "$argon2"):
        ok, err := crypt.VerifyPassword(plaintext, u.PasswordHash)
        if err != nil { return err }
        if !ok { return errInvalidCreds }
        return nil

    default:
        return errors.New("unknown password hash format")
    }
}
```

## Cleanup phase

After all (or nearly all) active users have logged in once and been upgraded:

1. Identify users still on bcrypt: `SELECT count(*) FROM users WHERE password_hash LIKE '$2%'`.
2. Email them a forced password reset.
3. After the reset window, drop the bcrypt branch from `loginAndMaybeRehash`.
