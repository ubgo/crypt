# Example: hash_password

User registration and login with argon2id password hashing.

## When to use this pattern

- Storing user passwords for later verification (i.e., the canonical user-auth flow).
- Any case where you receive a secret and need to confirm the same secret later, but never need to recover the original.

## When NOT to use this pattern

- API tokens, encryption keys, session secrets — those need to be retrievable, so use `Seal`/`Open` (encryption) instead of hashing.
- Any value the user needs to see again (passwords once typed are typed again, but a generated API key shown once is gone if you only have the hash).

## Run

```sh
cd examples/hash_password
go run .
```

The argon2id KDF is intentionally slow (~10–100 ms by design). The example will pause briefly during registration and each login attempt.

## What it does

1. Hashes Alice's password and stores the PHC string in a fake user table.
2. Verifies a correct password → success.
3. Verifies a wrong password → rejection.
4. Verifies an unknown email → rejection.

## Wire format

The stored string is OWASP-recommended PHC format:

```
$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
```

Parameters are encoded in the string itself, so you can re-tune memory/time costs in future without breaking existing hashes — `VerifyPassword` reads parameters from the stored value.

## Production checklist

- [ ] Rate-limit `login` to prevent online brute force.
- [ ] Constant-time-ish dummy verify for unknown-email cases (this example skips it for brevity).
- [ ] Lockout policy after N failed attempts.
- [ ] Password reset flow uses one-time signed tokens, never reveals stored hashes.
- [ ] Plaintext password is never logged (use `field.Sensitive()` in Ent schemas).
