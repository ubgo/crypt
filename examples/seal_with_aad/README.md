# Example: seal_with_aad

Bind ciphertext to a context using additional authenticated data (AAD).

## When to use AAD

Whenever a ciphertext should only be valid in a specific context:

- Session tokens bound to a user ID
- Per-tenant data bound to a tenant ID
- Per-row encryption bound to a primary key
- Per-route tokens bound to an HTTP path

If the AAD differs at decrypt time, `Open` fails with `ErrTampered` even when the key is correct.

## Run

```sh
cd examples/seal_with_aad
go run .
```

## What it does

1. Issues a session token for user "alice", with AAD = `"user:alice"`.
2. Opens the token as alice → succeeds.
3. Opens the same token as "bob" → fails with `ErrTampered`.

## How it works

GCM authenticates AAD into the cipher tag. The 16-byte tag at the end of every ciphertext is computed over (nonce + ciphertext + aad). If `Open` is called with different aad, the recomputed tag won't match the stored tag, and decryption rejects.

The AAD is **not** encrypted — only authenticated. It stays cleartext alongside the ciphertext (or, more usefully, is reconstructed from external state at decrypt time, like the user ID from the session).

## What this protects against

- Token replay across users (Alice's token isn't valid for Bob)
- Token replay across tenants (Tenant1's data isn't decryptable for Tenant2)
- Token replay across endpoints (an `/api/admin` token isn't valid on `/api/billing`)

## What it does NOT protect against

- Replay against the same user (use a one-time nonce or expiry inside the plaintext)
- Token leakage through logs, headers, etc. (operational concerns)
- Stolen server key (defense-in-depth needed: KMS, key rotation)
