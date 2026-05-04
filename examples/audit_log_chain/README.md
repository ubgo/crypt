# Example: audit_log_chain

HMAC-chained audit log with tamper detection. Each entry is signed over (previous-MAC || payload) — removing or modifying any entry breaks the chain.

## When to use this pattern

- Regulated audit trails (SOC2, HIPAA, PCI) where you must prove no entry has been altered.
- Security event logging.
- Append-only ledgers where order matters.

## Run

```sh
cd examples/audit_log_chain
go run .
```

## What it does

1. Builds an `AuditLog` with three entries (login, view, delete).
2. Each entry's MAC is computed over `prevMAC || payload`, binding it to the chain.
3. `Verify()` walks the chain forward; returns `-1` if all entries verify or the index of the first broken one.
4. Demonstrates that modifying an entry breaks the chain at that point.

## Limitations

- The signing secret must be protected — anyone with the secret can rewrite the chain. For stronger guarantees, use ephemeral keys with a hardware-anchored root, or write entries to an immutable store (S3 with object-lock, blockchain, etc.).
- Detection only — this scheme detects tampering but does not prevent it. Pair with append-only storage for prevention.

## Adapting to your code

```go
type AuditLog struct {
    secret []byte
    db     *sql.DB
}

func (l *AuditLog) Append(actor, action, resource string) error {
    var prev []byte
    _ = l.db.QueryRow(`SELECT mac FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)

    payload := fmt.Sprintf("%s|%s|%s|%s", time.Now().UTC().Format(time.RFC3339Nano), actor, action, resource)
    signed := append(prev, []byte(payload)...)
    mac := crypt.Sign(l.secret, signed)

    _, err := l.db.Exec(
        `INSERT INTO audit_log(actor, action, resource, payload, mac) VALUES($1, $2, $3, $4, $5)`,
        actor, action, resource, payload, mac,
    )
    return err
}
```
