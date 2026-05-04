# Migration Guide — AES-CBC → AES-GCM (when you want it)

This document describes how to migrate existing AES-CBC ciphertext to authenticated AES-GCM. **Migration is optional.** AES-CBC and AES-GCM are first-class peers in this package — `DecryptCBC` and `Open` both work indefinitely. Migrate only when authenticated encryption is genuinely required for your threat model (or for compliance), or as a side effect of rewriting nearby code. If your CBC ciphertexts are stable and you don't have a specific reason to switch, leaving them alone is correct.

This document tells you when to migrate, how to do it safely, and how to roll back if something goes wrong.

## Table of contents

- [When to migrate](#when-to-migrate)
- [What changes for callers](#what-changes-for-callers)
- [Migration approaches](#migration-approaches)
- [Migration playbook](#migration-playbook)
- [Rollback strategy](#rollback-strategy)
- [Cross-language migration (Node.js sibling)](#cross-language-migration-nodejs-sibling)

---

## When to migrate

You should migrate if **any** of these apply:

- A security audit (SOC2, PCI, HIPAA) flags lack of authenticated encryption.
- A demonstrated padding-oracle attack vector exists in your environment (rare in practice, but compliance may require defense-in-depth).
- You are already touching the affected schema for another reason — combine the change.
- A new feature requires per-row AAD binding (e.g., per-tenant data isolation).
- You are upgrading to v1.x and want a clean break with no legacy reads.

You should **not** migrate if none of the above apply. Stable production data using `EncryptCBC`/`DecryptCBC` is fine indefinitely. The byte-typed CBC API is a first-class peer of AES-GCM, not deprecated — only the older string-typed wrappers (`Cipher`, `New`, `EncryptWithKey`, `DecryptWithKey`) are marked `Deprecated`, and that's about preferring the byte API, not avoiding CBC.

## What changes for callers

### v0.x API (still works, marked Deprecated)

```go
c, _ := crypt.New(key)
encrypted, _ := c.Encrypt("secret")
decrypted, _ := c.Decrypt(encrypted)

// Or:
encrypted, _ := crypt.EncryptWithKey(key, "secret")
decrypted, _ := crypt.DecryptWithKey(key, encrypted)
```

### v1.x preferred API

```go
sealer, _ := crypt.NewSealer(keyBytes) // 32 bytes
encrypted, _ := sealer.Seal([]byte("secret"), nil)
decrypted, _ := sealer.Open(encrypted, nil)

// Or for one-shot:
encrypted, _ := crypt.Seal(keyBytes, []byte("secret"), nil)
decrypted, _ := crypt.Open(keyBytes, encrypted, nil)
```

Key differences:

| v0.x | v1.x |
|---|---|
| `string` key, `string` plaintext | `[]byte` key, `[]byte` plaintext |
| Hex output | base64url-no-pad output |
| 16/24/32 byte keys | 32-byte keys only |
| No AAD | Optional AAD parameter |
| No tamper detection | Tamper detection via GCM tag |

The byte-array API is more honest about what's actually being encrypted — string-typed plaintext is a leaky abstraction over bytes.

## Migration approaches

There are three viable approaches. Pick per use case.

### A. Lazy re-encrypt

Read with `crypt.OpenAuto` (handles both formats). On the next write to a row, write with `Seal`. Over time, the table converges to AEAD format naturally.

**Pros:**
- No batch script
- Zero downtime
- Reversible at any point

**Cons:**
- Mixed format in the database indefinitely
- Reader path forever depends on `OpenAuto`

**Best for:** Long-lived rows that are touched often (sessions, active client secrets, cached credentials).

```go
import (
    "github.com/ubgo/crypt"
    "github.com/ubgo/crypt"
)

func (s *Service) GetSecret(ctx context.Context, id string) (string, error) {
    row, err := s.db.PartnerApp.Get(ctx, id)
    if err != nil {
        return "", err
    }
    plain, err := crypt.OpenAuto(s.key, row.ClientSecret, nil)
    if err != nil {
        return "", err
    }
    return string(plain), nil
}

func (s *Service) RotateSecret(ctx context.Context, id, newSecret string) error {
    enc, err := s.sealer.Seal([]byte(newSecret), nil)
    if err != nil {
        return err
    }
    return s.db.PartnerApp.UpdateOneID(id).SetClientSecret(enc).Exec(ctx)
}
```

### B. One-shot batch migration

A script reads every row, decrypts with `OpenAuto`, re-encrypts with `Seal`, writes back.

**Pros:**
- Clean state at the end (reader can switch to plain `Open`)
- Predictable cutover date

**Cons:**
- Requires a maintenance window or careful concurrency strategy
- Reversible only via backup

**Best for:** Small tables, archival data that won't be touched naturally.

See [`examples/migrate_cbc_to_gcm/`](./examples/migrate_cbc_to_gcm) for a runnable demonstration.

```go
import (
    "github.com/ubgo/crypt"
    "github.com/ubgo/crypt"
)

func migrate(ctx context.Context, db *ent.Client, key []byte) error {
    rows, err := db.PartnerApp.Query().All(ctx)
    if err != nil {
        return err
    }
    for _, row := range rows {
        plain, err := crypt.OpenAuto(key, row.ClientSecret, nil)
        if err != nil {
            log.Printf("row %s: skip (%v)", row.ID, err)
            continue
        }
        sealed, err := crypt.Seal(key, plain, nil)
        if err != nil {
            return err
        }
        if err := db.PartnerApp.UpdateOneID(row.ID).SetClientSecret(sealed).Exec(ctx); err != nil {
            return err
        }
    }
    return nil
}
```

### C. Tag-and-route

Add an `enc_version` column to the affected table. Writers stamp the version on every write. Readers dispatch by version.

**Pros:**
- Explicit, auditable
- Supports future migrations too (version bumps)

**Cons:**
- Schema change required
- More code complexity

**Best for:** Regulated data where audit trail matters, or tables that may host multiple sequential format changes.

```sql
ALTER TABLE partner_apps ADD COLUMN enc_version INT NOT NULL DEFAULT 0;
```

```go
const (
    EncVersionCBC  = 0
    EncVersionAEAD = 1
)

func (s *Service) load(row *PartnerApp) ([]byte, error) {
    switch row.EncVersion {
    case EncVersionAEAD:
        return s.sealer.Open(row.ClientSecret, nil)
    case EncVersionCBC:
        return crypt.DecryptCBC(s.key, row.ClientSecret)
    default:
        return nil, fmt.Errorf("unknown enc_version %d", row.EncVersion)
    }
}

func (s *Service) save(row *PartnerApp, secret []byte) error {
    enc, err := s.sealer.Seal(secret, nil)
    if err != nil {
        return err
    }
    return s.db.PartnerApp.UpdateOneID(row.ID).
        SetClientSecret(enc).
        SetEncVersion(EncVersionAEAD).
        Exec(ctx)
}
```

## Migration playbook

For a typical "lazy + eventual" migration combining approaches A and B:

### Step 1 — Update read path

Change the read path from `DecryptCBC` (or `DecryptWithKey`) to `crypt.OpenAuto`. Verify in staging that reads succeed against current production data.

```go
// Before
plain, err := crypt.DecryptCBC(key, row.ClientSecret)

// After
plain, err := crypt.OpenAuto(key, row.ClientSecret, nil)
```

Deploy. Monitor for errors. No data has changed yet.

### Step 2 — Update write path

Change the write path from `EncryptCBC` to `Seal`.

```go
// Before
enc, err := crypt.EncryptCBC(key, plaintext)

// After
enc, err := sealer.Seal(plaintext, nil)
```

Deploy. New writes are AEAD; existing rows are still CBC. Reads via `OpenAuto` handle both.

### Step 3 — Soak

Wait for natural rotation. How long depends on your data:

- Sessions: hours
- Client secrets: weeks-to-months (until customers rotate)
- Archival data: indefinite (it never naturally rotates — go to step 4)

During the soak, monitor: log which format each read encountered. When the CBC count drops to zero (or close to it), proceed.

### Step 4 — (Optional) Batch the stragglers

If the soak doesn't fully drain CBC rows, run a batch script ([`examples/migrate_cbc_to_gcm/`](./examples/migrate_cbc_to_gcm)).

**Run from a backup:** dump the table or DB before starting.

```sh
# Backup
pg_dump -t partner_apps mydb > partner_apps_pre_migration.sql

# Migrate
go run ./cmd/migrate-secrets

# Verify
psql mydb -c "SELECT COUNT(*) FROM partner_apps WHERE client_secret NOT LIKE 'A%';"
# Should be 0 — AEAD outputs always start with 'A' (base64 of 0x01).
```

### Step 5 — Switch reader to `Open`

Change the read path back from `OpenAuto` to plain `Open`.

```go
// Before
plain, err := crypt.OpenAuto(key, row.ClientSecret, nil)

// After
plain, err := sealer.Open(row.ClientSecret, nil)
```

Deploy. Monitor for `ErrUnsupportedVersion` or `ErrTampered` — if any, you missed a row and need to revert step 5 until step 4 is repeated.

### Step 6 — Clean up

Search for any remaining import of `github.com/ubgo/crypt` in production paths. The legacy subpackage should now appear only in migration scripts.

```sh
grep -rn 'crypt' --include '*.go' . | grep -v cmd/migrate
```

If the table was the last consumer of `EncryptCBC`/`DecryptCBC`, consider removing those imports too.

## Rollback strategy

Migration is reversible up to step 5. After step 5 (reader switched to `Open` only):

- If you missed CBC rows in batch, those rows fail on read with `ErrUnsupportedVersion`.
- Quick fix: revert step 5, deploy, run batch again, redo step 5.

If batch corrupts data:

- Restore from the pre-migration backup.
- The encryption key did not change between formats — only the algorithm. Original CBC ciphertexts are still valid as long as the key is preserved.

If the key was rotated as part of migration:

- Use `KeyRing` (planned for v1.1) to read with old key, write with new key.
- For v1.0, keep the old key reachable for the duration of migration.

## Cross-language migration (Node.js sibling)

If you have a Node.js service that reads/writes the same encrypted data via `aitoolscrypt.ts` or `@ubgo/crypt`:

### Step 1 — Upgrade Node side first

The current `aitoolscrypt.ts` has bugs (see [PLAN.md](https://github.com/ubgo/crypt/blob/main/docs/internal/PLAN.md)) that silently corrupt data > 16 bytes. Replace with `@ubgo/crypt`:

```ts
// Before (buggy)
import { aitoolsCrypt } from "~/lib/aitoolscrypt"
const plain = aitoolsCrypt.decrypt(stored)

// After (correct, supports both formats)
import { openAuto } from "@ubgo/crypt"
const plain = openAuto(key, stored).toString("utf8")
```

Deploy. Node now reads CBC correctly (including > 16-byte payloads that were broken before).

### Step 2 — Coordinate Go and Node migration

Both sides switch to AEAD `seal` / `Seal` for new writes. Both sides use `openAuto` / `OpenAuto` for reads during the soak. Migrate batch on either side; it doesn't matter which.

### Step 3 — Both sides switch to plain `Open`

After the soak and batch, both Go and Node read with plain `Open` / `open`. Drop `legacy` imports.

This is the same playbook as Go-only, just executed on both sides. The shared wire format means there is no Go-vs-Node mismatch as long as both repos are at v1.x.
