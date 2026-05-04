# Example: migrate_cbc_to_gcm

One-shot migration from legacy AES-CBC ciphertext to modern AES-GCM AEAD.

## When to use this pattern

You have data already encrypted with the v0.x CBC API (`EncryptCBC` or the deprecated `EncryptWithKey`/`Cipher`). You want to upgrade it in place to the AEAD format with no service downtime.

## Run

```sh
cd examples/migrate_cbc_to_gcm
go run .
```

## What it does

1. Sets up an in-memory "database" with three CBC-encrypted rows and one AEAD row (mixed format, simulating a partially-migrated table).
2. Iterates every row.
3. Calls `legacy.OpenAuto(key, ciphertext, nil)` — works on both CBC and AEAD formats.
4. Re-encrypts the plaintext with `crypt.Seal`.
5. Writes the new AEAD ciphertext back.
6. Sanity-check: every row now opens with `crypt.Open` (no fallback needed).

## Why `legacy.OpenAuto` (not `DecryptCBC`)

- **Idempotent:** safe to re-run the script. If a row is already AEAD, OpenAuto handles it.
- **Mixed format:** if some rows were touched by application code mid-migration (writing AEAD), the script still completes for those rows.
- **Single import smell:** `import "github.com/ubgo/crypt/legacy"` is a flag that this code is migration tooling, easy to grep for cleanup later.

## Production playbook

The example is single-threaded and in-memory. A real migration:

1. **Backup the database first.** Migration is reversible only if you can restore.
2. **Run in a transaction or batches.** A 100M-row table needs batching (1k–10k rows per transaction).
3. **Don't lock the table.** Use cursor-based iteration with `WHERE id > $last`.
4. **Log row-by-row.** You want a record of every row processed.
5. **Run during low traffic.** AEAD encrypt is fast (~µs per row) but DB writes add up.
6. **Monitor application reads.** Once migration is done, app reads should still work via `crypt.Open` — but if app code uses `DecryptCBC` directly, update it to `Open`.
7. **Drop `legacy.OpenAuto`** from app code after a soak period.
8. **Eventually delete `EncryptCBC`/`DecryptCBC`** from your dependency tree (you control this — just stop calling them).

## Reverting

If migration goes wrong:

- The encryption *key* didn't change — only the algorithm. Old CBC ciphertext is still valid as long as you can put back the original column value.
- Restore from backup, OR keep `OpenAuto` in the read path so you can read both formats during diagnosis.
