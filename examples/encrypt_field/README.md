# Example: encrypt_field

Encrypt-at-rest of a database column using `crypt.Sealer`.

## When to use this pattern

- Storing sensitive strings (API client secrets, encryption keys, tokens) in a database column where plaintext storage is unacceptable.
- The application needs to read the value back out for use (so it must be reversible — not hashed).

## Run

```sh
cd examples/encrypt_field
go run .
```

## What it does

1. Loads a 32-byte application key (in production, from PKL/KMS/env).
2. Constructs a long-lived `Sealer`.
3. Encrypts a plaintext "client secret" — stores the ciphertext in a fake row.
4. Reads it back out, decrypts.
5. Demonstrates that any tampering with the stored ciphertext surfaces as an error.

## Adapting to your code

Inject the `Sealer` as a dependency on your service struct:

```go
type Service struct {
    sealer *crypt.Sealer
    db     *ent.Client
}

func (s *Service) CreatePartnerApp(ctx context.Context, secret string) error {
    enc, err := s.sealer.Seal([]byte(secret), nil)
    if err != nil {
        return fmt.Errorf("seal client_secret: %w", err)
    }
    return s.db.PartnerApp.Create().SetClientSecret(enc).Exec(ctx)
}

func (s *Service) GetPartnerApp(ctx context.Context, id string) (string, error) {
    row, err := s.db.PartnerApp.Get(ctx, id)
    if err != nil {
        return "", err
    }
    pt, err := s.sealer.Open(row.ClientSecret, nil)
    if err != nil {
        return "", fmt.Errorf("open client_secret: %w", err)
    }
    return string(pt), nil
}
```
