# Example: sealer

Application-wide `Sealer` injected as a service dependency.

## When to use this pattern

Always, in production code. Specifically:

- The application has one or more long-lived services that need to encrypt repeatedly.
- You want to validate the application key exactly once at boot, not on every call.
- You want testable services that take a `*crypt.Sealer` as a dependency rather than reaching into a global.

## Run

```sh
cd examples/sealer
go run .
```

## Why a `Sealer` (not free functions)?

`Seal`/`Open` re-construct the underlying `cipher.Block` and `cipher.AEAD` on every call. For an application that encrypts often (every request, every row save), that's wasted work. `Sealer` constructs the AEAD once and reuses it.

`Sealer` is also concurrent-safe — Go's `cipher.AEAD` is documented as concurrent-safe, and `Sealer` makes no additional state mutations. Share across goroutines without locks.

## Plugin / DI integration

```go
// In your plugin / boot code:
type Plugin struct {
    Sealer *crypt.Sealer
    DB     *ent.Client
    // ... other deps
}

func New(cfg *Config) (*Plugin, error) {
    sealer, err := crypt.NewSealer(cfg.EncryptionKey)
    if err != nil {
        return nil, fmt.Errorf("init sealer: %w", err)
    }
    return &Plugin{Sealer: sealer, ...}, nil
}
```

## Test injection

```go
func TestService_Encrypt(t *testing.T) {
    testKey := bytes.Repeat([]byte{0x01}, crypt.AEADKeySize)
    sealer, _ := crypt.NewSealer(testKey)
    svc := NewService(sealer)

    ct, err := svc.Encrypt("test data")
    require.NoError(t, err)
    pt, err := svc.Decrypt(ct)
    require.NoError(t, err)
    require.Equal(t, "test data", pt)
}
```

No globals to monkey-patch, no PKL config to mock — the sealer is just a value passed in.
