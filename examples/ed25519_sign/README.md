# Example: ed25519_sign

Ed25519 public-key signatures.

## When to use this pattern

- Webhook signing where partners verify with your public key (no shared secret to leak).
- Software update signing — clients verify before applying.
- Distributed verification: publish a public key once, anyone can validate signatures forever.
- Licence / entitlement files signed by a server, verified by clients.

For symmetric (shared-secret) signing where both sides hold the same key, prefer `Sign` / `Verify` (HMAC-SHA256). HMAC is faster and simpler.

## Run

```sh
cd examples/ed25519_sign
go run .
```

## What it does

1. Generates an Ed25519 keypair from the OS CSPRNG.
2. Signer signs a webhook body with the private key — produces a 64-byte signature.
3. Verifier validates the signature using only the public key.
4. Demonstrates rejection of tampered body, tampered signature, and wrong public key.

## HTTP integration

Outgoing:

```go
sig, _ := crypt.SignEd25519(privKey, body)
req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
req.Header.Set("X-Signature-Algorithm", "ed25519")
```

Incoming verification middleware:

```go
func VerifyEd25519Webhook(pub ed25519.PublicKey) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body)
        r.Body = io.NopCloser(bytes.NewReader(body))

        sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Signature"))
        if err != nil {
            http.Error(w, "bad signature header", 400)
            return
        }
        ok, err := crypt.VerifyEd25519(pub, body, sig)
        if err != nil || !ok {
            http.Error(w, "invalid signature", 401)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

## Key management

- Store the private key in a secrets manager / KMS. It never leaves the signing service.
- Publish the public key freely — embed in client config, host at a `/.well-known/keys` endpoint, etc.
- Rotate by adding a second active key alongside the old one; clients accept signatures from either during the rotation window. After rotation, drop the old key.
