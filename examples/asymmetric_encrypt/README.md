# Example: asymmetric_encrypt

X25519 + ChaCha20-Poly1305 sealed-box encryption. Anyone with the recipient's public key can encrypt; only the recipient (with the matching private key) can decrypt.

## When to use this pattern

- End-to-end encrypted messages where the server should not be able to read.
- Distributing config files / secrets to multiple recipients (each with their own keypair).
- Sending data to a partner you've exchanged public keys with.
- Age-style file encryption.

## Run

```sh
cd examples/asymmetric_encrypt
go run .
```

## What it does

1. Generates a recipient X25519 keypair.
2. Sender encrypts under the recipient's public key — does not need the private key.
3. Recipient decrypts with the private key.
4. Demonstrates that a different private key cannot decrypt.
5. Adds a sender-authentication layer: signs the plaintext with Ed25519 first, then seals. Recipient unwraps and verifies the signature against the sender's known public key.

## Sender authentication

Sealed-box semantics are anonymous-sender by design: anyone with the recipient's public key could have sent the message. To authenticate the sender, sign the plaintext with Ed25519 before sealing:

```go
sig, _ := crypt.SignEd25519(senderPriv, payload)
ct, _ := crypt.SealAsymmetric(recipientPub, append(sig, payload...))

// Recipient
opened, _ := crypt.OpenAsymmetric(recipientPriv, ct)
gotSig := opened[:crypt.Ed25519SignatureSize]
gotMsg := opened[crypt.Ed25519SignatureSize:]
ok, _ := crypt.VerifyEd25519(senderPub, gotMsg, gotSig)
```

## Adapting to your code

```go
// At account creation, store the user's public key:
pub, priv, _ := crypt.GenerateKeyPair()
db.User.UpdateOne(u).SetPublicKey(pub).Exec(ctx)
storeSafelyForUser(priv) // client-side or KMS-wrapped

// Sender side (anyone with the public key):
ct, err := crypt.SealAsymmetric(recipient.PublicKey, payload)

// Recipient side:
plain, err := crypt.OpenAsymmetric(myPrivateKey, ct)
```
