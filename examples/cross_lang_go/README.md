# Example: cross_lang_go

End-to-end demo: Go encrypts, Node.js (`@ubgo/crypt`) decrypts. Same shared key, same AAD, byte-for-byte interoperable wire format.

## Run

```sh
# 1. From the Go repo root:
go run ./examples/cross_lang_go

# 2. Copy the printed ciphertext.

# 3. In the TS repo:
cd ../crypt-ts
node --import tsx examples/cross-lang-ts/decrypt.ts <paste-ciphertext-here>
```

The TS side produces the exact same plaintext.

## Reverse direction

```sh
# 1. From the TS repo root:
node --import tsx examples/cross-lang-ts/encrypt.ts

# 2. Copy the printed ciphertext.

# 3. In the Go repo (one-line decrypt):
go run ./examples/cross_lang_go/decrypt -ct '<paste>'
```

(Or paste into your own program — `crypt.Open` is a single function call.)

## Why this works

Both implementations target the same wire format (see `WIRE_FORMAT.md`):

```
base64url-no-pad( 0x01 || nonce[12] || ciphertext || tag[16] )
```

Both use AES-256-GCM under the hood (Go's `crypto/cipher.NewGCM`, Node's `crypto.createCipheriv("aes-256-gcm", ...)`). They produce byte-identical output when given the same `(key, nonce, aad, plaintext)`, which is the contract verified by `testdata/vectors.json` in CI.
