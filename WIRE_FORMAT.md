# Wire Format Specification

This document is the byte-by-byte specification for the ciphertext formats produced by `github.com/ubgo/crypt`. Implementations in any language can target this spec to achieve byte-identical interop.

The TypeScript counterpart at [`@ubgo/crypt`](https://github.com/ubgo/crypt-ts) is one such implementation. Both consume the same [`testdata/vectors.json`](./testdata/vectors.json) for known-answer correctness testing.

---

## AEAD format (version 0x01) — primary

Used by `Seal`, `Open`, `Sealer.Seal`, `Sealer.Open`.

### Encoding

```
Final string output is base64url-no-pad encoding of the binary layout below.
```

`base64url-no-pad` uses the alphabet `A-Z`, `a-z`, `0-9`, `-`, `_`. No `=` padding. URL-safe and HTTP-header-safe without escaping.

### Binary layout

```
Offset   Size   Field           Description
------   ----   -----           -----------
0        1      version         Always 0x01 for AES-256-GCM.
1        12     nonce           96-bit random nonce, fresh per Seal call.
13       N      ciphertext      AES-256-GCM ciphertext, same length as plaintext.
13+N     16     tag             128-bit GCM authentication tag.
```

Total binary size: `29 + N` bytes for an `N`-byte plaintext. After base64url encoding: `ceil((29 + N) * 4 / 3)` characters.

### Sealing algorithm

```
1. Validate len(key) == 32, else error.
2. Generate 12 random bytes (nonce) from CSPRNG.
3. Initialize AES-256-GCM cipher with key, nonce.
4. If aad is provided and non-empty, configure the cipher to authenticate it.
5. Encrypt plaintext, producing ciphertext (length N) and tag (length 16).
6. Concatenate: [0x01] || nonce[12] || ciphertext[N] || tag[16].
7. base64url-no-pad encode.
8. Return the resulting string.
```

### Opening algorithm

```
1. Validate len(key) == 32, else error.
2. base64url-no-pad decode the input string. If decoding fails, return ErrInvalidCiphertext.
3. Validate len(decoded) >= 29 (1 + 12 + 16), else return ErrCiphertextTooShort.
4. Validate decoded[0] == 0x01, else return ErrUnsupportedVersion.
5. Slice:
     nonce = decoded[1:13]    (12 bytes)
     tag   = decoded[len-16:] (16 bytes)
     ct    = decoded[13:len-16]
6. Initialize AES-256-GCM cipher with key, nonce.
7. If aad provided, configure cipher to authenticate it.
8. Set the auth tag on the cipher to the parsed tag.
9. Decrypt ct. If GCM authentication fails, return ErrTampered.
10. Return the resulting plaintext bytes.
```

### Worked example

Inputs (hex):
- key:       `0000000000000000000000000000000000000000000000000000000000000000` (32 bytes, all zero)
- nonce:     `000000000000000000000000` (12 bytes, all zero)
- aad:       (empty)
- plaintext: `68656c6c6f2c20776f726c64` ("hello, world", 12 bytes)

Process:
1. AES-256-GCM(key, nonce) encrypts plaintext → ciphertext (12 bytes) || tag (16 bytes).
2. Binary buffer: `01` || `000000000000000000000000` || `<ciphertext>` || `<tag>`.
3. base64url-no-pad → `AQAAAAAAAAAAAAAAAKbCLFEiTEsZaDyptyVyvm9D_ANLvLHf91EaQ6I`

This vector is in [`testdata/vectors.json`](./testdata/vectors.json) under `aead[1]`.

---

## AES-CBC format

Used by `EncryptCBC`, `DecryptCBC`, and the v0.x string-typed wrappers (`EncryptWithKey` / `DecryptWithKey` / `Cipher.Encrypt` / `Cipher.Decrypt`, which delegate to the byte-typed forms).

### Encoding

```
Final string output is hex (lowercase) encoding of the binary layout below.
```

### Binary layout

```
Offset   Size   Field           Description
------   ----   -----           -----------
0        16     IV              128-bit random IV, fresh per encrypt call.
16       N'     ciphertext      AES-CBC ciphertext, PKCS7-padded to a multiple of 16.
```

Where `N' = N + (16 - N%16)`, i.e., plaintext length rounded up to the next 16-byte boundary (with full-block padding if already aligned).

### CBC encrypt algorithm

```
1. Validate len(key) in {16, 24, 32}, else error.
2. PKCS7-pad plaintext to a multiple of 16:
     padLen = 16 - (len(plaintext) % 16)
     padded = plaintext + (padLen bytes, each = padLen)
3. Generate 16 random bytes (IV) from CSPRNG.
4. AES-CBC encrypt padded with key, iv → ciphertext.
5. Concatenate: iv[16] || ciphertext[N'].
6. hex-encode (lowercase).
7. Return the resulting string.
```

### CBC decrypt algorithm

```
1. Validate len(key) in {16, 24, 32}, else error.
2. hex-decode input. If decoding fails, return ErrInvalidCiphertext.
3. Validate len(decoded) >= 16, else return ErrCiphertextTooShort.
4. Slice:
     iv = decoded[0:16]
     ct = decoded[16:]
5. Validate len(ct) % 16 == 0, else return ErrCiphertextNotBlockAligned.
6. AES-CBC decrypt ct with key, iv → padded plaintext.
7. PKCS7-unpad. If padding is malformed, return ErrInvalidPadding.
8. Return plaintext bytes.
```

### PKCS7 padding rules

- Pad always added, even when input is already block-aligned. A 16-byte input gets a full 16-byte block of `0x10` padding bytes appended.
- Pad byte value equals the number of pad bytes.
- Unpad: read last byte as `padLen`. Validate `1 <= padLen <= 16` and that the last `padLen` bytes are all `padLen`. If not, reject as invalid padding.

### Worked example

Inputs (hex):
- key:       `0000000000000000000000000000000000000000000000000000000000000000` (32 bytes)
- iv:        `11111111111111111111111111111111` (16 bytes)
- plaintext: `68656c6c6f` ("hello", 5 bytes)

Process:
1. PKCS7 pad: `68656c6c6f0b0b0b0b0b0b0b0b0b0b0b` (5 + 11 pad bytes = 16).
2. AES-256-CBC(key, iv) encrypts padded → ciphertext (16 bytes).
3. Binary: iv (16) || ciphertext (16) = 32 bytes.
4. hex → 64 lowercase chars.

This vector is in [`testdata/vectors.json`](./testdata/vectors.json) under `cbc_legacy[0]`.

---

## HMAC-SHA256 — Sign / Verify

The MAC is the raw output of HMAC-SHA256, with no encoding. Callers choose how to encode for transmission (typically base64 or hex in HTTP headers).

### Layout

```
32 bytes (256 bits), the SHA-256 digest of the HMAC computation.
```

### Sign algorithm

```
1. Initialize HMAC-SHA256 with key.
2. Feed data into the HMAC.
3. Read the 32-byte digest.
4. Return.
```

### Verify algorithm

```
1. If len(mac) != 32, return false (without error).
2. Compute expected = Sign(key, data).
3. Compare expected to mac in constant time.
4. Return whether equal.
```

The constant-time comparison is essential: naive byte-wise comparison short-circuits at the first mismatch and leaks timing.

### Worked example

Inputs (hex):
- key:  `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (32 bytes)
- data: `68656c6c6f` ("hello", 5 bytes)

Process:
1. HMAC-SHA256(key, data) = 32-byte digest.

This vector is in [`testdata/vectors.json`](./testdata/vectors.json) under `hmac[1]`.

---

## Format detection (`legacy.OpenAuto`)

The migration helper detects which format a ciphertext uses:

```
1. Try base64url-no-pad decode.
2. If decoded successfully AND len(decoded) >= 29 AND decoded[0] == 0x01:
     dispatch to AEAD Open.
3. Else try hex-decode.
4. If decoded successfully AND len(decoded) >= 16 AND len(decoded[16:]) > 0 AND len(decoded[16:]) % 16 == 0:
     dispatch to CBC DecryptCBC.
5. Else return ErrUnknownFormat.
```

False positive on the AEAD detection (a hex string that happens to start with bytes resembling base64url and has 0x01 as its first decoded byte) is theoretically possible but vanishingly rare. If `Open` rejects the input on the AEAD path, `OpenAuto` falls through to the CBC path before giving up.

---

## Test vectors

The authoritative test vectors live at [`testdata/vectors.json`](./testdata/vectors.json) and are generated by `go run ./cmd/gen-vectors`.

Format:

```json
{
  "version": 1,
  "notes": "...",
  "aead": [
    {
      "name": "...",
      "key_hex": "...",
      "nonce_hex": "...",
      "aad_hex": "...",
      "plaintext_hex": "...",
      "expected_b64url": "..."
    }
  ],
  "hmac": [
    {
      "name": "...",
      "key_hex": "...",
      "data_hex": "...",
      "expected_hex": "..."
    }
  ],
  "cbc_legacy": [
    {
      "name": "...",
      "key_hex": "...",
      "iv_hex": "...",
      "plaintext_hex": "...",
      "expected_hex": "..."
    }
  ]
}
```

All byte fields are hex-encoded — JSON cannot safely carry arbitrary bytes in string fields.

To regenerate after a deliberate change:

```sh
go run ./cmd/gen-vectors > testdata/vectors.json
```

The Go test suite (`vectors_test.go`) and TS test suite (`@ubgo/crypt`'s `vectors.test.ts`) both consume this file. Any divergence in either implementation fails CI.

---

## Versioning policy

- Version 0x01 is **frozen**. Wire format will not change in any v1.x release.
- Future algorithms (e.g., XChaCha20-Poly1305) will use new version bytes (0x02, 0x03, ...).
- Old version bytes will continue to be readable by future versions of the package.
- The version byte will never be recycled.

---

## References

- [NIST SP 800-38D — GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [RFC 5652 §6.3 — PKCS7 padding](https://datatracker.ietf.org/doc/html/rfc5652#section-6.3)
- [RFC 4648 §5 — base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
- [RFC 2104 — HMAC](https://datatracker.ietf.org/doc/rfc2104/)
