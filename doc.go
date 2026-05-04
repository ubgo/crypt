// Package crypt is a cryptography toolkit for Go applications, with
// a byte-for-byte parity TypeScript counterpart (@ubgo/crypt) so Go
// and Node services can encrypt, decrypt, sign, and verify each
// other's payloads.
//
// # Quick start — authenticated encryption
//
// Use [Seal] and [Open] for authenticated encryption with AES-256-GCM.
//
//	key, _ := crypt.RandomBytes(crypt.AEADKeySize) // 32 bytes
//	ct, _ := crypt.Seal(key, []byte("hello, world"), nil)
//	pt, _ := crypt.Open(key, ct, nil)
//	// pt == []byte("hello, world")
//
// For a long-lived sealer with a bound key, use [Sealer]:
//
//	sealer, _ := crypt.NewSealer(appKey)
//	ct, _ := sealer.Seal([]byte("payload"), []byte("user:42"))
//
// # What's included
//
// Authenticated encryption (AES-256-GCM):
//   - [Seal] / [Open]    — package-level form
//   - [Sealer]           — bound-key form, no globals
//
// Random:
//   - [RandomBytes] / [RandomToken] / [RandomHex]
//
// Signing (HMAC-SHA256):
//   - [Sign] / [Verify] / [ConstantTimeEqual]
//
// Password hashing (argon2id):
//   - [HashPassword] / [VerifyPassword]
//
// Legacy (AES-CBC, deprecated):
//   - [EncryptCBC] / [DecryptCBC]
//   - The package-level [EncryptWithKey] / [DecryptWithKey] / [Cipher]
//     are also CBC-based and Deprecated.
//
// Migration helper:
//   - github.com/ubgo/crypt/legacy.OpenAuto detects format and dispatches.
//
// # Wire format
//
// AEAD output is base64url-no-pad encoding of:
//
//	[version:1=0x01][nonce:12][ciphertext:N][tag:16]
//
// The version byte enables forward-compatibility for future algorithms.
//
// Legacy CBC output is hex(IV[16] || PKCS7-padded ciphertext).
//
// # Cross-language parity
//
// All AEAD and HMAC outputs are byte-for-byte interoperable with the
// TypeScript counterpart at github.com/ubgo/crypt-ts. Both sides
// consume testdata/vectors.json as a known-answer correctness check.
//
// # When to use what
//
// Encrypt-at-rest of a database column:
//
//	enc, _ := sealer.Seal(plaintext, nil)
//	db.Save(enc)
//
// Bind ciphertext to a context (e.g., user ID):
//
//	enc, _ := sealer.Seal(plaintext, []byte("user:"+userID))
//
// Generate API tokens / magic links / CSRF:
//
//	token, _ := crypt.RandomToken(32)
//
// Sign outgoing webhooks:
//
//	mac := crypt.Sign(secret, body)
//	req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(mac))
//
// Hash user passwords:
//
//	hash, _ := crypt.HashPassword(plaintext)
//	ok, _  := crypt.VerifyPassword(plaintext, hash)
//
// # Security notes
//
//   - The default key fallback present in earlier versions of this
//     package is removed. AEAD operations require an explicit 32-byte
//     key supplied at call time.
//   - AES-CBC has no message authentication. Code paths that read
//     CBC ciphertext should be marked as legacy and migrated.
//   - Password hashing uses argon2id with parameters tuned per OWASP
//     recommendations (m=64 MiB, t=2, p=1). Stored hashes encode
//     parameters in PHC format, allowing future re-tuning without
//     breaking existing data.
package crypt
