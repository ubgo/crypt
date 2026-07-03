// Package crypt is a cryptography toolkit for Go applications, with
// a byte-for-byte parity TypeScript counterpart crypt-ts so Go
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
//   - The v0.x string-typed wrappers [EncryptWithKey] / [DecryptWithKey]
//     and [Cipher] / [New] are kept Deprecated; use the byte-typed
//     EncryptCBC/DecryptCBC instead.
//
// Format auto-detect:
//   - [OpenAuto] decrypts ciphertext that may be AEAD or AES-CBC.
//     Useful for migration scripts and rollover-window readers.
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
// # Key binding and rotation — design choices
//
// The package binds keys in exactly two ways and intentionally omits
// a third that callers sometimes ask for.
//
//   - Call-time: [Seal] / [Open] take the key as an argument. Simplest;
//     good when the key is already in hand at the call site.
//   - Construction-time: [NewSealer] binds the key into a [Sealer] once,
//     so downstream code calls Seal/Open with no key argument. Prefer
//     this to writing your own encryptToken(key, ...) wrappers — it is
//     the same "set once, call bare" ergonomics without a global.
//
// There is deliberately no package-level default key (no SetKey /
// SealDefault). A global would be hidden mutable state: hard to test
// (parallel tests share it), impossible to run two keys at once, and a
// silent zero-key footgun if used before it is set. A [Sealer] value
// gives the same convenience without those hazards.
//
// A [Sealer] is also immutable — no Rekey method. Its key never changes
// after construction, which is what lets it be shared across goroutines
// without a lock. To rotate keys:
//
//   - Use [KeyRing] for restart-free rotation. Writes use the active
//     key; reads dispatch by the kid embedded in each ciphertext, so old
//     data stays readable during the migration window. This is the right
//     tool for compliance rotation and compromise response.
//   - Or swap a whole Sealer at a safe boundary via
//     sync/atomic.Pointer[Sealer]. Cheap and race-free, but a single
//     key only — old ciphertext is not readable after the swap unless
//     you keep the old Sealer around yourself.
//
// # Security notes
//
//   - The default key fallback present in earlier versions of this
//     package is removed. AEAD operations require an explicit 32-byte
//     key supplied at call time.
//   - AES-CBC has no built-in message authentication. If you need
//     tamper detection on CBC output, layer HMAC on top, or use
//     Seal/Open which build it in.
//   - Password hashing uses argon2id with parameters tuned per OWASP
//     recommendations (m=64 MiB, t=2, p=1). Stored hashes encode
//     parameters in PHC format, allowing future re-tuning without
//     breaking existing data.
package crypt
