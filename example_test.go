package crypt_test

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ubgo/crypt"
)

// ExampleSeal demonstrates the most basic encryption flow: derive a
// 32-byte key, seal a plaintext, open it back out.
func ExampleSeal() {
	// In production, load this from secure config — never hard-code.
	key := []byte("01234567890123456789012345678901") // 32 bytes

	ct, err := crypt.Seal(key, []byte("hello, world"), nil)
	if err != nil {
		panic(err)
	}

	pt, err := crypt.Open(key, ct, nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pt))
	// Output: hello, world
}

// ExampleSeal_aad shows binding ciphertext to a context using
// additional authenticated data (AAD). Decrypting with a different
// AAD fails, even with the right key.
func ExampleSeal_aad() {
	key := []byte("01234567890123456789012345678901")

	ct, _ := crypt.Seal(key, []byte("user payload"), []byte("user:42"))

	// Right AAD → success.
	pt, err := crypt.Open(key, ct, []byte("user:42"))
	fmt.Println("right AAD:", err, string(pt))

	// Wrong AAD → ErrTampered.
	_, err = crypt.Open(key, ct, []byte("user:99"))
	fmt.Println("wrong AAD:", err != nil)

	// Output:
	// right AAD: <nil> user payload
	// wrong AAD: true
}

// ExampleSealer shows the recommended pattern for an application that
// encrypts repeatedly with the same key: construct one Sealer at boot,
// share it across goroutines.
func ExampleSealer() {
	key := []byte("01234567890123456789012345678901")

	sealer, err := crypt.NewSealer(key)
	if err != nil {
		panic(err)
	}

	a, _ := sealer.Seal([]byte("first"), nil)
	b, _ := sealer.Seal([]byte("second"), nil)

	pa, _ := sealer.Open(a, nil)
	pb, _ := sealer.Open(b, nil)

	fmt.Println(string(pa), string(pb))
	// Output: first second
}

// ExampleSign demonstrates HMAC-SHA256 signing for webhook
// authenticity: signer and verifier share a secret key.
func ExampleSign() {
	secret := []byte("shared-webhook-secret")
	body := []byte(`{"event":"order.created","id":"ord_123"}`)

	mac := crypt.Sign(secret, body)
	signature := base64.StdEncoding.EncodeToString(mac)

	// Verifier reproduces the MAC and compares constant-time.
	ok := crypt.Verify(secret, body, mac)
	fmt.Println("len(mac):", len(mac))
	fmt.Println("verify:", ok)
	fmt.Println("signature ok:", strings.HasSuffix(signature, "="))
	// Output:
	// len(mac): 32
	// verify: true
	// signature ok: true
}

// ExampleHashPassword shows the password-storage flow: hash on
// registration, verify on login. Hashes encode the parameters used,
// so future cost-tuning is backward-compatible.
func ExampleHashPassword() {
	stored, err := crypt.HashPassword("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	ok, _ := crypt.VerifyPassword("correct horse battery staple", stored)
	bad, _ := crypt.VerifyPassword("Tr0ub4dor&3", stored)

	fmt.Println("phc prefix:", strings.HasPrefix(stored, "$argon2id$"))
	fmt.Println("right pw:", ok)
	fmt.Println("wrong pw:", bad)
	// Output:
	// phc prefix: true
	// right pw: true
	// wrong pw: false
}

// ExampleRandomToken shows generation of a URL-safe token suitable
// for password-reset links, magic-login URLs, API keys, etc.
func ExampleRandomToken() {
	token, err := crypt.RandomToken(24)
	if err != nil {
		panic(err)
	}
	// 24 random bytes → 32 base64url chars (no padding).
	fmt.Println("len:", len(token))
	fmt.Println("url-safe:", !strings.ContainsAny(token, "+/="))
	// Output:
	// len: 32
	// url-safe: true
}

// ExampleConstantTimeEqual demonstrates safe API-key comparison.
// Never use bytes.Equal or `==` for secrets — they leak timing
// information that attackers can use to recover the secret one
// byte at a time.
func ExampleConstantTimeEqual() {
	expected := []byte("internal-api-key-from-config")
	provided := []byte("internal-api-key-from-config")

	if crypt.ConstantTimeEqual(expected, provided) {
		fmt.Println("authorized")
	} else {
		fmt.Println("forbidden")
	}
	// Output: authorized
}

// ExampleOpen shows the verify direction of an AEAD round-trip.
func ExampleOpen() {
	key := []byte("01234567890123456789012345678901")
	ct, _ := crypt.Seal(key, []byte("payload"), []byte("ctx"))

	pt, err := crypt.Open(key, ct, []byte("ctx"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt))
	// Output: payload
}

// ExampleVerify shows verifying an HMAC-SHA256 signature.
func ExampleVerify() {
	secret := []byte("shared-secret")
	body := []byte(`{"event":"order.created"}`)

	mac := crypt.Sign(secret, body)

	if crypt.Verify(secret, body, mac) {
		fmt.Println("authentic")
	} else {
		fmt.Println("rejected")
	}
	// Output: authentic
}

// ExampleRandomBytes shows generating raw random bytes for use as a
// key.
func ExampleRandomBytes() {
	key, err := crypt.RandomBytes(crypt.AEADKeySize)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(key))
	// Output: 32
}

// ExampleRandomHex shows generating a hex string suitable for log
// correlation IDs, filenames, or any case-insensitive identifier.
func ExampleRandomHex() {
	id, err := crypt.RandomHex(8)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(id))
	// Output: 16
}

// ExampleEncryptCBC demonstrates AES-CBC encryption — useful for
// interop with existing AES-CBC systems (PHP, Java, Python). Pair
// with HMAC if you need authentication, or use Seal for built-in
// authenticated encryption.
func ExampleEncryptCBC() {
	key := []byte("01234567890123456789012345678901")
	ct, err := crypt.EncryptCBC(key, []byte("payload"))
	if err != nil {
		panic(err)
	}

	pt, err := crypt.DecryptCBC(key, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt))
	// Output: payload
}

// ExampleSealer_Seal_aad shows binding ciphertext to a context, with
// the bound-key Sealer form.
func ExampleSealer_Seal_aad() {
	key := []byte("01234567890123456789012345678901")
	sealer, _ := crypt.NewSealer(key)

	ct, _ := sealer.Seal([]byte("payload"), []byte("user:42"))
	pt, _ := sealer.Open(ct, []byte("user:42"))

	fmt.Println(string(pt))
	// Output: payload
}
