// Time-locked tokens — built-in IssueToken / VerifyToken with
// embedded expiry. Stateless one-time tokens for password reset,
// email verify, magic login.
//
// Compare with examples/magic_link/ which builds the same shape
// by hand around Seal/Open. This one uses the v1.2 helper that
// embeds the expiry in the wrapped plaintext for you.
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ubgo/crypt"
)

const (
	purposePasswordReset = "pwreset-v1"
	purposeEmailVerify   = "email-verify-v1"
	resetTokenTTL        = time.Hour
)

func main() {
	key := []byte("01234567890123456789012345678901")

	// User clicks "forgot password" — issue a token, email it.
	tok, err := crypt.IssueToken(key, []byte(`user_id=usr_42`), resetTokenTTL, []byte(purposePasswordReset))
	if err != nil {
		log.Fatal(err)
	}
	url := "https://app.example.com/reset?t=" + tok
	fmt.Printf("emailed link:\n  %s\n\n", url)

	// User clicks the link. Verify token, extract user.
	payload, err := crypt.VerifyToken(key, tok, []byte(purposePasswordReset))
	if err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Printf("token valid, payload: %s\n", payload)

	// Cross-purpose replay attempt: attacker uses a password-reset
	// token at the email-verify endpoint. AAD mismatch → rejected.
	if _, err := crypt.VerifyToken(key, tok, []byte(purposeEmailVerify)); err != nil {
		fmt.Printf("\ncross-purpose replay: %v (rejected)\n", err)
	}

	// Expired token — embedded expiry past, ErrExpired returned.
	// (Manually craft one because IssueToken rejects negative TTL.)
	expiredPayload := append(append([]byte(nil), packExpiryBytes(-time.Hour)...), []byte("stale")...)
	expired, _ := crypt.Seal(key, expiredPayload, []byte(purposePasswordReset))
	if _, err := crypt.VerifyToken(key, expired, []byte(purposePasswordReset)); errors.Is(err, crypt.ErrExpired) {
		fmt.Printf("\nexpired token: %v (rejected)\n", err)
	}
}

// packExpiryBytes encodes (now+offset).Unix() as 8 big-endian bytes,
// matching the format VerifyToken expects internally.
func packExpiryBytes(offset time.Duration) []byte {
	expiry := uint64(time.Now().Add(offset).Unix())
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[7-i] = byte(expiry >> (8 * i))
	}
	return out
}
