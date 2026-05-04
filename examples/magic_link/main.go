// Magic-link / password-reset link, stateless.
//
// Pattern: a user requests a password-reset email. We issue a URL
// like https://app.com/reset?t=<token>, where <token> is a sealed
// payload containing { user_id, expires_at, purpose }. No DB write
// required. When the user clicks the link, we open the token,
// validate the expiry, and admit them.
//
// Statelessness is the win: no DB row to garbage-collect, no race
// conditions, no replay across-purposes (AAD prevents that).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ubgo/crypt"
)

const (
	purposePasswordReset = "pwreset-v1"
	purposeEmailVerify   = "email-verify-v1"
	resetTokenTTL        = 1 * time.Hour
)

type linkPayload struct {
	UserID    string `json:"u"`
	ExpiresAt int64  `json:"e"` // unix seconds
}

// issueLink seals a payload bound to the purpose (via AAD). A token
// minted for password-reset cannot be used for email-verify even if
// an attacker steals it — the AAD differs.
func issueLink(sealer *crypt.Sealer, userID, purpose string, ttl time.Duration) (string, error) {
	pt, err := json.Marshal(linkPayload{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	return sealer.Seal(pt, []byte(purpose))
}

// verifyLink opens the token and returns the user ID if valid + not
// expired. Returns errors that are safe to surface to users (do not
// leak whether the token was tampered vs expired).
func verifyLink(sealer *crypt.Sealer, token, purpose string) (string, error) {
	pt, err := sealer.Open(token, []byte(purpose))
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}
	var p linkPayload
	if err := json.Unmarshal(pt, &p); err != nil {
		return "", fmt.Errorf("invalid token")
	}
	if time.Now().Unix() >= p.ExpiresAt {
		return "", fmt.Errorf("token expired")
	}
	return p.UserID, nil
}

func main() {
	key := []byte("01234567890123456789012345678901")
	sealer, err := crypt.NewSealer(key)
	if err != nil {
		log.Fatal(err)
	}

	// User clicks "forgot password" — we email them a link.
	token, err := issueLink(sealer, "usr_42", purposePasswordReset, resetTokenTTL)
	if err != nil {
		log.Fatal(err)
	}
	url := "https://app.example.com/reset?t=" + token
	fmt.Printf("emailed link:\n  %s\n\n", url)

	// User clicks the link.
	uid, err := verifyLink(sealer, token, purposePasswordReset)
	if err != nil {
		log.Fatalf("link verify failed: %v", err)
	}
	fmt.Printf("link valid for user: %s\n", uid)

	// Cross-purpose replay attempt: attacker uses a password-reset
	// token on an email-verify endpoint. AAD mismatch → rejected.
	if _, err := verifyLink(sealer, token, purposeEmailVerify); err != nil {
		fmt.Printf("cross-purpose replay: %v\n", err)
	}

	// Expired token. We construct one with negative TTL.
	expired, _ := issueLink(sealer, "usr_99", purposePasswordReset, -time.Hour)
	if _, err := verifyLink(sealer, expired, purposePasswordReset); err != nil {
		fmt.Printf("expired token: %v\n", err)
	}
}
