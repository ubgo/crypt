// CSRF token issue + verify, double-submit pattern.
//
// Pattern: when rendering a form, generate a CSRF token tied to the
// session. Embed it in the form as a hidden field AND set it as a
// cookie. On submission, verify the form value matches the cookie.
// Both attacker-controlled origin AND attacker-controlled form data
// are insufficient because the attacker cannot read the cookie value
// (Same-Origin Policy).
//
// We use a sealed value rather than a random one because:
//   - We can encode the session ID into the token (binding to user).
//   - We can encode an expiry, so stale tokens fail.
//   - Comparison is byte-equality on the sealed string (constant-time
//     not strictly required, since the cookie is the source of truth).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ubgo/crypt"
)

type csrfPayload struct {
	SessionID string `json:"s"`
	IssuedAt  int64  `json:"i"`
}

const csrfTTL = 15 * time.Minute

func IssueCSRF(sealer *crypt.Sealer, sessionID string) (string, error) {
	pt, _ := json.Marshal(csrfPayload{
		SessionID: sessionID,
		IssuedAt:  time.Now().Unix(),
	})
	return sealer.Seal(pt, []byte("csrf-v1"))
}

func VerifyCSRF(sealer *crypt.Sealer, token, expectedSession string) error {
	pt, err := sealer.Open(token, []byte("csrf-v1"))
	if err != nil {
		return fmt.Errorf("invalid csrf token")
	}
	var p csrfPayload
	if err := json.Unmarshal(pt, &p); err != nil {
		return fmt.Errorf("invalid csrf token")
	}
	if p.SessionID != expectedSession {
		return fmt.Errorf("csrf token does not belong to this session")
	}
	if time.Now().Unix()-p.IssuedAt > int64(csrfTTL.Seconds()) {
		return fmt.Errorf("csrf token expired")
	}
	return nil
}

func main() {
	sealer, _ := crypt.NewSealer([]byte("01234567890123456789012345678901"))

	sessionID := "sess_abc123"
	tok, err := IssueCSRF(sealer, sessionID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("CSRF token: %s\n\n", tok)

	// Genuine submission.
	if err := VerifyCSRF(sealer, tok, sessionID); err != nil {
		fmt.Printf("genuine submit: %v\n", err)
	} else {
		fmt.Printf("genuine submit: ok\n")
	}

	// Wrong session — attacker stole token from another session.
	if err := VerifyCSRF(sealer, tok, "sess_attacker"); err != nil {
		fmt.Printf("foreign session: %v\n", err)
	}

	// Tampered token.
	if err := VerifyCSRF(sealer, tok[:len(tok)-2]+"XX", sessionID); err != nil {
		fmt.Printf("tampered token: %v\n", err)
	}
}
