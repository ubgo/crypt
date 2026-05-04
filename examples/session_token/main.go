// Stateless session token with embedded expiry — a JWT-like pattern
// implemented as a sealed payload, smaller and without algorithm
// confusion.
//
// We seal a JSON payload that contains the user, scopes, expiry, and
// an issued-at timestamp. The server stores nothing. On every request,
// the token is opened, expiry is checked, and the session is
// reconstructed.
//
// Compared to JWT: smaller (no JOSE header), no algorithm-negotiation
// risk, AAD-bindable to a tenant or audience.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ubgo/crypt"
)

type Session struct {
	UserID    string   `json:"u"`
	Scopes    []string `json:"s,omitempty"`
	IssuedAt  int64    `json:"i"`
	ExpiresAt int64    `json:"e"`
}

const (
	sessionAAD     = "session-v1" // bind to format version
	sessionTTL     = 24 * time.Hour
	clockSkewLimit = 30 * time.Second
)

func IssueSession(sealer *crypt.Sealer, userID string, scopes []string) (string, error) {
	now := time.Now()
	pt, err := json.Marshal(Session{
		UserID:    userID,
		Scopes:    scopes,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(sessionTTL).Unix(),
	})
	if err != nil {
		return "", err
	}
	return sealer.Seal(pt, []byte(sessionAAD))
}

func OpenSession(sealer *crypt.Sealer, token string) (*Session, error) {
	pt, err := sealer.Open(token, []byte(sessionAAD))
	if err != nil {
		return nil, errors.New("invalid session")
	}
	var s Session
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, errors.New("invalid session")
	}
	now := time.Now().Unix()
	if now >= s.ExpiresAt {
		return nil, errors.New("session expired")
	}
	if s.IssuedAt > now+int64(clockSkewLimit.Seconds()) {
		return nil, errors.New("session in the future")
	}
	return &s, nil
}

func main() {
	sealer, err := crypt.NewSealer([]byte("01234567890123456789012345678901"))
	if err != nil {
		log.Fatal(err)
	}

	tok, err := IssueSession(sealer, "usr_42", []string{"read", "write"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("session token (%d chars):\n  %s\n\n", len(tok), tok)

	s, err := OpenSession(sealer, tok)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	fmt.Printf("opened session: user=%s scopes=%v expires=%v\n",
		s.UserID, s.Scopes, time.Unix(s.ExpiresAt, 0).Format(time.RFC3339))

	// Tampered token.
	bad := tok[:len(tok)-3] + "XYZ"
	if _, err := OpenSession(sealer, bad); err != nil {
		fmt.Printf("tampered: %v\n", err)
	}
}
