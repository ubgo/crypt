// Example: bind ciphertext to a context using AAD (additional
// authenticated data).
//
// AAD is data that is authenticated but not encrypted. The same
// AAD must be supplied at both Seal and Open. If the AAD differs,
// Open fails with ErrTampered, even with the right key.
//
// Use case: a session token sealed for a specific user. Stealing
// userA's token doesn't let an attacker use it as userB, because
// the AAD ("user:A") was authenticated into the ciphertext.
package main

import (
	"errors"
	"fmt"

	"github.com/ubgo/crypt"
)

func issueSession(serverKey []byte, userID, payload string) (string, error) {
	aad := []byte("user:" + userID)
	return crypt.Seal(serverKey, []byte(payload), aad)
}

func openSession(serverKey []byte, userID, ciphertext string) (string, error) {
	aad := []byte("user:" + userID)
	pt, err := crypt.Open(serverKey, ciphertext, aad)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func main() {
	serverKey := []byte("01234567890123456789012345678901")

	// Issue a session token for Alice.
	token, err := issueSession(serverKey, "alice", `{"role":"admin"}`)
	if err != nil {
		panic(err)
	}
	fmt.Printf("token issued for alice: %s\n\n", token)

	// Server reads token and asserts user identity (e.g., from a cookie
	// + a server-side claim about who the cookie belongs to).
	pt, err := openSession(serverKey, "alice", token)
	fmt.Printf("open as alice: pt=%q err=%v\n", pt, err)

	// Attacker steals Alice's token, tries to use it as Bob.
	_, err = openSession(serverKey, "bob", token)
	fmt.Printf("open as bob:   err=%v\n", err)
	fmt.Printf("is tampered:   %v\n", errors.Is(err, crypt.ErrTampered))
}
