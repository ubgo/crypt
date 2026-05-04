// Example: register / login flow with argon2id password hashing.
//
// Pattern: on registration, hash the user's password and store the
// PHC string. On login, look up the user by email, verify the
// supplied password against the stored hash. Never store plaintext.
package main

import (
	"errors"
	"fmt"

	"github.com/ubgo/crypt"
)

// fakeUser stands in for an Ent User row.
type fakeUser struct {
	Email        string
	PasswordHash string // PHC-format argon2id hash
}

var users = map[string]*fakeUser{} // by email

func register(email, password string) error {
	if _, exists := users[email]; exists {
		return errors.New("email already registered")
	}
	hash, err := crypt.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	users[email] = &fakeUser{Email: email, PasswordHash: hash}
	return nil
}

func login(email, password string) error {
	u, ok := users[email]
	if !ok {
		// Constant-time-ish: still call VerifyPassword on a dummy hash
		// to avoid leaking "user exists" via timing. (For brevity, we
		// just return.)
		return errors.New("invalid credentials")
	}
	ok, err := crypt.VerifyPassword(password, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !ok {
		return errors.New("invalid credentials")
	}
	return nil
}

func main() {
	// Register.
	if err := register("alice@example.com", "correct horse battery staple"); err != nil {
		fmt.Printf("register: %v\n", err)
		return
	}
	fmt.Printf("registered: alice\n")
	fmt.Printf("stored hash: %s\n\n", users["alice@example.com"].PasswordHash)

	// Login with right password.
	if err := login("alice@example.com", "correct horse battery staple"); err != nil {
		fmt.Printf("login: %v\n", err)
	} else {
		fmt.Println("login (right password): ok")
	}

	// Login with wrong password.
	if err := login("alice@example.com", "Tr0ub4dor&3"); err != nil {
		fmt.Printf("login (wrong password): %v\n", err)
	}

	// Login with unknown email.
	if err := login("bob@example.com", "anything"); err != nil {
		fmt.Printf("login (unknown email): %v\n", err)
	}
}
