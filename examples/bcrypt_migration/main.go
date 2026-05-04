// Bcrypt password migration to argon2id.
//
// Use case: you have a `users` table with bcrypt hashes from a
// previous system (Rails, Django, Node bcrypt). New code should
// hash with argon2id (HashPassword / VerifyPassword), but you can't
// re-hash existing users until they next log in (you don't have
// their plaintext password).
//
// Migration playbook:
//  1. On login: try VerifyPasswordBcrypt against stored hash. If
//     it matches, the user is authenticated AND we have plaintext
//     in memory. Re-hash with argon2id, save.
//  2. New registrations always use HashPassword (argon2id).
//  3. Eventually all active users have argon2id hashes; the
//     bcrypt path can be removed.
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/ubgo/crypt"
)

// fakeUser stands in for a User row.
type fakeUser struct {
	Email        string
	PasswordHash string // bcrypt or argon2id
}

// loginAndRehash demonstrates the migration pattern.
func loginAndRehash(u *fakeUser, plaintext string) error {
	// Determine the hash format.
	switch {
	case strings.HasPrefix(u.PasswordHash, "$2"):
		// bcrypt (legacy).
		ok, err := crypt.VerifyPasswordBcrypt(plaintext, u.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("invalid credentials")
		}
		// Successful bcrypt verify: re-hash with argon2id.
		newHash, err := crypt.HashPassword(plaintext)
		if err != nil {
			return err
		}
		u.PasswordHash = newHash
		fmt.Printf("  rehashed %s from bcrypt to argon2id\n", u.Email)
		return nil

	case strings.HasPrefix(u.PasswordHash, "$argon2"):
		ok, err := crypt.VerifyPassword(plaintext, u.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("invalid credentials")
		}
		return nil

	default:
		return fmt.Errorf("unknown password hash format")
	}
}

func main() {
	// Setup: simulate a legacy user with a bcrypt hash.
	bcryptHash, err := crypt.HashPasswordBcrypt("correct-horse-battery-staple", crypt.DefaultBcryptCost)
	if err != nil {
		log.Fatal(err)
	}
	user := &fakeUser{
		Email:        "alice@example.com",
		PasswordHash: bcryptHash,
	}
	fmt.Printf("user before login: hash starts with %s\n\n", user.PasswordHash[:7])

	// First login: bcrypt verify, then auto-rehash.
	if err := loginAndRehash(user, "correct-horse-battery-staple"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("user after login:  hash starts with %s\n\n", user.PasswordHash[:18])

	// Subsequent logins: argon2id-only path.
	if err := loginAndRehash(user, "correct-horse-battery-staple"); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("subsequent login: argon2id verify ok\n")

	// Wrong password is still rejected.
	if err := loginAndRehash(user, "wrong"); err != nil {
		fmt.Printf("wrong password: %v\n", err)
	}
}
