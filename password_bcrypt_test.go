package crypt

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordBcrypt_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("bcrypt is slow")
	}
	hash, err := HashPasswordBcrypt("correct horse battery staple", DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPasswordBcrypt("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("ok=%v err=%v", ok, err)
	}
}

func TestVerifyPasswordBcrypt_RejectsWrong(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	hash, _ := HashPasswordBcrypt("right", DefaultBcryptCost)
	ok, err := VerifyPasswordBcrypt("wrong", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Errorf("accepted wrong password")
	}
}

func TestVerifyPasswordBcrypt_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-bcrypt-hash",
		"$argon2id$v=19$m=65536,t=2,p=1$saltsalt$hashhash",
	}
	for _, c := range cases {
		ok, err := VerifyPasswordBcrypt("anything", c)
		if ok {
			t.Errorf("VerifyPasswordBcrypt(%q): unexpectedly accepted", c)
		}
		if !errors.Is(err, ErrInvalidPasswordHash) {
			t.Errorf("VerifyPasswordBcrypt(%q): err=%v want ErrInvalidPasswordHash", c, err)
		}
	}
}

func TestHashPasswordBcrypt_Rejects72PlusBytes(t *testing.T) {
	long := strings.Repeat("x", 73)
	if _, err := HashPasswordBcrypt(long, DefaultBcryptCost); err == nil {
		t.Errorf("expected error on 73-byte input")
	}
}

func TestHashPasswordBcrypt_RejectsBadCost(t *testing.T) {
	if _, err := HashPasswordBcrypt("x", 3); err == nil {
		t.Errorf("expected error on too-low cost")
	}
	if _, err := HashPasswordBcrypt("x", 32); err == nil {
		t.Errorf("expected error on too-high cost")
	}
}

func TestHashPasswordBcrypt_FormatStartsWithDollarTwo(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	hash, _ := HashPasswordBcrypt("x", bcryptMinForTest())
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("expected $2 prefix, got %q", hash)
	}
}

// bcryptMinForTest returns a low cost factor for fast tests.
func bcryptMinForTest() int { return 4 }
