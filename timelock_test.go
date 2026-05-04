package crypt

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func tokKey() []byte { return bytes.Repeat([]byte{0x42}, AEADKeySize) }

func TestIssueToken_VerifyOk(t *testing.T) {
	key := tokKey()
	tok, err := IssueToken(key, []byte("payload"), time.Hour, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := VerifyToken(key, tok, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "payload" {
		t.Errorf("got %q", pt)
	}
}

func TestIssueToken_RejectsZeroTTL(t *testing.T) {
	if _, err := IssueToken(tokKey(), []byte("x"), 0, nil); err == nil {
		t.Errorf("expected error on zero TTL")
	}
	if _, err := IssueToken(tokKey(), []byte("x"), -time.Second, nil); err == nil {
		t.Errorf("expected error on negative TTL")
	}
}

func TestVerifyToken_Expired(t *testing.T) {
	// Manually craft an expired token by sealing an expiry in the past.
	// We can't use IssueToken with a negative TTL — that's rejected.
	key := tokKey()
	// Seal a "wrapped" with expiry = now - 1h.
	expiry := time.Now().Add(-time.Hour).Unix()
	wrapped := make([]byte, 8+5)
	for i := 0; i < 8; i++ {
		wrapped[7-i] = byte(expiry >> (8 * i))
	}
	copy(wrapped[8:], "stale")
	tok, _ := Seal(key, wrapped, []byte("test"))

	if _, err := VerifyToken(key, tok, []byte("test")); !errors.Is(err, ErrExpired) {
		t.Errorf("got %v, want ErrExpired", err)
	}
}

func TestVerifyToken_WrongAAD(t *testing.T) {
	key := tokKey()
	tok, _ := IssueToken(key, []byte("payload"), time.Hour, []byte("ctx-1"))
	if _, err := VerifyToken(key, tok, []byte("ctx-2")); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered", err)
	}
}

func TestVerifyToken_WrongKey(t *testing.T) {
	tok, _ := IssueToken(tokKey(), []byte("payload"), time.Hour, nil)
	wrong := bytes.Repeat([]byte{0x77}, AEADKeySize)
	if _, err := VerifyToken(wrong, tok, nil); !errors.Is(err, ErrTampered) {
		t.Errorf("got %v, want ErrTampered", err)
	}
}

func TestVerifyToken_TamperedPayload(t *testing.T) {
	key := tokKey()
	tok, _ := IssueToken(key, []byte("payload"), time.Hour, nil)
	tampered := tok[:len(tok)-2] + "XX"
	if _, err := VerifyToken(key, tampered, nil); err == nil {
		t.Errorf("expected error on tampered token")
	}
}
