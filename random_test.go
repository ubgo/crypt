package crypt

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRandomBytes_Length(t *testing.T) {
	for _, n := range []int{1, 8, 16, 32, 64, 256} {
		b, err := RandomBytes(n)
		if err != nil {
			t.Fatalf("RandomBytes(%d): %v", n, err)
		}
		if len(b) != n {
			t.Errorf("RandomBytes(%d): got len=%d", n, len(b))
		}
	}
}

func TestRandomBytes_Distinct(t *testing.T) {
	a, _ := RandomBytes(32)
	b, _ := RandomBytes(32)
	if string(a) == string(b) {
		t.Errorf("two RandomBytes(32) calls returned identical output")
	}
}

func TestRandomBytes_RejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		if _, err := RandomBytes(n); err == nil {
			t.Errorf("RandomBytes(%d): expected error", n)
		}
	}
}

func TestRandomToken_Length(t *testing.T) {
	cases := []struct {
		n    int
		want int // base64url-no-pad length = ceil(n*4/3)
	}{
		{1, 2},
		{8, 11},
		{16, 22},
		{24, 32},
		{32, 43},
	}
	for _, tc := range cases {
		s, err := RandomToken(tc.n)
		if err != nil {
			t.Fatalf("RandomToken(%d): %v", tc.n, err)
		}
		if len(s) != tc.want {
			t.Errorf("RandomToken(%d): got len=%d want=%d (%q)", tc.n, len(s), tc.want, s)
		}
	}
}

func TestRandomToken_URLSafeNoPadding(t *testing.T) {
	tok, _ := RandomToken(32)
	if strings.ContainsAny(tok, "+/=") {
		t.Errorf("RandomToken contains non-URL-safe chars: %q", tok)
	}
	// And it must decode cleanly as RawURL.
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Errorf("RandomToken not valid RawURLEncoding: %v", err)
	}
}

func TestRandomToken_Distinct(t *testing.T) {
	a, _ := RandomToken(16)
	b, _ := RandomToken(16)
	if a == b {
		t.Errorf("two RandomToken(16) calls returned identical output")
	}
}

func TestRandomHex_Length(t *testing.T) {
	for _, n := range []int{1, 8, 16, 32} {
		s, err := RandomHex(n)
		if err != nil {
			t.Fatalf("RandomHex(%d): %v", n, err)
		}
		if len(s) != 2*n {
			t.Errorf("RandomHex(%d): got len=%d want=%d", n, len(s), 2*n)
		}
		if _, err := hex.DecodeString(s); err != nil {
			t.Errorf("RandomHex(%d) not valid hex: %v", n, err)
		}
	}
}

func TestRandomHex_LowercaseOnly(t *testing.T) {
	s, _ := RandomHex(64)
	if strings.ContainsAny(s, "ABCDEF") {
		t.Errorf("RandomHex produced uppercase characters: %q", s)
	}
}

func TestRandomHex_Distinct(t *testing.T) {
	a, _ := RandomHex(16)
	b, _ := RandomHex(16)
	if a == b {
		t.Errorf("two RandomHex(16) calls returned identical output")
	}
}
