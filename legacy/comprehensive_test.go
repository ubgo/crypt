package legacy_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/crypt"
	"github.com/ubgo/crypt/legacy"
)

func TestOpenAuto_EmptyString(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x01}, 32)
	if _, err := legacy.OpenAuto(key, "", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_BadBase64NotHex(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x01}, 32)
	if _, err := legacy.OpenAuto(key, "***clearly-neither***", nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_HexButNotCBCAligned(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x01}, 32)
	// 16 bytes of IV + 1 byte body — not 16-aligned.
	bad := strings.Repeat("00", 17)
	if _, err := legacy.OpenAuto(key, bad, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_HexShorterThanIV(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x01}, 32)
	bad := strings.Repeat("00", 8) // 8 bytes < 16
	if _, err := legacy.OpenAuto(key, bad, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_AEADWithVersion0x01ButWrongKey(t *testing.T) {
	t.Parallel()
	good := bytes.Repeat([]byte{0x01}, 32)
	bad := bytes.Repeat([]byte{0x02}, 32)
	ct, _ := crypt.Seal(good, []byte("hello"), nil)
	if _, err := legacy.OpenAuto(bad, ct, nil); err == nil {
		t.Errorf("expected error decrypting with wrong key")
	}
}

func TestOpenAuto_AEADCoincidentalCBCFallthrough(t *testing.T) {
	t.Parallel()
	// Construct a base64 string that decodes to start with 0x01 but
	// is way too short for AEAD, thereby triggering the fall-through
	// to CBC detection. The CBC detection should also fail (too short).
	key := bytes.Repeat([]byte{0x01}, 32)
	too := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}) // 3 bytes < AEAD min
	if _, err := legacy.OpenAuto(key, too, nil); !errors.Is(err, crypt.ErrUnknownFormat) {
		t.Errorf("got %v, want ErrUnknownFormat", err)
	}
}

func TestOpenAuto_WithAADOnAEAD(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x01}, 32)
	aad := []byte("ctx")
	ct, _ := crypt.Seal(key, []byte("data"), aad)
	pt, err := legacy.OpenAuto(key, ct, aad)
	if err != nil {
		t.Fatalf("OpenAuto: %v", err)
	}
	if string(pt) != "data" {
		t.Errorf("got %q", pt)
	}
	// Wrong AAD should fail.
	if _, err := legacy.OpenAuto(key, ct, []byte("other")); err == nil {
		t.Errorf("expected error with wrong AAD")
	}
}

func TestOpenAuto_AllKeySizesForCBC(t *testing.T) {
	t.Parallel()
	for _, n := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{0x01}, n)
		ct, _ := crypt.EncryptCBC(key, []byte("payload"))
		pt, err := legacy.OpenAuto(key, ct, nil)
		if err != nil {
			t.Errorf("CBC key=%d: %v", n, err)
			continue
		}
		if string(pt) != "payload" {
			t.Errorf("CBC key=%d: got %q", n, pt)
		}
	}
}
