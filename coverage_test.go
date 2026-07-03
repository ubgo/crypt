package crypt

// coverage_test.go targets the error branches that the feature-focused
// tests leave uncovered: crafted-malformed inputs (wrong versions, bad
// lengths, tampered bytes) and the CSPRNG-failure paths reached by
// swapping the package randReader for a failing reader.
//
// A handful of defensive branches remain intentionally uncovered because
// they are unreachable in practice: aes.NewCipher / cipher.NewGCM /
// chacha20poly1305.New after the key length has already been validated to
// 32 bytes (those constructors only fail on a wrong key length), and the
// pad() error return (pad never fails). Contorting the code to hit them
// would add no real assurance.

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// errBoom is the sentinel returned by the failing test doubles below.
var errBoom = errors.New("coverage_test: injected failure")

// failingReader always fails, exercising the "OS CSPRNG returned an
// error" branches that never fire in production.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, errBoom }

// partialRand yields `okBytes` bytes of real randomness, then fails.
// Used to fail the *second* CSPRNG read in a function (e.g. the nonce
// read in SealAsymmetric, after the ephemeral-key read succeeds).
type partialRand struct{ okBytes int }

func (r *partialRand) Read(p []byte) (int, error) {
	if r.okBytes <= 0 {
		return 0, errBoom
	}
	if len(p) > r.okBytes {
		p = p[:r.okBytes]
	}
	n, _ := cryptorand.Read(p)
	r.okBytes -= n
	return n, nil
}

// bytesThenErr serves a fixed prefix of bytes, then returns err. Used to
// feed OpenStream a valid header followed by a read failure or EOF.
type bytesThenErr struct {
	data []byte
	err  error
}

func (r *bytesThenErr) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

// failAfterWriter succeeds for `ok` writes, then fails — used to hit each
// individual w.Write error branch inside SealStream.
type failAfterWriter struct {
	ok  int
	buf bytes.Buffer
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.ok <= 0 {
		return 0, errBoom
	}
	w.ok--
	return w.buf.Write(p)
}

// swapRand temporarily replaces the package CSPRNG source and restores it
// via t.Cleanup. Callers must NOT run in parallel — randReader is global.
func swapRand(t *testing.T, r io.Reader) {
	t.Helper()
	prev := randReader
	randReader = r
	t.Cleanup(func() { randReader = prev })
}

func key32(t *testing.T) []byte {
	t.Helper()
	k, err := RandomBytes(AEADKeySize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return k
}

// TestRNGFailure exercises every CSPRNG-failure branch by injecting a
// failing reader. These subtests share global state (randReader) and
// therefore must run sequentially — no t.Parallel().
func TestRNGFailure(t *testing.T) {
	k := key32(t)

	t.Run("RandomBytes", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := RandomBytes(16); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("RandomToken", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := RandomToken(16); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("RandomHex", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := RandomHex(16); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("Seal", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := Seal(k, []byte("x"), nil); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("Sealer.Seal", func(t *testing.T) {
		s, err := NewSealer(k)
		if err != nil {
			t.Fatal(err)
		}
		swapRand(t, failingReader{})
		if _, err := s.Seal([]byte("x"), nil); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("EncryptCBC", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := EncryptCBC(k[:16], []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("SealChaCha20", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := SealChaCha20(k, []byte("x"), nil); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("GenerateKeyPair", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, _, err := GenerateKeyPair(); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("SealAsymmetric_keygen", func(t *testing.T) {
		// Full failure: the ephemeral keygen read fails first.
		pub, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		swapRand(t, failingReader{})
		if _, err := SealAsymmetric(pub, []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("SealAsymmetric_nonce", func(t *testing.T) {
		// 32 good bytes for the ephemeral key, then the nonce read fails.
		pub, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		swapRand(t, &partialRand{okBytes: X25519KeySize})
		if _, err := SealAsymmetric(pub, []byte("x")); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("SealStream", func(t *testing.T) {
		swapRand(t, failingReader{})
		err := SealStream(k, strings.NewReader("x"), &bytes.Buffer{}, DefaultStreamChunkSize)
		if err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("GenerateEd25519", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, _, err := GenerateEd25519(); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("KeyRing.Seal", func(t *testing.T) {
		ring, err := NewKeyRing("v1", k)
		if err != nil {
			t.Fatal(err)
		}
		swapRand(t, failingReader{})
		if _, err := ring.Seal([]byte("x"), nil); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("HashPassword", func(t *testing.T) {
		swapRand(t, failingReader{})
		if _, err := HashPassword("pw"); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("EnvelopeSealer.Seal_dek_rng", func(t *testing.T) {
		kms := NewStaticKMS()
		if err := kms.AddKey("k", k); err != nil {
			t.Fatal(err)
		}
		env := NewEnvelopeSealer(kms, "k")
		swapRand(t, failingReader{}) // StaticKMS.GenerateDataKey → RandomBytes fails
		if _, err := env.Seal(context.Background(), []byte("x"), nil); err == nil {
			t.Fatal("want error")
		}
	})
}

func TestChaCha20_ErrorBranches(t *testing.T) {
	k := key32(t)

	if _, err := OpenChaCha20(k[:5], "abc", nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad key: got %v", err)
	}
	if _, err := OpenChaCha20(k, "!!!not base64!!!", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad base64: got %v", err)
	}
	short := base64.RawURLEncoding.EncodeToString([]byte{0x02, 0x00, 0x00})
	if _, err := OpenChaCha20(k, short, nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("too short: got %v", err)
	}
	// Internal test-only sealer: wrong explicit nonce length.
	if _, err := sealChaCha20WithNonce(k, []byte("x"), nil, make([]byte, 5)); err == nil {
		t.Fatal("wrong nonce length: want error")
	}
}

func TestAsymmetric_ErrorBranches(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt to a low-order (all-zero) public key → ECDH fails.
	if _, err := SealAsymmetric(make([]byte, X25519KeySize), []byte("x")); err == nil {
		t.Fatal("low-order recipient: want error")
	}
	// Wrong recipient key length.
	if _, err := SealAsymmetric(make([]byte, 5), []byte("x")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad recipient len: got %v", err)
	}
	if _, err := OpenAsymmetric(make([]byte, 5), "abc"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad priv len: got %v", err)
	}
	if _, err := OpenAsymmetric(priv, "!!!bad!!!"); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad base64: got %v", err)
	}
	if _, err := OpenAsymmetric(priv, base64.RawURLEncoding.EncodeToString([]byte{0x05, 0x00})); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("too short: got %v", err)
	}

	minSize := 1 + X25519KeySize + aeadNonceSize + aeadTagSize
	// Wrong version byte.
	wrongVer := make([]byte, minSize)
	wrongVer[0] = 0x01
	if _, err := OpenAsymmetric(priv, base64.RawURLEncoding.EncodeToString(wrongVer)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("wrong version: got %v", err)
	}
	// Correct version, but low-order ephemeral pub (all zeros) → ECDH fails.
	lowOrder := make([]byte, minSize)
	lowOrder[0] = versionAsymmetricV1
	if _, err := OpenAsymmetric(priv, base64.RawURLEncoding.EncodeToString(lowOrder)); err == nil {
		t.Fatal("low-order ephemeral pub: want error")
	}
}

func TestKeyRing_ErrorBranches(t *testing.T) {
	kA := key32(t)
	kB := key32(t)

	if _, err := NewKeyRing("", kA); err == nil {
		t.Fatal("empty kid: want error")
	}
	if _, err := NewKeyRing(strings.Repeat("x", keyRingMaxKidLen+1), kA); err == nil {
		t.Fatal("oversized kid: want error")
	}
	if _, err := NewKeyRing("v1", kA[:5]); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad key len: got %v", err)
	}

	ring, err := NewKeyRing("v1", kA)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Add("v2", kB); err != nil {
		t.Fatal(err)
	}

	// v1 ciphertext produced with an unrelated key → no ring key opens it.
	// Exercises the kidsActiveFirst loop (>1 key) and openV1WithAEAD failure.
	foreign, err := Seal(key32(t), []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Open(foreign, nil); !errors.Is(err, ErrTampered) {
		t.Fatalf("v1 no-key: got %v", err)
	}

	// Crafted v3 frames.
	tooShort := func(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

	kidZero := make([]byte, aeadMinSize)
	kidZero[0] = VersionAEADv3
	kidZero[1] = 0 // kidLen 0 → invalid
	if _, err := ring.Open(tooShort(kidZero), nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("kidLen 0: got %v", err)
	}

	kidTooLong := make([]byte, aeadMinSize)
	kidTooLong[0] = VersionAEADv3
	kidTooLong[1] = keyRingMaxKidLen // valid kidLen, but frame too short to hold it + nonce + tag
	if _, err := ring.Open(tooShort(kidTooLong), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("short-after-kid: got %v", err)
	}

	unknownKid := make([]byte, 2+3+aeadNonceSize+aeadTagSize)
	unknownKid[0] = VersionAEADv3
	unknownKid[1] = 3
	copy(unknownKid[2:5], "zzz")
	if _, err := ring.Open(base64.RawURLEncoding.EncodeToString(unknownKid), nil); !errors.Is(err, ErrTampered) {
		t.Fatalf("unknown kid: got %v", err)
	}

	// Valid v3 frame, tampered tag → gcm.Open fails.
	ct, err := ring.Seal([]byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ct)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if _, err := ring.Open(base64.RawURLEncoding.EncodeToString(raw), nil); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered v3: got %v", err)
	}

	// Unsupported version byte.
	badVer := make([]byte, aeadMinSize)
	badVer[0] = 0x7F
	if _, err := ring.Open(base64.RawURLEncoding.EncodeToString(badVer), nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad version: got %v", err)
	}
}

// fakeKMS is a controllable KMS for exercising EnvelopeSealer error paths.
type fakeKMS struct {
	dek     []byte
	wrapped []byte
	genErr  error
	decErr  error
}

func (f *fakeKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return f.dek, f.wrapped, f.genErr
}
func (f *fakeKMS) Decrypt(context.Context, string, []byte) ([]byte, error) {
	return f.dek, f.decErr
}
func (f *fakeKMS) Encrypt(context.Context, string, []byte) ([]byte, error) {
	return f.wrapped, f.genErr
}

func TestEnvelope_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	k := key32(t)

	// GenerateDataKey succeeds but returns a bad-length DEK → inner Seal fails.
	badDEK := &fakeKMS{dek: []byte("too-short"), wrapped: []byte("w")}
	if _, err := NewEnvelopeSealer(badDEK, "k").Seal(ctx, []byte("x"), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad DEK: got %v", err)
	}

	// KMS GenerateDataKey error surfaces.
	genErr := &fakeKMS{genErr: errBoom}
	if _, err := NewEnvelopeSealer(genErr, "k").Seal(ctx, []byte("x"), nil); err == nil {
		t.Fatal("gen err: want error")
	}

	// Build a real envelope, then fail the unwrap.
	kms := NewStaticKMS()
	if err := kms.AddKey("k", k); err != nil {
		t.Fatal(err)
	}
	env := NewEnvelopeSealer(kms, "k")
	ct, err := env.Seal(ctx, []byte("payload"), nil)
	if err != nil {
		t.Fatal(err)
	}
	decErr := NewEnvelopeSealer(&fakeKMS{decErr: errBoom}, "k")
	if _, err := decErr.Open(ctx, ct, nil); err == nil {
		t.Fatal("decrypt err: want error")
	}

	// Malformed envelope frames.
	if _, err := env.Open(ctx, "!!!bad!!!", nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad base64: got %v", err)
	}
	if _, err := env.Open(ctx, base64.RawURLEncoding.EncodeToString([]byte{versionEnvelopeV1, 0x00}), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("short header: got %v", err)
	}
	wrongVer := make([]byte, 8)
	wrongVer[0] = 0x01
	if _, err := env.Open(ctx, base64.RawURLEncoding.EncodeToString(wrongVer), nil); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("wrong version: got %v", err)
	}
	// wrappedLen larger than the frame → ErrCiphertextTooShort.
	huge := make([]byte, 1+4+2)
	huge[0] = versionEnvelopeV1
	binary.BigEndian.PutUint32(huge[1:5], 1000)
	if _, err := env.Open(ctx, base64.RawURLEncoding.EncodeToString(huge), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("oversized wrappedLen: got %v", err)
	}
	// Regression: wrappedLen near math.MaxUint32 must NOT overflow the
	// bounds check and panic the slice. Pre-fix, "5+wrappedLen" wrapped
	// in uint32 to a tiny value, passed the guard, and raw[5:5+wrappedLen]
	// panicked with an out-of-range slice (attacker-triggerable DoS).
	overflow := make([]byte, 1+4+2)
	overflow[0] = versionEnvelopeV1
	binary.BigEndian.PutUint32(overflow[1:5], 0xFFFFFFFF)
	if _, err := env.Open(ctx, base64.RawURLEncoding.EncodeToString(overflow), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("overflow wrappedLen: want ErrCiphertextTooShort, got %v", err)
	}
}

func TestStream_ErrorBranches(t *testing.T) {
	k := key32(t)

	// SealStream key + chunkSize validation.
	if err := SealStream(k[:5], strings.NewReader("x"), &bytes.Buffer{}, 8); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad key: got %v", err)
	}
	if err := SealStream(k, strings.NewReader("x"), &bytes.Buffer{}, 0); err == nil {
		t.Fatal("bad chunkSize: want error")
	}

	// Fail each header/body write in turn.
	for _, ok := range []int{0, 1, 2, 3, 4} {
		w := &failAfterWriter{ok: ok}
		if err := SealStream(k, strings.NewReader("hello world"), w, 4); err == nil {
			t.Fatalf("write fail after %d writes: want error", ok)
		}
	}

	// r.Read returns a non-EOF error → SealStream's default branch.
	if err := SealStream(k, &bytesThenErr{err: errBoom}, &bytes.Buffer{}, 8); err == nil {
		t.Fatal("read fail: want error")
	}

	// OpenStream key validation.
	if err := OpenStream(k[:5], strings.NewReader("x"), &bytes.Buffer{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad key: got %v", err)
	}
	// Header too short.
	if err := OpenStream(k, strings.NewReader("CRSV"), &bytes.Buffer{}); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("short header: got %v", err)
	}
	// Bad magic.
	badMagic := append([]byte("XXXX"), append([]byte{streamVersion}, make([]byte, streamNoncePrefix)...)...)
	if err := OpenStream(k, bytes.NewReader(badMagic), &bytes.Buffer{}); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("bad magic: got %v", err)
	}
	// Bad version.
	badVer := append([]byte(streamMagic), append([]byte{0x02}, make([]byte, streamNoncePrefix)...)...)
	if err := OpenStream(k, bytes.NewReader(badVer), &bytes.Buffer{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("bad version: got %v", err)
	}

	validHeader := append([]byte(streamMagic), append([]byte{streamVersion}, make([]byte, streamNoncePrefix)...)...)
	// Valid header then EOF → ErrTruncated.
	if err := OpenStream(k, &bytesThenErr{data: append([]byte(nil), validHeader...), err: io.EOF}, &bytes.Buffer{}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: got %v", err)
	}
	// Valid header then a non-EOF read error on the length field.
	if err := OpenStream(k, &bytesThenErr{data: append([]byte(nil), validHeader...), err: errBoom}, &bytes.Buffer{}); err == nil {
		t.Fatal("lenField read fail: want error")
	}
	// Valid header + a length field claiming more bytes than provided.
	var lenField [4]byte
	binary.BigEndian.PutUint32(lenField[:], 100)
	shortBody := append(append([]byte(nil), validHeader...), lenField[:]...)
	shortBody = append(shortBody, 0x01, 0x02) // fewer than 100 bytes
	if err := OpenStream(k, bytes.NewReader(shortBody), &bytes.Buffer{}); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("short chunk body: got %v", err)
	}

	// Valid stream decrypted into a writer that fails on the first plaintext write.
	var sealed bytes.Buffer
	if err := SealStream(k, strings.NewReader("hello world"), &sealed, 4); err != nil {
		t.Fatal(err)
	}
	if err := OpenStream(k, bytes.NewReader(sealed.Bytes()), &failAfterWriter{ok: 0}); err == nil {
		t.Fatal("plaintext write fail: want error")
	}
}

func TestPassword_ErrorBranches(t *testing.T) {
	// parsePHC: 6 segments but non-empty leading part.
	bad := "x$argon2id$v=19$m=65536,t=2,p=1$" +
		base64.RawStdEncoding.EncodeToString([]byte("saltsaltsaltsalt")) + "$" +
		base64.RawStdEncoding.EncodeToString([]byte("hash"))
	if _, err := VerifyPassword("pw", bad); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("leading '$' missing: got %v", err)
	}
}

func TestBcrypt_ErrorBranches(t *testing.T) {
	// Empty / too-short hash → ErrHashTooShort branch.
	if ok, err := VerifyPasswordBcrypt("pw", ""); ok || !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("too short: ok=%v err=%v", ok, err)
	}
	// A well-formed-length hash with an unsupported version → the "other
	// errors" branch (not mismatch, not too-short).
	unsupported := "$3a$12$" + strings.Repeat("a", 53)
	if ok, err := VerifyPasswordBcrypt("pw", unsupported); ok || !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("unsupported version: ok=%v err=%v", ok, err)
	}
}

func TestDeriveKey_TooLong(t *testing.T) {
	// HKDF-SHA256 caps output at 255*32 = 8160 bytes; asking for more fails.
	if _, err := DeriveKey(key32(t), nil, []byte("info"), 8161); err == nil {
		t.Fatal("oversized length: want error")
	}
}

func TestVerifyToken_ShortPlaintext(t *testing.T) {
	k := key32(t)
	// A sealed payload shorter than the 8-byte expiry header.
	ct, err := Seal(k, []byte{1, 2, 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(k, ct, nil); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("short token plaintext: got %v", err)
	}
}

func TestIssueToken_Expired(t *testing.T) {
	// Guard: negative TTL is rejected up front.
	if _, err := IssueToken(key32(t), []byte("p"), -time.Second, nil); err == nil {
		t.Fatal("negative TTL: want error")
	}
}
