package crypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing using argon2id, the OWASP-recommended modern
// password hash function.
//
// Output is a self-contained PHC string of the form:
//
//	$argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
//
// - $argon2id  algorithm identifier
// - $v=19      argon2 version 1.3 (RFC 9106)
// - $m=N       memory cost in kibibytes
// - $t=N       time cost (iterations)
// - $p=N       parallelism
// - $<salt>    base64-no-pad random salt
// - $<hash>    base64-no-pad derived key
//
// VerifyPassword reads parameters from the stored string, so we can
// re-tune memory/time costs in future without breaking existing
// hashes.

// argon2id parameters. These are the OWASP-recommended values for
// "second" tier (interactive logins, server-side derivation):
//
//   - 64 MiB memory
//   - 2 iterations
//   - 1 lane of parallelism
//   - 16-byte salt
//   - 32-byte output
//
// Tuning guidance: increase m (memory) before t (iterations) when
// raising work. Memory cost is what makes argon2 GPU-resistant.
const (
	argonMemoryKiB  = 64 * 1024 // 64 MiB
	argonTimeCost   = 2
	argonParallel   = 1
	argonSaltLen    = 16
	argonKeyLen     = 32
	argonAlgo       = "argon2id"
	argonVersionTag = 19 // argon2.Version, but typed as const for the PHC string
)

// HashPassword hashes plaintext using argon2id with library-default
// parameters and returns a PHC-format string.
//
// The salt is randomly generated from crypto/rand on every call;
// hashing the same plaintext twice produces different output strings.
//
// Returns an error only on rare CSPRNG failure.
func HashPassword(plaintext string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("crypt: random salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(plaintext),
		salt,
		argonTimeCost,
		argonMemoryKiB,
		argonParallel,
		argonKeyLen,
	)

	return formatPHC(salt, hash), nil
}

// VerifyPassword constant-time compares plaintext against a stored
// PHC-format hash.
//
// Returns:
//   - (true, nil) on match
//   - (false, nil) on plaintext mismatch
//   - (false, ErrInvalidPasswordHash) on malformed stored hash
//
// Parameters are read from the stored string, so this works across
// future parameter tunings: stored hashes from older settings still
// verify correctly.
func VerifyPassword(plaintext, stored string) (bool, error) {
	salt, hash, params, err := parsePHC(stored)
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey(
		[]byte(plaintext),
		salt,
		params.timeCost,
		params.memoryKiB,
		params.parallel,
		uint32(len(hash)),
	)
	if subtle.ConstantTimeCompare(computed, hash) == 1 {
		return true, nil
	}
	return false, nil
}

// argon2Params describes the cost parameters extracted from a PHC
// string. Used for re-deriving the hash to compare.
type argon2Params struct {
	memoryKiB uint32
	timeCost  uint32
	parallel  uint8
}

// formatPHC composes a PHC-format string with library-default params.
func formatPHC(salt, hash []byte) string {
	enc := base64.RawStdEncoding
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonAlgo,
		argonVersionTag,
		argonMemoryKiB,
		argonTimeCost,
		argonParallel,
		enc.EncodeToString(salt),
		enc.EncodeToString(hash),
	)
}

// parsePHC parses a PHC-format string into salt, hash, and params.
func parsePHC(s string) (salt, hash []byte, params argon2Params, err error) {
	// Expected: $argon2id$v=19$m=65536,t=2,p=1$<salt>$<hash>
	// Split on '$': leading '' + 5 segments.
	parts := strings.Split(s, "$")
	if len(parts) != 6 {
		return nil, nil, params, fmt.Errorf("%w: expected 5 segments, got %d", ErrInvalidPasswordHash, len(parts)-1)
	}
	if parts[0] != "" {
		return nil, nil, params, fmt.Errorf("%w: missing leading '$'", ErrInvalidPasswordHash)
	}
	if parts[1] != argonAlgo {
		return nil, nil, params, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidPasswordHash, parts[1])
	}

	// Version: "v=N"
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil {
		return nil, nil, params, fmt.Errorf("%w: bad version %q", ErrInvalidPasswordHash, parts[2])
	}
	if ver != argonVersionTag {
		return nil, nil, params, fmt.Errorf("%w: unsupported version %d", ErrInvalidPasswordHash, ver)
	}

	// Cost params: "m=N,t=N,p=N"
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, params, fmt.Errorf("%w: bad params %q: %v", ErrInvalidPasswordHash, parts[3], err)
	}
	params = argon2Params{memoryKiB: m, timeCost: t, parallel: p}

	enc := base64.RawStdEncoding
	salt, err = enc.DecodeString(parts[4])
	if err != nil {
		return nil, nil, params, fmt.Errorf("%w: bad salt: %v", ErrInvalidPasswordHash, err)
	}
	hash, err = enc.DecodeString(parts[5])
	if err != nil {
		return nil, nil, params, fmt.Errorf("%w: bad hash: %v", ErrInvalidPasswordHash, err)
	}

	if len(salt) == 0 || len(hash) == 0 {
		return nil, nil, params, fmt.Errorf("%w: empty salt or hash", ErrInvalidPasswordHash)
	}

	return salt, hash, params, nil
}

// Sentinel guard so errors.Is works against ErrInvalidPasswordHash
// even when the error has been wrapped through %w.
var _ = errors.Is
