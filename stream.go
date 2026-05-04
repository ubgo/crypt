package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Streaming AEAD — chunked encryption for files too large to load
// into memory. Each chunk is independently sealed with a counter-
// derived nonce and a per-chunk authentication tag.
//
// Wire format on disk:
//
//	[magic:4 = "CRSV"][version:1=0x01][nonce_prefix:8]
//	repeated chunks:
//	  [chunk_len:4 (big-endian)][ciphertext+tag : chunk_len bytes]
//	final chunk has chunk_len with MSB set to indicate "last".
//
// Each chunk's nonce is constructed deterministically:
//   nonce = nonce_prefix || counter:4 (big-endian)
// where counter starts at 0 and increments per chunk. The "last
// chunk" marker (high bit on chunk_len) is also bound into AAD,
// preventing truncation attacks (an attacker cannot remove chunks
// from the end without detection).
//
// Use cases:
//   - Encrypting multi-GB files for upload to S3.
//   - Streaming logs to an encrypted sink.
//   - Backup archives.
//
// For small payloads (< 1 MB), use Seal — the overhead per chunk
// makes streaming wasteful.

const (
	streamMagic       = "CRSV"
	streamVersion     = byte(0x01)
	streamNoncePrefix = 8
	streamHeaderSize  = 4 + 1 + streamNoncePrefix // magic + version + prefix

	// DefaultStreamChunkSize is the default chunk size in bytes for
	// the streaming AEAD writer. 64 KiB balances throughput against
	// per-chunk overhead.
	DefaultStreamChunkSize = 64 * 1024

	// streamMaxChunkSize caps chunk size to keep the chunk_len uint32
	// well below the high-bit-as-last-flag boundary.
	streamMaxChunkSize = 1 << 30 // 1 GiB
)

// ErrTruncated is returned when the streaming opener finishes without
// seeing a final-chunk marker — likely an attacker truncated the file.
var ErrTruncated = errors.New("crypt: stream truncated, no final chunk marker")

// SealStream encrypts the input reader to the output writer in chunks
// of chunkSize bytes. Pass DefaultStreamChunkSize for chunkSize unless
// you have a specific reason. The output is self-describing — call
// OpenStream with the same key to decrypt.
//
// Errors are returned from r.Read(), w.Write(), or AEAD operations.
// The output is not seekable — callers wanting random access need a
// different design.
func SealStream(key []byte, r io.Reader, w io.Writer, chunkSize int) error {
	if len(key) != AEADKeySize {
		return fmt.Errorf("%w: stream requires %d-byte key; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}
	if chunkSize <= 0 || chunkSize > streamMaxChunkSize {
		return fmt.Errorf("crypt: chunkSize must be in (0, %d]; got %d", streamMaxChunkSize, chunkSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	noncePrefix := make([]byte, streamNoncePrefix)
	if _, err := io.ReadFull(rand.Reader, noncePrefix); err != nil {
		return err
	}

	// Header.
	if _, err := w.Write([]byte(streamMagic)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{streamVersion}); err != nil {
		return err
	}
	if _, err := w.Write(noncePrefix); err != nil {
		return err
	}

	buf := make([]byte, chunkSize)
	var counter uint32
	for {
		n, err := io.ReadFull(r, buf)
		isLast := false
		switch err {
		case nil:
			// full chunk read; not last
		case io.EOF, io.ErrUnexpectedEOF:
			isLast = true
		default:
			return err
		}

		nonce := makeStreamNonce(noncePrefix, counter)
		aad := streamAAD(counter, isLast)
		ct := gcm.Seal(nil, nonce, buf[:n], aad)

		var lenField [4]byte
		binary.BigEndian.PutUint32(lenField[:], uint32(len(ct)))
		if isLast {
			lenField[0] |= 0x80 // set high bit
		}
		if _, err := w.Write(lenField[:]); err != nil {
			return err
		}
		if _, err := w.Write(ct); err != nil {
			return err
		}

		counter++
		if isLast {
			return nil
		}
	}
}

// OpenStream decrypts a stream produced by SealStream. Plaintext is
// written to w as chunks are decrypted.
//
// Returns ErrTruncated if the stream ends without the last-chunk
// marker — strong evidence of truncation.
func OpenStream(key []byte, r io.Reader, w io.Writer) error {
	if len(key) != AEADKeySize {
		return fmt.Errorf("%w: stream requires %d-byte key; got %d", ErrInvalidKey, AEADKeySize, len(key))
	}

	header := make([]byte, streamHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("%w: header read: %v", ErrInvalidCiphertext, err)
	}
	if string(header[:4]) != streamMagic {
		return fmt.Errorf("%w: bad magic", ErrInvalidCiphertext)
	}
	if header[4] != streamVersion {
		return fmt.Errorf("%w: stream version 0x%02x", ErrUnsupportedVersion, header[4])
	}
	noncePrefix := header[5 : 5+streamNoncePrefix]

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var counter uint32
	for {
		var lenField [4]byte
		if _, err := io.ReadFull(r, lenField[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return ErrTruncated
			}
			return err
		}
		isLast := lenField[0]&0x80 != 0
		lenField[0] &= 0x7F
		ctLen := binary.BigEndian.Uint32(lenField[:])

		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("%w: chunk read: %v", ErrInvalidCiphertext, err)
		}

		nonce := makeStreamNonce(noncePrefix, counter)
		aad := streamAAD(counter, isLast)
		pt, err := gcm.Open(nil, nonce, ct, aad)
		if err != nil {
			return fmt.Errorf("%w: chunk %d: %v", ErrTampered, counter, err)
		}
		if _, err := w.Write(pt); err != nil {
			return err
		}
		counter++
		if isLast {
			return nil
		}
	}
}

func makeStreamNonce(prefix []byte, counter uint32) []byte {
	out := make([]byte, aeadNonceSize) // 12 bytes
	copy(out[:streamNoncePrefix], prefix)
	binary.BigEndian.PutUint32(out[streamNoncePrefix:], counter)
	return out
}

// streamAAD encodes the counter + last-chunk flag into a fixed-size
// AAD that the AEAD authenticates. This binds each chunk to its
// position and to whether it's the final chunk, preventing reorder
// and truncation attacks.
func streamAAD(counter uint32, last bool) []byte {
	out := make([]byte, 5)
	binary.BigEndian.PutUint32(out[:4], counter)
	if last {
		out[4] = 0x01
	}
	return out
}
