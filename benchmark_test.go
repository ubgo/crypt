package crypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// To run all benchmarks:
//   go test -bench=. -benchmem ./...
//
// To run a subset:
//   go test -bench=Seal -benchmem ./...

func benchKey(b *testing.B) []byte {
	b.Helper()
	k := make([]byte, AEADKeySize)
	if _, err := rand.Read(k); err != nil {
		b.Fatal(err)
	}
	return k
}

func BenchmarkSeal_64B(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 64)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Seal(key, pt, nil)
	}
}

func BenchmarkSeal_1KB(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Seal(key, pt, nil)
	}
}

func BenchmarkSeal_16KB(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 16*1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Seal(key, pt, nil)
	}
}

func BenchmarkSeal_1MB(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 1024*1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Seal(key, pt, nil)
	}
}

func BenchmarkOpen_64B(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 64)
	ct, _ := Seal(key, pt, nil)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Open(key, ct, nil)
	}
}

func BenchmarkOpen_1KB(b *testing.B) {
	key := benchKey(b)
	pt := bytes.Repeat([]byte{0x42}, 1024)
	ct, _ := Seal(key, pt, nil)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = Open(key, ct, nil)
	}
}

func BenchmarkSealer_Seal_1KB(b *testing.B) {
	key := benchKey(b)
	s, _ := NewSealer(key)
	pt := bytes.Repeat([]byte{0x42}, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = s.Seal(pt, nil)
	}
}

func BenchmarkSealer_Open_1KB(b *testing.B) {
	key := benchKey(b)
	s, _ := NewSealer(key)
	pt := bytes.Repeat([]byte{0x42}, 1024)
	ct, _ := s.Seal(pt, nil)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = s.Open(ct, nil)
	}
}

func BenchmarkSign_64B(b *testing.B) {
	key := benchKey(b)
	data := bytes.Repeat([]byte{0x42}, 64)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		_ = Sign(key, data)
	}
}

func BenchmarkSign_1KB(b *testing.B) {
	key := benchKey(b)
	data := bytes.Repeat([]byte{0x42}, 1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		_ = Sign(key, data)
	}
}

func BenchmarkVerify_1KB(b *testing.B) {
	key := benchKey(b)
	data := bytes.Repeat([]byte{0x42}, 1024)
	mac := Sign(key, data)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for range b.N {
		Verify(key, data, mac)
	}
}

func BenchmarkRandomToken_24(b *testing.B) {
	for range b.N {
		_, _ = RandomToken(24)
	}
}

func BenchmarkRandomBytes_32(b *testing.B) {
	for range b.N {
		_, _ = RandomBytes(32)
	}
}

func BenchmarkConstantTimeEqual_32B(b *testing.B) {
	a := bytes.Repeat([]byte{0x42}, 32)
	c := bytes.Repeat([]byte{0x42}, 32)
	b.ResetTimer()
	for range b.N {
		ConstantTimeEqual(a, c)
	}
}

// HashPassword is intentionally slow; bench with low N.
func BenchmarkHashPassword(b *testing.B) {
	if testing.Short() {
		b.Skip("argon2id is slow")
	}
	for range b.N {
		_, _ = HashPassword("correct horse battery staple")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	if testing.Short() {
		b.Skip("argon2id is slow")
	}
	hash, _ := HashPassword("correct horse battery staple")
	b.ResetTimer()
	for range b.N {
		_, _ = VerifyPassword("correct horse battery staple", hash)
	}
}

func BenchmarkEncryptCBC_1KB(b *testing.B) {
	key := bytes.Repeat([]byte{0x42}, 32)
	pt := bytes.Repeat([]byte{0x42}, 1024)
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for range b.N {
		_, _ = EncryptCBC(key, pt)
	}
}
