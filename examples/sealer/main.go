// Example: application-wide bound-key Sealer injected via dependency.
//
// Pattern: at boot, validate the application key once and construct
// a single Sealer. Inject it into services that need encryption.
// Avoids re-validating the key, re-constructing AES blocks, and
// global mutable state.
package main

import (
	"fmt"
	"log"

	"github.com/ubgo/crypt"
)

// Service is a typical application component that needs encryption.
type Service struct {
	sealer *crypt.Sealer
}

func NewService(sealer *crypt.Sealer) *Service {
	return &Service{sealer: sealer}
}

func (s *Service) Encrypt(plaintext string) (string, error) {
	return s.sealer.Seal([]byte(plaintext), nil)
}

func (s *Service) Decrypt(ciphertext string) (string, error) {
	pt, err := s.sealer.Open(ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func main() {
	// 1. At boot: load and validate key.
	appKey := []byte("01234567890123456789012345678901")
	sealer, err := crypt.NewSealer(appKey)
	if err != nil {
		log.Fatalf("init sealer: %v", err)
	}

	// 2. Inject into services.
	svc := NewService(sealer)

	// 3. Use anywhere.
	ct, _ := svc.Encrypt("first")
	fmt.Println("encrypted first:", ct)

	pt, _ := svc.Decrypt(ct)
	fmt.Println("decrypted:      ", pt)

	ct, _ = svc.Encrypt("second")
	fmt.Println("encrypted second:", ct)

	// 4. Sealer is concurrent-safe — share across goroutines.
	done := make(chan struct{}, 3)
	for i := range 3 {
		go func(i int) {
			ct, _ := svc.Encrypt(fmt.Sprintf("from goroutine %d", i))
			pt, _ := svc.Decrypt(ct)
			fmt.Printf("goroutine %d -> %s\n", i, pt)
			done <- struct{}{}
		}(i)
	}
	for range 3 {
		<-done
	}
}
