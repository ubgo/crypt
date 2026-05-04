// Constant-time API key authentication using only net/http (no
// framework). The server compares the incoming X-API-Key header to
// the configured value in constant time.
//
// Production sites typically store hashed API keys in a database and
// compare the hash; this example assumes a single static internal key
// (e.g., for service-to-service auth) loaded from config.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/ubgo/crypt"
)

// requireAPIKey wraps a handler with API-key auth. The expected key
// is bound at construction time.
func requireAPIKey(expected []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-API-Key")
		if !crypt.ConstantTimeEqual([]byte(got), expected) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	// In production: load from secrets manager or env var.
	expectedKey := []byte("internal-api-key-from-config")

	mux := http.NewServeMux()
	mux.HandleFunc("/internal/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := httptest.NewServer(requireAPIKey(expectedKey, mux))
	defer srv.Close()

	// Authorized request.
	req, _ := http.NewRequest("GET", srv.URL+"/internal/health", nil)
	req.Header.Set("X-API-Key", "internal-api-key-from-config")
	resp, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("with correct key:   %d %s", resp.StatusCode, body)

	// Unauthorized: wrong key.
	req, _ = http.NewRequest("GET", srv.URL+"/internal/health", nil)
	req.Header.Set("X-API-Key", "wrong")
	resp, _ = http.DefaultClient.Do(req)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("with wrong key:     %d %s", resp.StatusCode, body)

	// Unauthorized: missing header.
	resp, _ = http.Get(srv.URL + "/internal/health")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("with missing key:   %d %s", resp.StatusCode, body)

	_ = log.Default()
}
