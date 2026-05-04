// Encrypted session cookie — the entire session lives inside the
// cookie, sealed with the server's key. Server-side state is not
// required.
//
// Pros vs a session-ID cookie pointing at a server-side store:
//   - Zero DB / Redis lookups per request.
//   - Scales horizontally without sticky sessions.
//
// Cons:
//   - Cookie size grows with payload — keep it small.
//   - Revocation requires either expiry or a server-side denylist.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"time"

	"github.com/ubgo/crypt"
)

const cookieName = "_session"

type sessionCookie struct {
	UserID    string `json:"u"`
	ExpiresAt int64  `json:"e"`
}

func setSession(w http.ResponseWriter, sealer *crypt.Sealer, userID string, ttl time.Duration) error {
	pt, err := json.Marshal(sessionCookie{
		UserID:    userID,
		ExpiresAt: time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		return err
	}
	value, err := sealer.Seal(pt, []byte("cookie-v1"))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    value,
		HttpOnly: true,
		// In production, set Secure: true and serve over HTTPS.
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
	})
	return nil
}

func getSession(r *http.Request, sealer *crypt.Sealer) (*sessionCookie, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil, fmt.Errorf("no session")
	}
	pt, err := sealer.Open(c.Value, []byte("cookie-v1"))
	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}
	var s sessionCookie
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, fmt.Errorf("invalid session")
	}
	if time.Now().Unix() >= s.ExpiresAt {
		return nil, fmt.Errorf("session expired")
	}
	return &s, nil
}

func main() {
	sealer, err := crypt.NewSealer([]byte("01234567890123456789012345678901"))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := setSession(w, sealer, "usr_42", time.Hour); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "logged in")
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		s, err := getSession(r, sealer)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "you are %s\n", s.UserID)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// 1. Login — server sets the cookie.
	resp, _ := client.Get(srv.URL + "/login")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Printf("GET /login → %d\n", resp.StatusCode)

	// 2. /me with the cookie.
	resp, _ = client.Get(srv.URL + "/me")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("GET /me        → %d %s", resp.StatusCode, body)

	// 3. /me without the cookie.
	resp, _ = http.Get(srv.URL + "/me")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("GET /me (none) → %d %s", resp.StatusCode, body)
}
