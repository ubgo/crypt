// Stripe-style webhook verification with a timestamp tolerance, to
// defend against replay attacks where an adversary captures a signed
// request and re-sends it later.
//
// The signed payload is `<unix-seconds>.<body>` rather than just the
// body. Verifier checks both: (a) the HMAC matches, and (b) the
// timestamp is within an acceptable freshness window (default 5
// minutes).
//
// Stripe documents this exact pattern at
// https://stripe.com/docs/webhooks/signatures.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/crypt"
)

// SignWebhook returns the signature header value, formatted as
// "t=<unix-seconds>,v1=<hex-mac>".
func SignWebhook(secret, body []byte, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	signed := []byte(ts + ".")
	signed = append(signed, body...)
	mac := crypt.Sign(secret, signed)
	return fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(mac))
}

// VerifyWebhook checks the signature and freshness. tolerance is the
// max allowed clock skew between signer and verifier; ~5 min is the
// usual choice.
func VerifyWebhook(secret, body []byte, header string, now time.Time, tolerance time.Duration) error {
	parts := strings.Split(header, ",")
	if len(parts) != 2 {
		return errors.New("malformed signature header")
	}
	var ts string
	var v1 string
	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "t="):
			ts = strings.TrimPrefix(p, "t=")
		case strings.HasPrefix(p, "v1="):
			v1 = strings.TrimPrefix(p, "v1=")
		}
	}
	if ts == "" || v1 == "" {
		return errors.New("malformed signature header")
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("malformed timestamp")
	}
	delta := now.Unix() - tsInt
	if delta < 0 {
		delta = -delta
	}
	if time.Duration(delta)*time.Second > tolerance {
		return errors.New("timestamp outside tolerance — possible replay")
	}

	mac, err := hex.DecodeString(v1)
	if err != nil {
		return errors.New("malformed mac")
	}
	signed := []byte(ts + ".")
	signed = append(signed, body...)
	if !crypt.Verify(secret, signed, mac) {
		return errors.New("signature mismatch")
	}
	return nil
}

func main() {
	secret := []byte("partner-webhook-secret")
	body := []byte(`{"event":"order.created","id":"ord_42"}`)

	now := time.Now()
	header := SignWebhook(secret, body, now)
	fmt.Printf("--- outgoing ---\nX-Signature: %s\nBody: %s\n\n", header, body)

	// Receiver verifies within the tolerance window.
	if err := VerifyWebhook(secret, body, header, now.Add(time.Second), 5*time.Minute); err != nil {
		fmt.Printf("verify within window: %v\n", err)
	} else {
		fmt.Printf("verify within window: ok\n")
	}

	// Replay attempt 10 minutes later.
	if err := VerifyWebhook(secret, body, header, now.Add(10*time.Minute), 5*time.Minute); err != nil {
		fmt.Printf("replay 10m later: %v\n", err)
	}

	// Wrong secret.
	if err := VerifyWebhook([]byte("wrong"), body, header, now, 5*time.Minute); err != nil {
		fmt.Printf("wrong secret: %v\n", err)
	}

	// Tampered body.
	tampered := []byte(`{"event":"order.created","id":"ord_99"}`)
	if err := VerifyWebhook(secret, tampered, header, now, 5*time.Minute); err != nil {
		fmt.Printf("tampered body: %v\n", err)
	}

	_ = log.Default()
}
