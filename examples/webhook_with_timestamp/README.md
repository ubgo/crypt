# Example: webhook_with_timestamp

Stripe-style webhook signing with a timestamp tolerance to defend against replay attacks.

## When to use this pattern

- Emitting webhooks where you want to prevent attackers from replaying captured-but-still-valid signed requests.
- Receiving webhooks from a partner (Stripe, GitHub, etc.) that uses this pattern.
- Any signed HTTP request where the captured payload should expire after a freshness window (~5 min).

## When the simpler [`sign_webhook`](../sign_webhook) is enough

If your transport already prevents replay (TLS-pinned with no caching, internal-only network, mutual auth) you don't need the timestamp dance. Just sign + verify the body. Use this example for partner-facing webhooks where the request might be captured and replayed minutes later.

## Run

```sh
cd examples/webhook_with_timestamp
go run .
```

## What it does

1. Signer builds the header `t=<unix-seconds>,v1=<hex-mac>` where the MAC is computed over `<unix-seconds>.<body>` (period-separated).
2. Verifier parses the header, checks (a) the MAC matches and (b) the timestamp is within the tolerance window (default 5 min).
3. Demonstrates rejection paths: timestamp 10 minutes old (replay), wrong secret, tampered body.

## Wire format (header)

```
X-Signature: t=1700000000,v1=<64-hex-char-mac>
```

The signed payload is `t.body` — concatenation of the timestamp string, a literal period, and the request body bytes. Including the timestamp in the signed payload ensures an attacker cannot just bump the `t=` field without invalidating the MAC.

## Adapting to your code

```go
const replayTolerance = 5 * time.Minute

func sendSignedWebhook(client *http.Client, url string, secret, body []byte) error {
    ts := strconv.FormatInt(time.Now().Unix(), 10)
    signed := append([]byte(ts+"."), body...)
    mac := crypt.Sign(secret, signed)

    req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
    req.Header.Set("X-Signature", fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(mac)))
    req.Header.Set("Content-Type", "application/json")
    _, err := client.Do(req)
    return err
}

func verifyIncomingWebhook(secret []byte, header string, body []byte) error {
    // Parse t=...,v1=...
    parts := strings.Split(header, ",")
    var ts, v1 string
    for _, p := range parts {
        switch {
        case strings.HasPrefix(p, "t="):
            ts = p[2:]
        case strings.HasPrefix(p, "v1="):
            v1 = p[3:]
        }
    }
    if ts == "" || v1 == "" {
        return errors.New("malformed signature header")
    }
    tsInt, err := strconv.ParseInt(ts, 10, 64)
    if err != nil { return errors.New("malformed timestamp") }
    if time.Since(time.Unix(tsInt, 0)) > replayTolerance {
        return errors.New("timestamp outside tolerance — possible replay")
    }
    mac, err := hex.DecodeString(v1)
    if err != nil { return errors.New("malformed mac") }
    signed := append([]byte(ts+"."), body...)
    if !crypt.Verify(secret, signed, mac) {
        return errors.New("signature mismatch")
    }
    return nil
}
```
