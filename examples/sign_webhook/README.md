# Example: sign_webhook

Sign and verify webhook payloads with HMAC-SHA256.

## When to use this pattern

- Emitting webhooks to partner systems that need to verify the request came from you.
- Receiving webhooks from third-party services (Stripe, GitHub, etc.) that sign their requests.
- Server-to-server calls within your own infrastructure where authenticity matters but encryption isn't needed.

## Run

```sh
cd examples/sign_webhook
go run .
```

## What it does

1. Computes HMAC-SHA256 over a JSON request body using a shared secret.
2. Encodes the MAC as base64 for transmission as a header.
3. Verifies the MAC on the receiving side using the same secret.
4. Demonstrates that body tampering rejects.
5. Demonstrates that wrong-key rejection.

## HTTP integration

Outgoing (Gin example):

```go
func (h *Handler) sendWebhook(ctx context.Context, partner *PartnerApp, event Event) error {
    body, _ := json.Marshal(event)
    mac := crypt.Sign(partner.WebhookSecret, body)

    req, _ := http.NewRequestWithContext(ctx, "POST", partner.WebhookURL, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(mac))
    req.Header.Set("X-Signature-Algorithm", "hmac-sha256")

    resp, err := h.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    return nil
}
```

Incoming verification middleware:

```go
func WebhookVerify(secret []byte) gin.HandlerFunc {
    return func(c *gin.Context) {
        body, err := io.ReadAll(c.Request.Body)
        if err != nil {
            c.AbortWithStatusJSON(400, gin.H{"error": "read body"})
            return
        }
        c.Request.Body = io.NopCloser(bytes.NewReader(body))

        sig := c.GetHeader("X-Signature")
        mac, err := base64.StdEncoding.DecodeString(sig)
        if err != nil || !crypt.Verify(secret, body, mac) {
            c.AbortWithStatusJSON(401, gin.H{"error": "invalid signature"})
            return
        }
        c.Next()
    }
}
```

## Why constant-time?

`crypt.Verify` uses a constant-time comparison internally. Naive byte comparison short-circuits at the first mismatch, leaking timing information that an attacker can exploit to recover the MAC byte-by-byte.

## Why share the body?

The MAC is computed over the *exact bytes* the verifier will see. If you re-marshal the body between signing and sending, the MAC may not match (whitespace, key order, etc. can differ). Always sign the bytes you actually transmit.
