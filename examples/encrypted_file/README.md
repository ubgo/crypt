# Example: encrypted_file

Encrypt a file before writing it to disk / object storage.

## When to use this pattern

- Storing user-uploaded documents at rest, where the storage layer (S3, local FS, GCS) is not trusted to hold plaintext.
- Backup files that may be moved across systems.
- Application data exports where the recipient should be able to decrypt later but the transport is shared infra.

For multi-GB files, use `SealStream` / `OpenStream` instead — see the [`streaming_file`](../streaming_file) example.

## Run

```sh
cd examples/encrypted_file
go run .
```

## What it does

1. Writes a 120-byte plaintext file to a temp directory.
2. Reads it, seals with `Sealer.Seal`, writes the ciphertext.
3. Reads ciphertext, opens, recovers the original.
4. Demonstrates AAD binding (`file:report-2026-05`) — opening with a different filename binding fails.

## Adapting to your code (S3 example)

```go
import "github.com/aws/aws-sdk-go-v2/service/s3"

func uploadEncrypted(ctx context.Context, sealer *crypt.Sealer, s3client *s3.Client, bucket, key string, body []byte) error {
    aad := []byte(fmt.Sprintf("s3:%s:%s", bucket, key))
    ct, err := sealer.Seal(body, aad)
    if err != nil {
        return err
    }
    _, err = s3client.PutObject(ctx, &s3.PutObjectInput{
        Bucket: &bucket,
        Key:    &key,
        Body:   strings.NewReader(ct),
    })
    return err
}

func downloadEncrypted(ctx context.Context, sealer *crypt.Sealer, s3client *s3.Client, bucket, key string) ([]byte, error) {
    out, err := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
    if err != nil {
        return nil, err
    }
    defer out.Body.Close()
    raw, err := io.ReadAll(out.Body)
    if err != nil {
        return nil, err
    }
    aad := []byte(fmt.Sprintf("s3:%s:%s", bucket, key))
    return sealer.Open(string(raw), aad)
}
```

The AAD = bucket+key binding ensures an attacker who copies a ciphertext to a different S3 path can't have it decrypted there.
