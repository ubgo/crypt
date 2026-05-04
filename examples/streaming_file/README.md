# Example: streaming_file

Streaming AEAD for arbitrary-size files using `SealStream` / `OpenStream`. Each chunk is independently authenticated with a counter-derived nonce; truncation surfaces as `ErrTruncated`.

## When to use this pattern

- Multi-GB file uploads (e.g., S3 streaming uploads with PutObject body as a reader).
- Encrypted backup archives.
- Streaming logs to an encrypted sink.
- Anywhere you'd otherwise have to load the whole plaintext into memory before sealing.

For small payloads (< ~1 MB), use `Seal` directly — per-chunk overhead makes streaming wasteful.

## Run

```sh
cd examples/streaming_file
go run .
```

## What it does

1. Writes a 1 MB plaintext file.
2. Streams encrypts to a `.enc` file (default 64 KiB chunks).
3. Streams decrypts back, byte-for-byte equal to original.
4. Demonstrates truncation detection: drop the trailing chunk marker, `OpenStream` returns `ErrTruncated`.

## Wire format

```
[magic:"CRSV"][version:1=0x01][nonce_prefix:8]
repeated:
  [chunk_len:4 BE]    (high bit = "last chunk")
  [chunk_ciphertext]  (chunk_len bytes incl. tag)
```

Each chunk's nonce is `nonce_prefix || counter:4 BE`. AAD = `counter || isLast` — binds chunk position and final-flag, preventing reorder + truncation attacks.

## Adapting to your code

```go
// Stream-encrypt an S3 upload:
import "github.com/aws/aws-sdk-go-v2/feature/s3/manager"

reader, writer := io.Pipe()
go func() {
    defer writer.Close()
    if err := crypt.SealStream(key, srcFile, writer, crypt.DefaultStreamChunkSize); err != nil {
        log.Print(err)
    }
}()

uploader := manager.NewUploader(s3client)
_, err := uploader.Upload(ctx, &s3.PutObjectInput{
    Bucket: &bucket,
    Key:    &key,
    Body:   reader,
})
```

Decrypt path is symmetric — `s3.GetObject` body → `OpenStream` → consumer.

## Limitations

- Not seekable. To random-access encrypted chunks, use a different design (per-chunk index / per-block AEAD with a known offset scheme).
- Chunk size is a trade-off: bigger chunks = less per-chunk overhead but more memory; default 64 KiB is fine for most uses.
