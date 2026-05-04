# Benchmarks

Real numbers from `go test -bench=. -benchmem` on commodity hardware. Re-run on your target hardware before making capacity decisions — AEAD performance is dominated by AES-NI on x86_64 and ARMv8.

## How to run

```sh
go test -bench=. -benchmem -short ./...
# or
task bench
```

## Reference numbers

Hardware: Apple M1, macOS 14, Go 1.25.

```
BenchmarkSeal_64B-10                 1,261,357 ops/sec   1102 ns/op    58 MB/s    6 allocs/op
BenchmarkSeal_1KB-10                   534,183 ops/sec   2091 ns/op   490 MB/s    6 allocs/op
BenchmarkSeal_16KB-10                   45,747 ops/sec  22739 ns/op   721 MB/s    6 allocs/op
BenchmarkSeal_1MB-10                     1,143 ops/sec    1.07 ms/op  977 MB/s    6 allocs/op

BenchmarkOpen_64B-10                 2,075,781 ops/sec    568 ns/op   113 MB/s    4 allocs/op
BenchmarkOpen_1KB-10                   863,071 ops/sec   1582 ns/op   647 MB/s    4 allocs/op

BenchmarkSealer_Seal_1KB-10            712,826 ops/sec   1781 ns/op   575 MB/s    4 allocs/op
BenchmarkSealer_Open_1KB-10          1,000,000 ops/sec   1058 ns/op   968 MB/s    2 allocs/op

BenchmarkSign_64B-10                 3,144,964 ops/sec    399 ns/op   160 MB/s    6 allocs/op
BenchmarkSign_1KB-10                 1,522,695 ops/sec    808 ns/op  1267 MB/s    6 allocs/op
BenchmarkVerify_1KB-10               1,367,116 ops/sec    808 ns/op  1268 MB/s    6 allocs/op

BenchmarkRandomToken_24-10           3,736,100 ops/sec    329 ns/op
BenchmarkRandomBytes_32-10           4,072,074 ops/sec    289 ns/op

BenchmarkConstantTimeEqual_32B-10  100,000,000 ops/sec     12 ns/op
BenchmarkEncryptCBC_1KB-10             336,502 ops/sec   3547 ns/op   289 MB/s    6 allocs/op
```

`HashPassword` and `VerifyPassword` (argon2id) are intentionally slow — that's the entire point. Each call takes ~50 ms on the same hardware. Don't try to make them faster; raise rate limits instead.

## What this means in practice

- **Encrypt-at-rest, per-row:** at ~500k ops/sec for 1KB rows, you're not bottlenecked on crypto unless you're doing >100k DB writes/sec on a single core.
- **Webhook signing:** ~1.5M sign ops/sec. Effectively free.
- **API key generation:** ~3.7M tokens/sec. Effectively free.
- **Session decryption per request:** ~860k ops/sec for 1KB sessions. A typical web service maxes out elsewhere first (network, DB) by 2+ orders of magnitude.

## Sealer vs package-level Seal/Open

`Sealer` is faster than the package-level functions for repeated operations because the `cipher.AEAD` is built once. The difference is small (~15-20%) but measurable. Use `Sealer` in long-lived services; use the package-level form in scripts and one-shot calls.

## Comparison vs TypeScript counterpart

The Node/V8 sibling at `@ubgo/crypt` is roughly 3-5x slower per op due to JS overhead, but still in the same order of magnitude. Both implementations call the same hardware AES-NI under the hood. See `BENCHMARKS.md` in the [TS repo](https://github.com/ubgo/crypt-ts) for matching numbers.

## Allocations

Most operations allocate 4-6 small buffers per call. Steady-state allocations per AEAD operation are bounded — there's no growth path that scales with throughput. The allocations are mostly small input/output buffers; reducing them further would require an opaque API that's harder to misuse, which we declined.

## When crypto becomes the bottleneck

In our usage profile (saas web services), **never**. We've never seen a profile where crypt operations show up above network or DB time. If you see one:

1. Verify you're using `Sealer` for repeated ops.
2. Check that argon2 is gated to login paths only — never on every request.
3. Consider if any encryption can be cached (but tread carefully — caching plaintext defeats the encryption).
4. Open an issue with a profile and we'll look.
