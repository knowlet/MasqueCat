# MasqueCat benchmarks

This document describes the microbenchmarks in `masquecat_benchmark_test.go`, how to reproduce them, and what the numbers do and do not measure.

## Scope

The current benchmark suite measures CPU and allocation costs in the MasqueCat userspace framing and token paths:

- `BenchmarkEncodeMasquePacket`: builds the MasqueCat datagram envelope for 64, 256, 1200, 1400, and 4096-byte payloads.
- `BenchmarkDecodeMasquePacket`: parses the fixed MasqueCat header and returns a slice pointing at the payload.
- `BenchmarkMasqueTargetRoundTrip`: formats and parses the virtual CONNECT-UDP peer target.
- `BenchmarkMasqueConnBlobRoundTrip`: serializes and parses the `mc...` connection token.

These are microbenchmarks. They intentionally do **not** include WireGuard encryption, QUIC packet protection, HTTP/3 framing below the MasqueCat payload, kernel UDP syscalls, relay scheduling, network RTT, packet loss, congestion control, MTU fragmentation, or application traffic. The reported `MB/s` for packet encode/decode is therefore a memory/framing rate, **not tunnel throughput**.

## Running locally

Run the same benchmark set used by CI:

```sh
go test -run '^$' \
  -bench 'Benchmark(Encode|Decode)MasquePacket|BenchmarkMasque(Target|ConnBlob)' \
  -benchmem \
  -benchtime=100ms \
  -count=1 .
```

For more stable numbers during optimization work, use a longer run and multiple samples:

```sh
go test -run '^$' \
  -bench 'Benchmark(Encode|Decode)MasquePacket|BenchmarkMasque(Target|ConnBlob)' \
  -benchmem \
  -benchtime=1s \
  -count=10 . > before.txt
```

After a change, capture `after.txt` with the same machine, Go version, power profile, and benchmark arguments. `benchstat` can then be used to compare the two sample sets. Do not compare absolute `ns/op` values from different CPUs as if they were regressions.

## CI reference result

The following result is from GitHub Actions run `33364925642`, using Go 1.27.0 on Linux/amd64 with an AMD EPYC 7763 runner. CI uses a short `100ms` benchmark duration as a smoke/regression signal rather than a statistically rigorous performance experiment.

| Benchmark | ns/op | MB/s | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: |
| Encode 64 B | 66.59 | 961.12 | 144 | 1 |
| Encode 256 B | 139.0 | 1842.00 | 352 | 1 |
| Encode 1200 B | 413.5 | 2902.24 | 1280 | 1 |
| Encode 1400 B | 479.4 | 2920.32 | 1536 | 1 |
| Encode 4096 B | 1120 | 3658.42 | 4864 | 1 |
| Decode 64 B | 32.63 | 1961.20 | 0 | 0 |
| Decode 256 B | 32.54 | 7867.43 | 0 | 0 |
| Decode 1200 B | 32.49 | 36934.35 | 0 | 0 |
| Decode 1400 B | 32.49 | 43085.24 | 0 | 0 |
| Decode 4096 B | 32.48 | 126118.99 | 0 | 0 |
| Target round-trip | 99.62 | - | 0 | 0 |
| Connection-token round-trip | 4710 | - | 2413 | 14 |

The increasing decode `MB/s` is an artifact of `SetBytes(payloadSize)` combined with a decoder whose work is almost independent of payload size: it validates a one-byte version, reconstructs two fixed 32-byte node keys, and slices the remaining payload without copying it.

## Current hot paths

### Packet encode

`encodeMasquePacket` currently performs one allocation per datagram and copies the payload into a new buffer. For a typical 1200-byte payload, the CI reference is:

```text
413.5 ns/op
1280 B/op
1 alloc/op
```

This is the clearest framing-level optimization candidate. A reusable or pool-backed buffer could remove the allocation, but buffer ownership becomes important because the encoded slice crosses packet-transport boundaries. Any pooling change must be verified against concurrent forwarding and the actual QUIC/H3 send lifecycle before buffers are reused.

### Packet decode

`decodeMasquePacket` is zero-allocation in the benchmark. It copies only the two fixed-size key values and returns the payload as a slice of the input datagram. That keeps decode cost effectively constant across payload sizes.

### Connection token

The `mc...` token round-trip is much heavier than packet framing (`4710 ns/op`, `2413 B/op`, `14 allocs/op` in the reference run), but it is a control-plane/startup operation rather than a per-packet hot path. It should not be optimized ahead of the datagram path without profiling evidence.

## CI policy

The `benchmark-smoke` job is intended to answer two questions:

1. Do all benchmark targets still compile and execute?
2. Did a change cause an obvious allocation or order-of-magnitude performance regression?

CI does not currently enforce hard numeric thresholds because hosted-runner variance makes small `ns/op` limits brittle. If benchmark regression gating is added later, prefer repeated samples plus `benchstat`, and gate only on changes large enough to exceed normal runner variance.

## Next benchmark layers

Before making performance claims about MasqueCat as a tunnel, add benchmarks in layers:

1. in-process `streamForwarder` with a fake datagram stream, including concurrent sends;
2. loopback QUIC + HTTP/3 CONNECT-UDP throughput and packet rate;
3. WireGuard-over-MASQUE loopback with real encryption and netstack traffic;
4. direct and relay end-to-end tests with fixed RTT/loss using a network emulator;
5. MTU/fragmentation and mixed TCP/UDP application workloads.

Report packet rate, goodput, CPU time, allocations, latency percentiles, and loss/retransmission behavior separately. A single throughput number is not sufficient to characterize the transport.
