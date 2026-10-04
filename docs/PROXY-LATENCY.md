# Proxy-added latency of `toolgate wrap`

Design success criterion: the latency `toolgate wrap` adds to a tool call on
the light path (`evaluate_tool_call` on an egress rule, plus the `rules_mcp`
and `pii` detectors on every result, plus one audit row per call), measured
as the same 1,000 `tools/call` round-trips against a fake echo server,
wrapped and unwrapped, with 1 KB and 100 KB results. Target: p99 added under
5 ms at 1 KB. The 100 KB figure is reported, not gated.

Method: [`scripts/benchmark_proxy_latency.py`](../scripts/benchmark_proxy_latency.py).
Each call waits for its reply before the next is sent, as a host does; 50
warm-up calls per mode are discarded; time is wall-clock from writing the
request to reading the whole reply line. "Added" is the difference of the two
runs' percentiles, not a percentile of per-call differences: the runs are
separate. It is what a user sees, namely how much slower the p99 call gets.

## Windows dev machine, 2026-10-03

Windows 11 (AMD64), Python 3.11.15, 1,000 calls per mode.

| Result size | Mode | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|
| 1 KB | direct | 0.039 | 0.068 | 0.104 |
| 1 KB | wrapped | 1.079 | 1.424 | 1.830 |
| 1 KB | **added** | **1.040** | **1.356** | **1.726** |
| 100 KB | direct | 0.355 | 0.461 | 0.573 |
| 100 KB | wrapped | 43.123 | 46.387 | 52.677 |
| 100 KB | **added** | **42.768** | **45.926** | **52.103** |

**Target met at 1 KB: p99 added 1.73 ms against a 5 ms budget.**

**At 100 KB the cost is the detectors, not the proxy.** Profiled in-process on
the same 100 KB text: `rules_mcp` takes a median 24.5 ms and `pii` 16.8 ms,
each scanning the raw and the canonicalised text (`detectors/normalise.py`),
and the whole server-line decision 40.7 ms. That leaves about 2 ms for the
proxy's own work (framing, two thread hops for stdio, the audit row). Detector
cost grows with the size of the result, at roughly 0.4 ms per KB here; the
0.02-0.03 ms per result in [`LATENCY-BENCHMARK.md`](LATENCY-BENCHMARK.md) are
for that benchmark's much shorter results. A server whose results are large
pays for the PII and rule scan on each, in front of every line behind it
(each direction is processed in order, design D14). A policy with no
redaction and no injection detectors skips that cost entirely.

Not measured yet: the same run on the ubuntu CI runner, which the design also
asks for.
