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

## Ubuntu CI runner, 2026-10-04

GitHub `ubuntu-latest` (Linux 6.17.0-1022-azure, x86_64; AMD EPYC 7763, 4 vCPUs,
16 GB), Python 3.11.17, 1,000 calls per mode, slim install. Recorded by the
[`Proxy latency`](../.github/workflows/benchmark.yml) workflow, run 37228240238
on pull request #3. One run on one shared runner: a sample, not a property of
Linux.

| Result size | Mode | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|
| 1 KB | direct | 0.069 | 0.085 | 0.093 |
| 1 KB | wrapped | 1.091 | 1.211 | 1.394 |
| 1 KB | **added** | **1.022** | **1.126** | **1.301** |
| 100 KB | direct | 0.468 | 0.526 | 0.544 |
| 100 KB | wrapped | 46.264 | 47.377 | 49.237 |
| 100 KB | **added** | **45.796** | **46.851** | **48.693** |

**Target met at 1 KB on ubuntu too: p99 added 1.30 ms against a 5 ms budget**,
within 0.5 ms of the Windows figure. At 100 KB the added p99 (48.7 ms) is close to
Windows (52.1 ms), consistent with the cost being the detectors' scan, which does
not depend on the operating system's pipes.

## Network mode, Windows dev machine, 2026-10-05

Same benchmark with `--network enforce` against `--network off`, alternating,
two runs each, 1,000 calls per mode. The fake server makes no HTTP requests,
so this is what network mode adds to the stdio path: the forward proxy running
beside the pump, and recording each call's destinations for the divergence
field. It is not the cost of a proxied connection.

| Run | network | 1 KB p99 added (ms) | 100 KB p99 added (ms) |
|---|---|---|---|
| 1 | off | 1.391 | 75.202 |
| 2 | enforce | 1.511 | 55.358 |
| 3 | off | 1.473 | 60.057 |
| 4 | enforce | 1.519 | 58.977 |

**At 1 KB, network mode adds 0.04-0.13 ms at p99**, inside the design's
criterion (within 1 ms of the mode off). At 100 KB the run-to-run spread
(55-75 ms) is larger than any difference between the modes, so no effect is
claimed there either way.

## Track D: cheaper detectors, Windows dev machine, 2026-10-08

Two changes, both required to leave every detection unchanged
([`tests/test_detector_prefilter.py`](../tests/test_detector_prefilter.py),
plus the existing rule, PII and golden-set suites, all passing):

- **Normalise once.** `normalise()` ran once per detector per result; it now
  runs once per result and is shared (`scan_normalised(..., canonical)`).
- **Literal prefilters.** Each `mcp` rule lists `requires`, words of which at
  least one must appear for its pattern to match; the rule is skipped when
  none does. The check runs on a fold of the text that maps the four
  non-ASCII characters Python's `re.IGNORECASE` matches to ASCII letters
  (I with dot, dotless i, long s, Kelvin sign; all code points checked by the
  test), so it cannot hide a case-insensitive match. The PII email pattern is
  skipped when the text has no `@`.

**Detector cost for one 100 KB result** (`rules_mcp` + `pii`, median of 15,
two runs, same process, old path versus new path):

| Text | Old | New | Saved |
|---|---|---|---|
| benchmark filler ("the quick brown fox ...") | 49.7-50.1 ms | 19.8-21.2 ms | 57-60 % |
| the repository's docs (prose) | 66.7-67.4 ms | 61.2-62.6 ms | 6-9 % |

The filler is the favourable case: it contains none of the rules' required
words, so every `mcp` rule is skipped. Ordinary prose usually contains some
("response", "model", "http"), so most rules still run and the saving is
mostly the shared normalisation.

**Proxy benchmark** (the method above, 1,000 calls, network off, two runs):

| Result size | p50 added | p95 added | p99 added |
|---|---|---|---|
| 1 KB | 1.002-1.022 ms | 1.321-1.387 ms | 1.458-1.904 ms |
| 100 KB | 21.771-21.797 ms | 25.359-25.397 ms | 30.195-30.318 ms |

At 100 KB, p99 added fell from 52.1 ms (2026-10-03) and 55-75 ms
(2026-10-05) to about 30 ms on this text. At 1 KB nothing changed beyond run
to run noise, as expected: the detectors were never the cost there.
