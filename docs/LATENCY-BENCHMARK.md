# Latency benchmark (FR-13, FR-14, NFR-1, NFR-2)

Two measurements, both against the real reused weights (CPU, no GPU per
assumption A3): per-detector/fused latency on a sample of the real ingested
corpus (FR-13), and gate overhead across a real >=20-call agent chain
(FR-14). Mean and p95 in milliseconds throughout, warmup excluded --
`evaluation/experiment2/exp2_eval.py`'s own `latency_hf`/`latency_sklearn`
convention (`n_warm=10`), reused rather than invented (`src/llmshield_mcp/latency.py`).

**Verdict:** NFR-1 (~5ms rule/PII budget) is met with room to spare. NFR-2
(report honestly against a 100ms SME budget, even if missed) is missed by
roughly 2x on short text and by one to two orders of magnitude on realistic
fetched web content, because V3's `chunk_max` strategy scores every
overlapping window of long content and stays fully in the fused pipeline
even though it currently carries zero decision weight (`config/policy.yaml`
ships it `inert`, M5).

---

## 1. Per-detector and fused-pipeline latency

`scripts/benchmark_latency.py` against 50 items (10-item warmup) sampled at
random (seed 42) from the real ingested corpus (`corpus/payload_corpus.sqlite`
-- a realistic, benign-heavy mix, not a handful of hand-picked probes).

| Detector | mean (ms) | p95 (ms) | vs budget |
|---|---|---|---|
| `rules_mcp` | 0.02 | 0.03 | NFR-1 (~5ms): met, ~250x headroom |
| `rules_inj` | 0.03 | 0.04 | NFR-1: met |
| `pii` | 0.03 | 0.05 | NFR-1: met |
| `v0` | 2.24 | 3.13 | NFR-1: met, ~2x headroom |
| `v3` | 172.52 | 228.95 | NFR-2 (100ms): **missed, ~1.7x** |
| `guard` | 169.92 | 218.29 | NFR-2: **missed, ~1.7x** |
| **fused** (all 6 + `PolicyEngine.decide`) | **313.97** | **382.08** | NFR-2: **missed, ~3x** |

(`scan_normalised` column -- what the live gate actually calls. The raw
`.score()` column without the dual-scan pass is materially identical for
rules/PII and about 12ms faster for V3; see the script's own two-table output.)

**The two transformers are the entire cost.** Rules, PII and V0 combined add
under 3 ms; `PolicyEngine.decide()` itself is negligible (pure Python dict
lookups, no I/O). `guard` costs essentially what V3 costs -- unsurprising, as
both are DeBERTa-v3-base with a 512-token window -- so adding it roughly
doubles the fused figure.

**Shipping a classifier as `inert` does not save any of this.** An inert
detector still runs and is still scored on every intercepted tool result;
inert only means it does not affect the *decision*. That is precisely why the
policy profiles exist (`plan.md` 2.25, 2.26): the only way to stop paying for a
classifier is to leave it out of the policy file entirely, which is what
`config/policy.yaml` now does by default. The default profile pays 0.08 ms of
detector time; adding `guard` takes it to ~170 ms; the research profile with
V0+V3+guard pays ~345 ms.

*(Figures above are a fresh run including `guard`. An earlier run without it
reported V3 at 208.28 ms and fused at 215.03 ms; run-to-run variation on a busy
CPU is substantial, which is why the shapes -- transformers dominate, rules are
free -- matter more than the exact milliseconds.)*

## 2. Gate overhead across a real chain (FR-14)

Recorded with `mcp-shield run-agent --db chains/latency_run.sqlite --out
chains/latency_chain.json --model claude-haiku-4-5`, task: fetch 16 distinct
real URLs one at a time, then list and read the 4 sandbox files individually.
**25 tool calls** (>= 20, FR-14), all gated live by the fused pipeline as
`config/policy.yaml` then defined it -- rules + PII + V0 + V3. (`guard` did not
exist for this run, and the default profile no longer names V0/V3 at all; see
section 1.)

> **The fixture behind this section is no longer committed.** Recording a chain
> stores every tool result verbatim, so fetching 16 real URLs embedded CC BY-SA
> content from Wikipedia and MDN into a file in an MIT repository. It was
> removed rather than attributed — see
> [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md), and
> `tests/test_chain_licensing.py`, which stops another one being committed.
>
> The numbers below stand as a recorded measurement and are unaffected: they
> were computed from `chains/latency_run.sqlite`, which was never committed
> either (matching every other `*.sqlite` here). To re-derive them, re-record a
> chain with the command above against URLs you may redistribute, or against any
> URLs at all if you do not intend to commit the result.

| Call type | n | content (mean chars) | gate `latency_ms` mean / p95 | `roundtrip_ms` mean / p95 |
|---|---|---|---|---|
| `fetch` (real web pages) | 16 | 3,348 | **4,459 / 10,139** | 1,407 / 2,323 |
| filesystem (sandbox files) | 9 | 285 | 240 / 320 | 2.9 / 4.5 |

The filesystem numbers land close to section 1's per-item figures (short
text, single V3 window). The fetch numbers do not: real web pages are long
enough to push V3's `chunk_max` strategy across many overlapping windows,
and gate `latency_ms` scales with that window count -- one page reached
**13.1 seconds** in this run (`docs/M0-OBSERVATIONS.md` first observed this
shape at smoke-test scale, ~5.3s at ~1500 tokens; this is the same effect at
chain scale, on unscripted real content). For nine of the sixteen fetches,
gate latency **exceeded** the network round-trip time (`roundtrip_ms`) that
produced the content in the first place -- the gate becomes the dominant
cost, not the underlying tool call.

One fetched page's PII scanner fired for real (`fused_decision = redact` in
the log), the only non-`allow` decision in this run -- a genuine detection
on live content, not a synthetic probe.

---

## Reproduce

```
uv run python scripts/benchmark_latency.py

mcp-shield run-agent --task "..." --model claude-haiku-4-5 \
  --db chains/latency_run.sqlite --out chains/latency_chain.json
```

Both need the real reused weights (`config/models.yaml` /
`LLMSHIELD_MODELS_ROOT`) and, for the first, a corpus already produced by
`mcp-shield corpus-ingest`. Exact figures will vary run to run (model
non-determinism in which URLs/files get how many tool calls, CPU load,
network conditions for the live fetches); the shape -- rules/PII/V0 trivial,
V3 dominant and length-dependent, chunked scoring pushing gate latency past
network round-trip time on real content -- is the reproducible part.
