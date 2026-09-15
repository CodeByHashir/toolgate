# M12: Cross-Call / Session-Level Tool Security Correlation

## What M12 is

A **session-level observation layer** that sits alongside the existing per-call
gate (`gating/transport.py`) and produces two things:

1. **Call-level notes** appended to individual audit-log rows when a notable
   cross-call pattern is detected (hash recurrence with score divergence, rising
   injection signal).
2. **A session summary row** written to the decision log at session end, giving
   a reviewer a single narrative instead of 25 individual rows to scan.

M12 is **observation only**.  It never produces a Decision, never blocks a tool
result, and never escalates.  Every gating decision on any individual result is
made by `PolicyEngine` against that result alone and is completely unchanged.

---

## Motivation: the dilution attack

`docs/M0-OBSERVATIONS.md` section 1 documents the strongest measured effect in
this project: a known injection payload scoring P(injection)=0.998 in isolation
scores 0.052 when embedded in benign carrier text — **within a single 512-token
window, nothing truncated.**

An attacker exploiting this would send the same payload at progressively higher
dilution ratios across multiple calls, probing which ratio evades the per-call
detector.  A single-call gate cannot see this sequence; it inspects each result
independently.  The session accumulator can detect it because:

- The gate already computes a sha256 hash of every result (stored in
  `raw_result_hash`, never the raw content).
- The gate already logs `detector_scores` for every call.
- The accumulator observes both and flags when the same hash appears twice with
  diverging scores.

This is the one genuinely new threat that session-level visibility exposes.

---

## What M12 detects

### 1. Hash recurrence with score divergence (the dilution signal)

When the same `raw_result_hash` (sha256) appears twice in a session, the
accumulator computes the per-detector score delta.  If any detector's score
changed by ≥ 0.05 in absolute value, the second occurrence is annotated with:

```
session:hash_recurrence(first_at=3,v0:-0.750)
```

Meaning: the content that appeared at call index 3 reappeared now, and the V0
score dropped by 0.75 (the dilution direction).

### 2. Score trend across the session

If a detector's score rises or falls monotonically across the session (delta ≥
0.15, more than half consecutive pairs in the same direction), individual call
notes may include:

```
session:score_rising(v0)
```

### 3. Session summary row

At session end, one row is written with `outcome = "session_summary"` (distinct
from per-call `outcome = "result"`):

```json
{
  "total_calls": 25,
  "distinct_tools": 3,
  "distinct_servers": 2,
  "non_allow_calls": 1,
  "hash_recurrence_count": 3,
  "hash_divergence_count": 0,
  "score_trend_detectors": []
}
```

This row must be **excluded from per-call statistics** (FPR denominators,
latency averages): it is a reviewer aid, not a decision row.

---

## What M12 explicitly does NOT detect

| Pattern | Why not |
|---|---|
| `file_read → fetch` sequence | Indistinguishable from legitimate data-analysis workflows; FPR ≈ 100% on real chains |
| Enumeration of files | No semantic content visibility at the transport boundary |
| Content lineage (`output_N ⊆ input_N+1`) | Requires storing raw content cross-call — violates NFR-3/SEC-1 |
| Cross-session correlation | Out of scope; requires persistent cross-session store |
| Any blocking/escalation on sequence alone | M9 benchmark chain has cross-server reads+fetches by construction |

The M9 benchmark's `test_no_cross_server_fp_on_m9_chain` regression test
enforces this: the real 25-call chain must produce `hash_divergence_count == 0`
and `score_trend_detectors == []`.

---

## Architecture

```
Gate.observe_inbound()
  ├─ DecisionRecord written to DecisionLog  (unchanged: M0-M11 behaviour)
  └─ if accumulator:
       obs = accumulator.observe(record)      # pure in-memory, no I/O
       if obs.is_notable():
           log.update_note(cid, note)         # targeted SQLite UPDATE

session ends:
  accumulator.finish(log)                     # writes one summary row
```

### State bounds (NFR-5)

All accumulator state is strictly bounded regardless of session length:

| Field | Bound | Notes |
|---|---|---|
| `_call_sequence` | 100 entries (`MAX_SEQUENCE`) | Oldest dropped |
| `_score_history[det]` | 20 values (`SCORE_WINDOW`) per detector | Rolling window |
| `_hash_seen` | Unbounded count, but each entry is one int list | ~100 bytes per unique hash; 10,000 calls ≈ 2 MB max |
| `_server_counts`, `_tool_counts` | Bounded by number of distinct servers/tools | Typically < 10 |

### No I/O on the hot path

`observe()` is pure in-memory dict lookups and list appends.  The only I/O is
`finish()` (one SQLite write) and `update_note()` (one targeted UPDATE, only
when a notable observation occurs).

---

## Benchmark results

Measured with `scripts/benchmark_session.py` (same warmup convention as
`scripts/benchmark_latency.py`: 10-run warmup excluded, 200 timed runs):

| Operation | Mean (ms) | p95 (ms) |
|---|---|---|
| `observe()` per call | **0.005** | 0.005 |
| `finish()` (1 SQLite write, after 25 calls) | 2.57 | 3.03 |
| Full 25-call session (all observe + finish) | 2.70 | 3.27 |
| Per-call share of full session | **0.108** | — |

Reference from `docs/LATENCY-BENCHMARK.md`:

| Component | Mean (ms) |
|---|---|
| `rules_mcp` | 0.06 |
| `pii` | 0.07 |
| `v0` | 2.07 |
| `v3` | 208.28 |

The `observe()` overhead (0.005 ms) is ~12× below `rules_mcp` and is entirely
negligible relative to V3 (40,000×).  The `finish()` write (2.57 ms) is a
one-time cost per session, not per call.

---

## Usage

```python
from llmshield_mcp.gating import DecisionLog, Gate, SessionAccumulator

log = DecisionLog(path)
acc = SessionAccumulator()

# Pass to every Gate for this session alongside the shared log.
gate_fs = Gate("filesystem", log, accumulator=acc, ...)
gate_fetch = Gate("fetch", log, accumulator=acc, ...)

# ... run agent session ...

# At session end:
summary = acc.finish(log)
# summary.hash_divergence_count, .score_trend_detectors, etc.
```

When `accumulator=None` (the default), `Gate` behaviour is identical to M0-M11.

---

## Known limitations

### 1. Hash recurrence ≠ dilution attack in all cases

A legitimate repeated read (the same file read twice, or two different URLs
that serve identical content, as in the M9 chain where example.com and
example.org return the same "Example Domain" page) produces a recurrence with
zero score divergence.  The signal is thus recurrence **and** divergence.  A
reviewer should only act on a non-zero `hash_divergence_count` and a matching
`score_divergence` entry, not on `hash_recurrence_count` alone.

### 2. Score trend on zero-score benign sessions

All five detectors (rules_mcp, rules_inj, pii, v0, v3) score 0.0 on benign
tool results in normal operation.  A zero-score session produces no trend
signal (`delta = 0.0 < TREND_MIN_DELTA = 0.15`).  The trend signal is only
meaningful when at least one detector registers non-trivial scores across
multiple calls — which is the case precisely when there is injection activity.

### 3. Sequence not stored for adversarial reconstruction

`_call_sequence` is capped at 100 entries.  For very long sessions, the oldest
entries are dropped.  This means the accumulator's `first_seen_at` index for a
hash seen at call 0 and again at call 200 will still be correct (the hash table
stores the index, not the sequence slot), but the sequence itself is truncated.

### 4. No backward-fill for pre-accumulator sessions

Existing SQLite decision logs (M0-M11 runs) have no `session_summary` rows.
The accumulator is purely additive; old logs are unaffected.

### 5. update_note targets by correlation_id

`DecisionLog.update_note()` targets the most-recently written row for the given
`correlation_id`.  If two calls in the same session somehow share a
correlation_id (which the Gate's UUID generator makes astronomically unlikely),
only the more recent row gets the note.

---

## Tests

`tests/test_session.py` — 42 tests:

| Category | Tests | What they cover |
|---|---|---|
| Unit: `SessionAccumulator` | 16 | Call count, hash recurrence, score divergence, trend detection, boundedness, lifecycle guards |
| Unit: helpers | 6 | `_detect_trend` and `_to_float` edge cases |
| Integration: `finish()` | 8 | Summary row written, note JSON valid, non-allow counts, divergence counted |
| Integration: `update_note` | 2 | Correct row targeted, most-recent-row semantics |
| Gate backward compat | 1 | Gate with `accumulator=None` produces no session rows |
| Gate + accumulator | 3 | Note written, summary row, decisions unchanged |
| M9 chain regression | 2 | Real 25-call chain produces zero dangerous anomaly flags |

**Critical regression test:** `test_m9_chain_no_dangerous_anomalies` feeds the
real `chains/latency_chain.json` fixture through the accumulator and asserts:
- `hash_divergence_count == 0` (no false dilution alarm)
- `score_trend_detectors == []` (no false trend alarm)
- `non_allow_calls == 0` (no decisions changed)

---

## Reproduce

```bash
# Tests (no models needed)
uv run pytest tests/test_session.py -v

# All tests including M12
uv run pytest -m "not models" -v

# Benchmark
uv run python scripts/benchmark_session.py
```
