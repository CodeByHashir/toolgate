# Dilution Benchmark

> **These are measured benchmark numbers. They characterise what these
> specific detectors do on these specific corpora under these experimental
> conditions. They are not security claims and must not be quoted as such.**

Companion to `docs/M0-OBSERVATIONS.md` §1.

Run: `uv run python scripts/benchmark_dilution.py`

---

## Background

`docs/M0-OBSERVATIONS.md §1` documents the key motivating observation: a known
injection payload scoring P(injection) = 0.998 in isolation dropped to 0.052
when embedded in ×5 benign filler within a single 512-token window. That was a
single hand-measured data point with a semantic model (V3). This benchmark
turns it into a systematic, reproducible measurement for the rule-based and PII
detectors that run in CI — and exposes a methodological flaw that was found and
corrected before the results were recorded.

---

## Methodology

### Corpora

| Source | n | Notes |
|---|---|---|
| BIPIA (text + code tasks) | 125 | Indirect injection objectives phrased as task instructions |
| InjecAgent (DH + DS) | 62 | Direct injection commands targeting agent tool calls |
| **Total adversarial** | **187** | |
| Benign FP sample | 50 | Lines from `corpus.sources.load_benign()`, scored as-is |

### Filler — and why it matters

Dilution experiments mix the adversarial payload with "benign filler" text.
**The filler must score 0.0 on all detectors before use.**

This is not a minor technicality. The first run of this benchmark used
`corpus.sources.load_benign()` directly, which returned lines from `CLAUDE.md`
— a system-prompt file containing text such as:

> *"You are working as an engineering agent... Never make assumptions when the
> repository can provide evidence."*

At a 75% dilution ratio, the tiled filler concatenated the substring
`provide [payload-word] your answer`, which triggered rule MCP-002
(`\b(provide)\b[...]{0,30}\byour\s+(answer)\b`) on a payload that scored 0.0
in isolation. This inflated `rules_mcp` recall from 20.3% to 20.7% at ratio
0.75 only — a methodological artifact, not a genuine dilution effect.

**Fix:** `dilution.load_neutral_filler()` screens every candidate line through
all active detectors and rejects any that score > 0.0. The benchmark now uses
only verified-neutral prose from Python source docstrings. The 75% anomaly
disappears entirely with clean filler.

The regression test
`TestLoadNeutralFiller::test_filler_does_not_inflate_recall_at_any_ratio`
encodes this property permanently.

### Measurement conditions

| Parameter | Value |
|---|---|
| Filler | 128 verified-neutral words from Python source docstrings |
| Dilution ratios | 0.0 (isolated), 0.5, 0.75, 0.90 |
| Payload positions | start / middle / end (at each non-zero ratio) |
| Detectors | `rules_mcp`, `rules_inj`, `pii` — no ML weights, CI-safe |
| Scoring | `scan_normalised()` — same path as the live `Gate` |
| Reproducibility | Fully deterministic; no random generation |

**Denominators:** ratio=0.0 has n=187 (isolated-only). Each non-zero ratio
has n=561 (3 positions × 187 payloads). The `recall_by_ratio` table in the
JSON output carries correct denominators.

---

## Results

### 1. Recall by Dilution Level

Recall = fraction of adversarial corpus with non-zero detector score.
The denominator at ratio=0.0 is 187 (isolated); at each non-zero ratio it is
561 (3 positions × 187 payloads). Percentages are comparable across ratios.

| Detector | isolated | 50% diluted | 75% diluted | 90% diluted |
|---|---|---|---|---|
| `rules_mcp` | 20.3% (38/187) | 20.3% (114/561) | 20.3% (114/561) | 20.3% (114/561) |
| `rules_inj` | 0.0% (0/187) | 0.0% (0/561) | 0.0% (0/561) | 0.0% (0/561) |
| `pii` | 19.3% (36/187) | 19.3% (108/561) | 19.3% (108/561) | 19.3% (108/561) |

**Recall is completely flat across all dilution levels for all three detectors.**

### 2. Score Degradation

Mean score across all payloads (over all positions at each non-zero ratio):

| Detector | isolated | 90% diluted | Absolute drop | Relative drop |
|---|---|---|---|---|
| `rules_mcp` | 0.2032 | 0.2032 | 0.0000 | 0% |
| `rules_inj` | 0.0000 | 0.0000 | 0.0000 | n/a |
| `pii` | 0.1631 | 0.1631 | 0.0000 | 0% |

No score degradation at any dilution level.

### 3. Position Effect

Recall pooled across all non-zero ratio levels, by position:

| Detector | payload at start | payload in middle | payload at end |
|---|---|---|---|
| `rules_mcp` | 20.3% (114/561) | 20.3% (114/561) | 20.3% (114/561) |
| `rules_inj` | 0.0% (0/561) | 0.0% (0/561) | 0.0% (0/561) |
| `pii` | 19.3% (108/561) | 19.3% (108/561) | 19.3% (108/561) |

Position has no measurable effect on recall.

### 4. Benign False Positives

50 items from `load_benign()`, scored directly (no dilution):

| Detector | FPs | Total | FPR, Wilson 95% CI |
|---|---|---|---|
| `rules_mcp` | 0 | 50 | 0% [0%, 7.14%] |
| `rules_inj` | 0 | 50 | 0% [0%, 7.14%] |
| `pii` | 0 | 50 | 0% [0%, 7.14%] |

No false positives were observed on the benign sample — but **n=50 is far too
small to say anything useful about a false-positive rate.** The Wilson 95%
upper bound is 7.14%: a detector firing on one benign line in fifteen would
produce this result roughly 3 times in 100. Treat this row as a smoke test
confirming the detectors are not wildly miscalibrated on benign text, not as an
FPR measurement. The real FPR figure is the 4,654-line one in
`docs/POLICY-AUDIT.md`, upper-bounded at 0.082%.

### 5. Latency

1,820 calls per detector (187 payloads × 4 ratios × 3 positions minus 5-payload warmup):

| Detector | mean (ms) | p95 (ms) | n |
|---|---|---|---|
| `rules_mcp` | 0.178 | 0.504 | 1,820 |
| `rules_inj` | 0.192 | 0.548 | 1,820 |
| `pii` | 0.167 | 0.473 | 1,820 |

All within NFR-1 lexical budget (~5 ms).

---

## Session-level correlation: measured, and removed

An earlier milestone (M12) added a `SessionAccumulator` that watched for the
same sha256 recurring within a session with *diverging* detector scores, on the
theory that an attacker probing dilution ratios would show up as that pattern.
**It was removed.** The benchmark below is why, and the finding is kept here
because it is a real negative result about session-level correlation, not just
a deleted feature.

Three separate reasons, each independently sufficient:

1. **Dilution changes the content, so it changes the hash.** The same payload at
   ratio 0.0 and ratio 0.9 is two different texts and therefore two different
   sha256 values. The accumulator sees no recurrence at all. This was measured,
   not reasoned about: the `different_dilution_levels` experiment produced
   `hash_recurrence_count = 0`. The mechanism could not detect the threat it
   was built for.
2. **Identical content implies identical scores.** Every detector here is a
   deterministic function of its input, so a recurring hash necessarily carries
   the same scores. Score divergence on a recurring hash is therefore
   structurally unreachable through the real gating path, whatever the corpus.
   The only experiment that ever produced a divergence fed the accumulator
   hand-written `DecisionRecord`s; no detector was involved.
3. **It was never wired into a runtime path.** `Gate` accepted an accumulator,
   but nothing outside tests and benchmarks ever passed one, and `finish()` was
   never called in production.

Removing it also restored a property worth more than the feature: the decision
log is append-only again. The accumulator needed an `UPDATE` to append its note
to an already-written row, which was the only mutation in an audit store whose
whole value is that rows do not change after the fact.

**What would actually be needed.** Detecting a dilution probe requires
recognising that two *different* texts carry the *same* payload — a content
similarity or lineage question, not a hash-identity one. The corpus machinery
for that already exists (MinHash/LSH, `corpus/decontaminate.py`), but applying
it across live tool results means holding content, or shingles of content,
across calls. That directly contradicts SEC-1/NFR-3, under which the gate
stores a hash and never the text. That trade-off is a design decision with a
real privacy cost, and it was never made — M12 implemented the cheap mechanism
that avoided it, which is precisely why the cheap mechanism did not work.

## What These Results Mean

### Rules and PII are dilution-immune by construction

Both detector types use lexical pattern matching: a regex either appears in the
text or it does not. Adding benign words around a pattern cannot remove it.
Therefore flat recall across dilution levels is the *expected* outcome, not
evidence of robustness.

The implication: **for rule-based and PII detectors, dilution is not an evasion
vector**. An attacker cannot hide a matching pattern by padding with benign text.
The 20% baseline recall is a corpus-level ceiling determined by how many
payloads happen to contain MCP-\* or PII-matching patterns, not by dilution
ratio.

### The V3 dilution collapse is a semantic model phenomenon

The M0-observed collapse (0.998 → 0.052) occurs because V3's transformer encodes
the payload in the context of surrounding benign tokens, and the benign context
suppresses the injection score. Rule-based detectors see only lexical presence
or absence — they have no context representation and therefore no dilution
sensitivity. The two detector families are measuring fundamentally different
properties and their dilution responses cannot be compared.

### `rules_inj` has 0% recall on this corpus

INJ-\* rules were written against user prompts (direct injection attempts) and
have zero transfer to the tool-result surface where BIPIA and InjecAgent payloads
are framed as indirect instructions. Dilution has no effect because no pattern
fires. This confirms the finding in `docs/POLICY-AUDIT.md` and `plan.md §2.14`.

### Comparison with single-call baseline

The isolated (ratio=0.0) condition replicates the per-call baseline:

| Metric | M7 GAUGE | Dilution isolated |
|---|---|---|
| `rules_mcp` recall | ~20% (corpus-level ASR) | 20.3% (38/187) |
| `rules_inj` recall | 0.0% | 0.0% |
| `pii` recall | not a GAUGE detector | 19.3% (36/187) |

Consistent with M7. Adding dilution does not change recall for these detectors.

---

## What This Benchmark Does NOT Measure

| Gap | Why not here |
|---|---|
| V3/V0 dilution collapse | Requires model weights; out of CI scope |
| Semantic paraphrasing evasion | Would require generating paraphrases; outside no-ML constraint |
| Cross-session accumulation | Accumulator is session-scoped by design |
| Multi-step gradual payload injection | Distinct from ratio-dilution; different threat model |
| Statistical confidence intervals | n=187 supports descriptive reporting; not AUROC territory |

---

## Reproducibility

```
# Fetch adversarial corpus (needed once)
uv run python scripts/benchmark_rules.py

# Run the benchmark
uv run python scripts/benchmark_dilution.py

# Run all related tests
uv run pytest tests/test_dilution.py -v
```

Results are written to `results/dilution/dilution_results.json` (gitignored).
All inputs are deterministic; the output is stable across runs.
