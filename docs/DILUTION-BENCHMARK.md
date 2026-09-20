# Dilution Benchmark

> **These are measured benchmark numbers. They characterise what these
> specific detectors do on these specific corpora under these experimental
> conditions. They are not security claims and must not be quoted as such.**

Companion to `docs/M0-OBSERVATIONS.md` §1 and `docs/M12-SESSION-CORRELATION.md`.

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

| Detector | FPs | Total | FPR |
|---|---|---|---|
| `rules_mcp` | 0 | 50 | 0.0% |
| `rules_inj` | 0 | 50 | 0.0% |
| `pii` | 0 | 50 | 0.0% |

No false positives on the benign sample.

### 5. Latency

1,820 calls per detector (187 payloads × 4 ratios × 3 positions minus 5-payload warmup):

| Detector | mean (ms) | p95 (ms) | n |
|---|---|---|---|
| `rules_mcp` | 0.178 | 0.504 | 1,820 |
| `rules_inj` | 0.192 | 0.548 | 1,820 |
| `pii` | 0.167 | 0.473 | 1,820 |

All within NFR-1 lexical budget (~5 ms).

---

## Session Accumulator Signals (M12)

These are **synthetic experiments**: scorer values are set manually, not
measured from a running detector. They verify that the accumulator's internal
state machine behaves correctly for each pattern, not that any real attack
produces those scores. This distinction is critical.

| Experiment | Description | Total calls | Hash recurrences | Hash divergences |
|---|---|---|---|---|
| `benign_baseline` | 20 distinct benign texts, all ALLOW | 20 | 0 | 0 |
| `repeated_diluted_same_ratio` | Same diluted text × 3 calls (same hash, stable score=0.0) | 3 | 2 | 0 |
| `different_dilution_levels` | Same payload at ratio=0.0 then ratio=0.9 (different hashes) | 2 | 0 | 0 |
| `simulated_score_divergence` | **Synthetic**: same hash, scores 1.0 → 0.05 (not from a real detector) | 2 | 1 | **1** |

**What each experiment demonstrates:**

- **Benign baseline:** The accumulator generates zero anomaly signals across 20
  unique benign calls. No session-layer false positives.

- **Repeated same-ratio:** The same content hash appearing 3 times produces
  `hash_recurrence_count = 2` and `hash_divergence_count = 0` because the score
  is stable (0.0 both times). This correctly distinguishes repetition from
  anomalous score change.

- **Different dilution levels:** The same adversarial payload at ratio=0.0 and
  ratio=0.9 produces two *different texts* → two different sha256 hashes →
  `hash_recurrence_count = 0`. This is correct: the accumulator tracks content
  identity (hash), not payload identity. An attacker delivering the same payload
  at different dilution levels produces non-recurring hashes — the accumulator
  cannot flag this from hashes alone without semantic payload knowledge.

- **Simulated score divergence:** Feeding the same hash with scores 1.0 then
  0.05 produces `hash_divergence_count = 1`. This verifies the accumulator's
  divergence-detection logic against the scenario that motivated M12 (the
  M0-observed V3 score collapse). The scores are **not from a real detector
  call** — this is purely a state-machine correctness test.

---

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

### The session accumulator adds value for *measured* score divergence only

The synthetic experiment verifies the accumulator's state machine for
score divergence, but three limits apply in this benchmark:

1. **No measured scores feed the session experiments.** The 1.0 → 0.05 scores
   are hand-set. The accumulator itself is tested against real scores in
   `tests/test_session.py`; this benchmark tests it against dilution-specific
   scenarios.

2. **Different dilution ratios produce different hashes.** If an attacker probes
   the same payload at ratio=0.0 then ratio=0.9, the two texts are distinct →
   distinct hashes → the accumulator sees no recurrence. The session layer only
   flags the dilution signal when the *exact same content* is processed twice
   with diverging scores — the scenario where a server returns the same cached
   response but the surrounding context changes the model's score.

3. **`hash_recurrence` alone is not a signal.** Legitimate repeated reads produce
   zero divergence. Only `hash_divergence_count > 0` is the meaningful indicator.

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
| Real measured score-divergence in the accumulator | Synthetic scores only in this benchmark; real scores in `test_session.py` |

---

## Reproducibility

```
# Fetch adversarial corpus (needed once)
uv run python scripts/benchmark_rules.py

# Run the benchmark
uv run python scripts/benchmark_dilution.py

# Run all related tests
uv run pytest tests/test_dilution.py tests/test_session.py -v
```

Results are written to `results/dilution/dilution_results.json` (gitignored).
All inputs are deterministic; the output is stable across runs.
