# Policy audit before M4

Written before wiring the ported detectors into a decision path, because M4
bakes these settings into the system and several of them do not survive contact
with the tool-result surface.

Everything below is measured, not argued. Scripts were throwaway; the corpora
are named so each number can be reproduced.

**Verdict: the rule set is sound and should be kept. The inherited fusion and
threshold configuration is not safe to adopt as-is, and one required pipeline
stage was missed in M3.**

---

## 1. Rule precision is good

Corpus: 46 real documents from this repository — source, tests, docs, README,
the memory files, the sandbox, and configs. 282,325 characters. This is
realistic content for a filesystem MCP server to serve.

| Result | Count |
|---|---|
| Documents where any rule fired | **3 / 46** |
| Documents after excluding self-referential files | **0 / 43** |

The three hits are `config/rules.yaml`, `tests/test_detector_rules.py` and
`src/llmshield_mcp/cli.py` — files that contain injection strings *because they
are about injection detection*. The text really is an injection string; it is
just quoted.

That is not a defect, but it is a real deployment class: security
documentation, detection rule sets and red-team corpora are legitimate files an
agent may be asked to read, and they will trip these rules. Worth stating as a
known behaviour rather than discovering it later.

PII produced one hit, on `tests/test_detector_pii.py`, which contains synthetic
test values. Correct behaviour.

## 2. Rule recall on this surface is poor

Corpus: 21 hand-written indirect injections in the shape they actually arrive
in — embedded in a file or page the agent reads, addressed to the assistant,
not typed by a user. Threat types cover direct override, HTML/markdown/code
comment injection, CSV cell injection, fake tool output, authority spoofing,
persona, prompt exfiltration, encoding, and evasion.

**Recall: 8 / 21 = 38.1%.**

Caught: the classic "ignore all previous instructions", the chat-template
tokens (`[INST]`, ChatML, `### System:`), the DAN persona, and "repeat your
system prompt".

Missed — and these are the *characteristic* tool-result vectors:

| Threat | Why it slips through |
|---|---|
| HTML comment injection | No rule looks at comment syntax |
| Markdown hidden comment | Same |
| Code comment injection | Same |
| CSV cell injection | Same |
| Fake tool output / next-step redirect | No rule models this shape at all |
| Polite paraphrase ("please disregard your earlier directions") | INJ-002 needs "instructions" |
| No-trigger-word override ("Your prior task is cancelled") | No lexical overlap |
| Synonym ("set aside everything you were told before") | No lexical overlap |
| Zero-width, homoglyph, base64, letter-spacing | See section 3 |

This is expected — the rules were written for user prompts — and it is exactly
the transfer question the project exists to answer. It is not a reason to
discard them. It **is** a reason not to let a rule-only path define the
decision.

## 3. A required pipeline stage was missed in M3

LLMShield's `src/llmshield/pre_llm/normaliser.py` is **Step 1 of the pre-LLM
pipeline and its docstring states it "runs before any detection component"**.
M3 ported steps 2 and 3 (PII, rules) but not step 1.

It applies four transforms: Unicode NFKC, invisible-character stripping
(zero-width, RTL override, BOM), base64 decoding, and homoglyph mapping.

Measured effect of adding an equivalent stage:

| | Recall |
|---|---|
| Rules alone | 8 / 21 = 38.1% |
| Rules after normalisation | **12 / 21 = 57.1%** |

It recovers exactly the four obfuscation cases — base64 (twice), zero-width,
homoglyph — and none of the nine semantic ones, which is the correct division
of labour: normalisation defeats obfuscation, not paraphrase.

False-positive cost, measured over 49 documents and 450,753 characters
including `uv.lock` (dense with base64-like hashes) and the recorded chain JSON:

**0 new false positives.**

This is a gap, not an enhancement. Recommend porting it before M4.

## 4. The inherited circuit breakers are unsafe here

`policies/default.json` carries `circuit_breakers`: `rule_flag >= 0.5` and
`ml_probability >= 0.95`. A circuit breaker is a hard override — it blocks
regardless of the weighted score.

### 4.1 The ML breaker blocks almost all benign content

Measured on eight benign documents, V0 and V3 on CPU:

| Document | V0 `not_benign` | V3 `injection` | V3 `not_benign` |
|---|---|---|---|
| `README.md` | 0.986 | 0.045 | **1.000** |
| `sandbox/README.md` | 0.889 | 0.099 | **1.000** |
| `sandbox/notes/meeting-notes.md` | 0.710 | 0.047 | **0.998** |
| `sandbox/src/config_loader.py` | 0.937 | 0.300 | **1.000** |
| `sandbox/data/quarterly.csv` | 0.291 | 0.021 | 0.159 |
| `src/llmshield_mcp/config.py` | 0.973 | 0.047 | **1.000** |
| `docs/PINNING.md` | 0.945 | 0.049 | **1.000** |
| `config/servers.yaml` | 0.737 | 0.047 | **1.000** |

With `ml_probability >= 0.95` applied to `not_benign` scores:

- **7 / 8 benign documents are hard-blocked.**
- Under `injection` scores: **0 / 8**.

Reading `README.md` would be blocked. This makes the score-mode decision
recorded in `prd.md` 9.2 far more consequential than it looked: it is not only
a reporting choice, it decides whether the system is usable at all under an
inherited threshold.

### 4.2 The rule breaker is all-or-nothing

The rule score is binary, so `rule_flag >= 0.5` means **any single regex match
blocks the result**, whatever its severity. Against section 1's corpus that is
a hard block on 3/49 documents, concentrated exactly on security-related files.

A medium-severity match on `base64 decode` appearing in a build log would block
the read.

## 5. The weight vector does not map onto this system

Inherited `risk_fusion.weights`: `pii 0.2, rule 0.3, ml 0.3, policy 0.2`.

| Problem | Detail |
|---|---|
| `policy` is dead | It was fed by `topic_controls`, which are empty in the default policy and have no equivalent here. 20% of the weight budget scores zero always, dragging every result below `high_min = 0.55`. |
| `ml` is one weight, we have two ML detectors | V0 and V3 must share 0.3, or the vector must be redefined. Neither is specified. |
| Thresholds are from another surface | `low_max 0.3` / `high_min 0.55` were calibrated on user prompts. FR-11 requires matched-FPR calibration on *this* corpus; inheriting them would invalidate the comparison the project exists to make. |

## 6. The inherited defaults cannot satisfy FR-7

`decision_actions` sets `escalation_enabled: false`. FR-7 requires Escalate as
one of the four decisions. The ported default cannot express it.

## 7. The fusion-mode ablation does not transfer either

The dissertation's own ablation
(`evaluation/results/fusion_ablation/deberta_onnx/fusion_ablation_summary.md`)
found **all five fusion modes identical** — recall 0.659, FPR 0.265, McNemar
p = 1.0 with b = c = 0 across every comparison. They collapse because
`tau_ml = 1.0000` leaves the ML signal silent and the binary rule breaker
deciding everything.

Two consequences. First, there is no inherited evidence for preferring one
fusion mode, so mode selection has to be an ablation axis here rather than a
setting copied across. Second, note the operating point being inherited: **FPR
0.265**, recall@1%FPR of 0.038. That is the baseline, on the surface it was
designed for.

The `risk_fusion` block in `policies/default.json` has **no `mode` key**, so it
falls back to `linear` — the mode the fusion docstring singles out as
structurally weak ("an ML probability of 0.9 contributes only 0.9 × 0.30 = 0.27,
below the block threshold; FM-5, 75.7% of bypasses").

---

## Recommendations for M4

Ordered by how much they change the outcome.

1. **Port the normaliser as a pre-detection stage.** +19pp recall, zero
   measured false-positive cost. It is a missing pipeline step. Its output
   feeds detection only — the frame forwarded to the agent stays untouched, as
   in M2.
2. **Do not inherit thresholds or circuit breakers.** Calibrate on this
   project's benign reference sets at a matched FPR. This is not caution, it is
   FR-11: an inherited threshold makes the cross-surface comparison meaningless.
   Ship M4 with thresholds marked uncalibrated and have the policy file refuse
   to run in blocking mode until calibration has been performed.
3. **Make the ML circuit breaker score-mode aware, or drop it.** At `>= 0.95`
   on `not_benign` it blocks 7/8 benign documents. If retained it must be
   calibrated per detector *and* per score mode.
4. **Replace the binary rule breaker with a severity-aware rule.** The rule set
   already carries `high` / `medium`; only `high` should be able to hard-block,
   and even that should be calibrated rather than assumed.
5. **Define a new weight vector for the four real signals** (rules, PII, V0,
   V3) and treat it as an ablation axis, not a constant. Drop `policy`.
6. **Enable Escalate** so FR-7 is expressible.
7. **Add a tool-result rule family, kept separate from `INJ-*`.** The nine
   semantic misses in section 2 include shapes with no rule at all — HTML and
   markdown comment injection, code-comment injection, CSV cell injection,
   fake-tool-output redirect. New rules should use a distinct `MCP-*` prefix
   and the 19 `INJ-*` rules must stay frozen, so the dissertation comparison
   stays honest and the new family's contribution is separately measurable.

## What this does not say

The 38.1% recall figure comes from 21 hand-written cases, not a decontaminated
corpus, and every number here is a smoke test against small samples. None of it
is a result. Its purpose is to stop M4 hard-coding settings that the evidence
already shows are wrong for this surface; the real measurement is M7.
