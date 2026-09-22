# prd.md — LLMShield-MCP Product Requirements

Source of truth for requirements. Derived from `PROPOSAL.md` (MVP Technical
Proposal). Section numbers in brackets refer to that document.

Amendments made after the proposal was written are recorded in section 9 of
this file rather than edited silently into the requirement text.

---

## 1. Product Purpose

LLMShield-MCP extends the author's existing LLMShield guardrail middleware and
GAUGE evaluation protocol from the **user-prompt injection surface** to the
**MCP tool-result surface**.

When an MCP-connected agent calls a tool, the result is inserted directly into
the model's context. This project builds a gating layer that inspects tool
results before they reach the model, reusing existing detection components
without retraining, and evaluates it with dissertation-grade statistical rigour.

**Primary research question:** do detectors trained on user-prompt injection
transfer to injection delivered via MCP tool results?

A well-evidenced negative result ("they do not transfer") is a legitimate and
valuable outcome, not a failure requiring a retrain to fix [15].

---

## 2. MVP Objectives [1.2]

1. Determine empirically whether prompt-surface detectors transfer to the MCP
   tool-result surface.
2. Build a working interception layer for two reference MCP servers that
   classifies every tool result as Allow / Redact / Block / Escalate.
3. Run the full GAUGE protocol on this surface: decontaminated corpus,
   matched-FPR comparison, dual benign references, threat-type disaggregation,
   leave-one-source-out generalisation test.
4. Benchmark gating latency per tool call and across a multi-call agent chain.
5. Publish a public evaluation harness and payload corpus with a README stating
   headline numbers in plain English.

---

## 3. Scope

### In scope [3.1]

- Gating of MCP **tool results** (not tool call requests) for two reference
  servers: filesystem and web-fetch.
- Reuse of existing rule engine, V0 lexical classifier, V3 transformer
  classifier and PII scanner. **No retraining.**
- Decontaminated payload corpus (low hundreds of items) using MinHash.
- Policy-as-code fusion/decision layer configurable without code changes.
- Audit logging of every decision.
- Minimal reference agent, used only to host realistic tool-call chains.
- Full GAUGE evaluation.
- Latency benchmarking.
- Public GitHub repository with harness, corpus and written report.

### Out of scope for MVP [3.2]

Admin REST API, results dashboard, hosted demo, tiered/cascade detection,
fine-tuned MCP-specific model, multi-turn injection tracking,
non-English/non-text payloads, transports beyond local stdio and reachable
HTTP+SSE. Full deferred list at [26].

---

## 4. Functional Requirements [6]

| ID | Requirement | Milestone |
|---|---|---|
| FR-1 | Intercept every tool result from a monitored MCP server before it reaches the agent | M2 |
| FR-2 | Run rule engine, V0 and PII scanner against every intercepted tool result | M3, M5 |
| FR-3 | Run V3 against every intercepted tool result (configurable always-on) | M5 |
| FR-4 | Fuse detector outputs into exactly one decision: Allow, Redact, Block, Escalate | M4 |
| FR-5 | On Redact, remove/mask only offending span(s), preserving the rest | M4 |
| FR-6 | On Block, replace the result with a safe, clearly-labelled refusal payload | M4 |
| FR-7 | On Escalate, pass through per policy and flag for human review | M4 |
| FR-8 | Log every decision: timestamp, correlation ID, server, tool, scores, decision, latency | M2 |
| FR-9 | Policy configuration via versioned file, no code changes | M4 |
| FR-10 | Corpus management: add, label, decontaminate | M6 |
| FR-11 | Run full GAUGE pipeline: matched-FPR ASR by threat type with confidence intervals | M7 |
| FR-12 | Run leave-one-source-out generalisation test | M8 |
| FR-13 | Benchmark per-call latency for each detector variant and the fused pipeline | M9 |
| FR-14 | Benchmark end-to-end overhead across >= 20 sequential tool calls | M9 |
| FR-15 | Pass MCP protocol-level error responses through without content-based detection | M2 |
| FR-16 | Enforce configurable maximum tool-result size with a defined truncation policy | M2, M5 |

---

## 5. Non-Functional Requirements [7]

| ID | Requirement | Status |
|---|---|---|
| NFR-1 | Lexical/rule path adds <= ~5 ms per tool result on commodity CPU | At risk — see 9.4 |
| NFR-2 | Transformer path latency measured and reported honestly against the sub-100 ms SME budget, even if not met | Measurement pending M9 |
| NFR-3 | Never execute, evaluate or act on content in a scanned tool result | Design constraint |
| NFR-4 | PII redacted or hashed before being written to any log | M3 |
| NFR-5 | Handle >= 20 sequential tool calls without memory growth or state leakage | M2 |
| NFR-6 | Evaluation pipeline runs fully offline/in-batch | M7 |
| NFR-7 | Every statistical figure carries a confidence interval, never a bare point estimate | M7 |
| NFR-8 | Dependencies version-pinned; no dynamic execution of externally sourced content | Done (M0) |

---

## 6. Security Requirements [16]

| ID | Requirement | Status |
|---|---|---|
| SEC-1 | Never execute, interpret or follow instructions in scanned content | Design constraint |
| SEC-2 | Enforce maximum content size to prevent DoS via oversized results | Partial (M0: V3 window cap) |
| SEC-3 | Redact or hash PII before writing to any log | M3 |
| SEC-4 | Sandbox the reference filesystem MCP server to a dedicated directory | M1 |
| SEC-5 | Use TLS for any remote (HTTP+SSE) MCP transport | M1 |
| SEC-6 | Fail-closed (Block/Escalate) on detector failure, logged distinctly | Partial (M0: detector contract reports failure; policy mapping is M4) |

---

## 7. Constraints and Dependencies [20]

| ID | Assumption | Resolved status |
|---|---|---|
| A1 | Author can reuse existing LLMShield code and models | **CONFIRMED.** Author owns them. Reuse permitted; **trained weights must not be published.** |
| A2 | Sufficient Anthropic API budget for corpus-scale evaluation | **RESOLVED by design change.** The reference agent hosts tool-call chains only; GAUGE runs offline against the stored corpus, so budget is a one-off rather than scaling with corpus size. |
| A3 | CPU-only inference acceptable | **CONFIRMED.** No GPU available. CPU-only for all paths. |
| A4 | MCP SDK stable enough to complete the project | Pinned `mcp==2.1.1`. SDK is at 2.x (types split into a separate `mcp-types` package); spec churn remains a risk. |

**Weights are not publishable.** Consequence: the public repository ships code,
corpus, harness and report but not the V0/V3 weights. To keep statistical claims
independently checkable, every evaluation run must emit a per-item `scores.csv`
from which all downstream statistics recompute without weights or inference.
This is a hard requirement, not an optional extra.

---

## 8. Acceptance Criteria [27]

1. Interception functions transparently for both reference MCP servers without
   breaking normal tool operation.
2. Full GAUGE protocol run end to end, producing matched-FPR ASR disaggregated
   by threat type, each with a confidence interval.
3. Leave-one-source-out generalisation test run and reported.
4. Latency benchmarked and reported per tool call and across a multi-call chain,
   for each detector variant.
5. Every gating decision during evaluation captured in the audit log.
6. Payload corpus decontaminated and documented with provenance.
7. Public repository with harness, corpus and a README stating headline numbers
   in plain English.
8. Findings reported honestly, including a negative or partial result.

---

## 9. Amendments to the Proposal

Recorded here rather than silently applied to the requirement text above.

### 9.1 Detector scope — V0 retained

The proposal's FR-2 mandates rule engine + V0 + PII. A mid-project decision to
run "V3 only" was reconsidered and reversed: **V0 is retained as a baseline
variant, V3 is the headline detector.**

Rationale: V0 is the only sub-5 ms path available for NFR-1; it preserves a
fourth detector variant for the matched-FPR comparison; and M0 evidence shows
V0 has no token limit, making it the natural control for the V3 truncation
experiment.

### 9.2 Score-mode asymmetry — new requirement

Discovered during M0: **both V0 and V3 are 4-class**, not binary, over
`(benign, injection, jailbreak, harmful)`. The dissertation collapsed them to a
scalar differently — V0 as `1 - P(benign)`
(`evaluation/experiment2/exp2_eval.py:74`), V3 as `P(injection)` (same file,
line 90, which resolves the positive class to `LABEL_1`).

These are not interchangeable. Under threat-type disaggregation a
`P(injection)` scorer reads as weak on jailbreak and harmful rows by
construction rather than by capability.

**Requirement added:** score mode is per-detector configuration. Dissertation
defaults are preserved for continuity, and the harmonised `not_benign` mode
must additionally be reported for both detectors so the comparison is fair.

### 9.3 Context dilution — new corpus axis

Proposal [19] lists an evasion sub-category covering encoding tricks, homoglyphs
and zero-width characters. It does **not** cover dilution.

M0 evidence (`docs/M0-OBSERVATIONS.md`): an injection payload scoring
P(injection) = 0.998 in isolation scores 0.052 when embedded in benign carrier
text **inside a single 512-token window** — nothing truncated, nothing chunked,
the payload fully visible to the model. Signal loss of roughly 95%.

**Requirement added:** the corpus must treat **dilution ratio** as a
first-class axis — the same payload embedded in increasing quantities of benign
carrier text. Without it the corpus would miss what currently appears to be the
strongest effect on this surface.

Status: smoke-test evidence from four probe strings. Not yet a finding.

### 9.4 NFR-1 feasibility

M0 first-pass CPU measurements: V3 at ~180-220 ms for a single window and
~5300 ms for a ~1500-token input under chunking. NFR-1's ~5 ms budget is
reachable by V0 on short inputs only (~2-3 ms; ~14 ms at ~1500 tokens).

NFR-1 and NFR-2 are **not** relaxed. They are measured and reported honestly per
NFR-2's own wording. If the transformer path proves impractical for real agent
loops, that is a reportable finding and the motivation for the cascade detection
already deferred at [26].

### 9.5 Interception architecture

Proposal [11.1] left the choice between (A) protocol-level proxy and (B)
client-side wrapper as an open question. Resolved — see `plan.md` section 2.1.

### 9.3 Score-mode reporting — 9.2's requirement finally satisfied, and what it showed

9.2 added a requirement: "the harmonised `not_benign` mode must additionally be
reported for both detectors so the comparison is fair." **That requirement went
unsatisfied for the whole project until `mcp-shield gauge-recut` was built**
(`plan.md` 2.26). `scores.csv` had carried the four class probabilities since
M7 specifically so the harmonised cut could be derived, but nothing ever read
them back, so every published AUROC used each detector's dissertation default
and the fair comparison 9.2 asked for was never made.

It matters. On the full decontaminated corpus V3 reads 0.346 under its shipped
`injection` cut and 0.540 under `not_benign` -- the difference between "worse
than chance" and "at chance", from the same inference. A report that had
satisfied 9.2 on time would not have published the stronger phrasing.

**Requirement restated and now enforced in practice:** any AUROC published for
a 4-class detector must be accompanied by its harmonised `not_benign` figure.
`docs/REPORT.md` section 4 carries the full mode table, and `gauge-recut`
regenerates it from the committed `scores.csv` with no weights.

### 9.4 Detector scope — a third, publishable classifier added

The proposal's FR-2 scopes detection to the reused rule engine, V0, V3 and PII.
A third classifier, `guard`
(`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0, pinned by commit
SHA), has been added outside that list.

**Rationale, and why it is not scope creep.** Two problems the original scope
could not solve:

1. *Unfalsifiability.* A1 makes V0/V3 unpublishable, so no reader can check any
   number this project reports about them. A published, fetchable classifier
   measured through the identical protocol gives at least one result a third
   party can reproduce.
2. *The obvious objection.* "These are one author's reused artifacts; a
   detector built properly would work." That is a claim about the world, and
   this project's standard is to measure claims rather than argue them.

**It does not alter the no-retraining constraint.** `guard` is used exactly as
published; nothing here is trained or fine-tuned.

**Result** (`docs/REPORT.md` section 4): it does not rescue the finding.
AUROC 0.553 [0.501, 0.605] against realistic benign content, 0.281 against the
adversarial-styled reference, and 89.6% attack success at its calibrated
escalate threshold. The finding therefore generalises beyond the reused models.

**Constraint carried forward:** `guard` ships `inert` like every other
classifier. Adding a detector that can be measured is not grounds for trusting
it, and promotion to a decision-carrying role still requires a calibration on
this surface that no current data supports.

**Known gap:** the corpus is decontaminated against V0/V3's training data, not
`guard`'s -- its training sets are named on its model card but not distributed,
so no equivalent MinHash check was possible. Contamination inflates apparent
performance, so the reported figure is an upper bound. Stated in the report
rather than left for a reader to notice.
