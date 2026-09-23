# plan.md — Implementation Plan and Architecture Decisions

Companion to `prd.md` (what to build) and `whats_has_been_done.md` (what is
built). This file holds the plan, the architecture decisions and their
rationale, remaining work, and known risks.

**Current position: M0-M10 complete; M12 built, measured and removed (2.25). A post-audit hardening pass has since verified the headline finding against falsification, closed a redaction leak, pinned the evaluation corpus, split the policy into light/research profiles, decoupled gating from logging, and restated the FPR and Escalate claims to match their evidence, added a third publishable classifier (2.26), resolved the licensing exposure by removal rather than attribution (2.27), and added capability gating of outbound tool calls -- the control that survives the negative result (2.28). Tool *declarations*, the third attacker-controlled channel, are now being closed: `docs/PLAN-DECLARATION-INTEGRITY.md` is **complete, all six steps** (concealment decoding in the normaliser, the declaration canonicaliser, the trust-on-first-use pin store, verification at the point of model input, a `tool_declarations` policy block with its own audit outcome, and a measured churn base rate in `docs/DECLARATION-CHURN.md`). It ships OFF: no block in `config/policy.yaml` means no gate, nothing pinned, nothing logged -- see 2.29. `docs/REPORT.md` + three committed SVG figures + a rewritten README state the headline findings in plain English. M11 (optional standalone proxy) not started. `config/policy.yaml` still ships uncalibrated by deliberate choice -- see 2.20.**

---

## 1. Milestone Plan

Each milestone is independently testable and lands as its own commit.

| # | Milestone | Requirements | Verification | Status |
|---|---|---|---|---|
| M0 | Scaffold, pinned CPU stack, reuse audit for V0/V3 | NFR-8, A1, A3 | `toolgate verify-models`; contract tests | **Done** |
| M1 | Both reference MCP servers running + minimal Claude agent + committed tool-call chain fixture | SEC-4, [3.1] | Agent reads a file and fetches a URL; fixture committed | **Done** |
| M2 | Interception layer, **logging only, zero detectors** | FR-1, FR-8, FR-15, FR-16, NFR-5 | 10-call run produced exactly 10 log rows; gate overhead 0.03-0.06 ms | **Done** |
| M3 | Port rule engine and PII scanner as detector adapters | FR-2 (part), NFR-4, SEC-3, SEC-6 | 55 unit tests incl. fail-closed for both adapters; zero false positives on the benign sandbox | **Done** |
| M3b | Normaliser as a pre-detection stage; MCP-* rule family derived from benchmark data | FR-2 | 194 tests; MCP-* 20.3% recall at 0.00% FP where INJ-* scores 0.0% | **Done** |
| M4 | Fusion and policy engine; golden-set regression test begins | FR-4, FR-5, FR-6, FR-7, FR-9 | Table-driven decision tests; threshold change in YAML alters decision with no code edit; thresholds refuse to block until calibrated | **Done** |
| M5 | V0 and V3 wired into the live gating path | FR-2, FR-3 | Ablation by config alone | **Done** |
| M6 | Corpus schema, ingest CLI, MinHash decontamination | FR-10, AC-6 | Drop-count report; no surviving near-duplicate above threshold | **Done** |
| M7 | GAUGE harness; DeLong ported, Wilson/CP/McNemar on statsmodels; replace hand-rolled CIs | FR-11, NFR-6, NFR-7 | Known-answer tests for Wilson, Clopper-Pearson, McNemar, DeLong | **Done** |
| M8 | Leave-one-source-out generalisation test | FR-12 | Per-held-out-family table | **Done** |
| M9 | Latency benchmark: per-detector, fused, 20-call chain | FR-13, FR-14, NFR-1, NFR-2 | Reproducible script, committed numbers | **Done** |
| M10 | Report generation; README headline numbers | AC-7, [18] | Tables and plots as static files | **Done** |
| M11 | *(optional)* Standalone stdio proxy over the same gating core | [11.1] option A | Agent config points at proxy, nothing else changes | Not started |
| M12 | Session-level observation accumulator; hash-recurrence/dilution detection | [M0-OBSERVATIONS.md §1] | Built, benchmarked, and **removed**: cannot detect the dilution attack it targets (hash changes with the content), divergence unreachable with deterministic detectors, never wired into a runtime path. Finding kept in `docs/DILUTION-BENCHMARK.md` | **Reverted (2.25)** |

Ordering rule: do not skip ahead. M2 deliberately ships with **no detection**
so that interception transparency can be proven independently of detection
correctness.

---

## 2. Architecture Decisions

### 2.1 Interception point — Transport decorator (resolves proposal [11.1])

**Decision:** intercept at the MCP SDK's `Transport` boundary, not as a
separate out-of-process JSON-RPC proxy and not as a client-side agent wrapper.

**Evidence gathered from `mcp` 2.1.1 source:**

| Fact | Location |
|---|---|
| `Transport` is a formal Protocol: an async context manager yielding `tuple[ReadStream[SessionMessage \| Exception], WriteStream[SessionMessage]]` | `src/mcp/client/_transport.py` |
| `stdio_client` yields exactly that pair from `anyio.create_memory_object_stream` | `client/stdio.py:114,135-136,204` |
| `streamable_http_client` yields the same pair | `client/streamable_http.py:640,705` |
| `Client(server=...)` accepts a `Transport` instance and uses it directly | `client/client.py:288-293,403` |
| No general middleware/interception API exists. `client/extension.py` supports only `ResultClaim` (extra result *types* on `tools/call`) and observation-only `NotificationBinding` | `client/extension.py` |

**Rationale over option A (out-of-process proxy):**

- A true proxy must relay the entire protocol surface — `tools/list`,
  resources, prompts, progress notifications, cancellation, sampling,
  elicitation, version negotiation, capability advertisement. Each is a place
  to break "transparent to both client and server" ([9], AC-1). The decorator
  forwards frames it does not care about untouched.
- A proxy adds a serialise plus IPC hop to every tool call. NFR-1 is a ~5 ms
  budget and NFR-2 is a number intended for publication; the measurement should
  not be contaminated by our own plumbing.

**Rationale over option B (client-side wrapper):**

- B hooks post-parse, above the protocol. It would lose FR-15 (distinguishing a
  protocol-level `JSONRPCError` from tool content) and would measure the agent
  rather than MCP.

**Bonus:** because all three transports converge on the identical
`TransportStreams` type, stdio and streamable HTTP are the same code path by
construction. This closes the proposal's open question about HTTP+SSE.

**Honest cost:** the decorator lives in the client process, so "config-only, no
code changes" ([9]) strictly holds only for SDK-based clients. Acceptable for
the MVP because the reference agent is ours. M11 adds a standalone stdio proxy
over the same core to recover deployment realism.

**Relationship to `architecture_1.png`:** the figure draws the interception
layer as a distinct box between agent and MCP server. That remains an accurate
depiction of the *logical* data flow and of the M11 packaging. The M2-M10
implementation places that same interception point inside the client process at
the transport boundary. The figure should be annotated accordingly before the
report is written.

### 2.2 Detector contract — failure is data, not an exception

`src/llmshield_mcp/detectors/base.py` centralises timing and failure
containment. Two decisions worth defending:

1. **A failed detector returns `score=None`, never `0.0` or `NaN`.** A `0.0`
   would be indistinguishable from a confident "benign" vote and would be
   silently averaged into a fusion score, so a detector crash would read as a
   safety verdict. `None` forces every consumer to handle the failure branch.
2. **Fail-closed (SEC-6) is not decided in the detector.** A detector reports
   "no opinion, and here is why"; translating that into Block or Escalate
   belongs to the policy engine. This keeps the fail-closed policy configurable
   and testable in one place rather than duplicated across four adapters.

### 2.3 Score mode is per-detector configuration

Both reused detectors are 4-class and the dissertation collapsed them to a
scalar differently (V0 `1 - P(benign)`, V3 `P(injection)`). Rather than pick one
and lose comparability with prior work, score mode is configuration with
dissertation defaults, and both modes are reported. See `prd.md` 9.2.

### 2.4 V3 long-content handling — two strategies, both evaluated

`truncate` reproduces the dissertation setup exactly. `chunk_max` slides an
overlapping window across the whole text and takes the maximum. Neither is a
fallback for the other; the gap between them is a result.

Implementation uses the tokenizer's own `return_overflowing_tokens` with
`stride`, which handles per-window special tokens correctly.
`build_inputs_with_special_tokens` was tried first and does not exist in
transformers 5.x.

Window count is capped (`max_chunks`, default 64) so an oversized tool result
cannot exhaust CPU or memory — SEC-2 and FR-16.

### 2.5 Version pins are load-bearing

`scikit-learn==1.9.0` and `transformers==5.12.1` match the versions that wrote
the reused artifacts. The V0 adapter promotes scikit-learn's
`InconsistentVersionWarning` to a hard load failure so the pin enforces itself
rather than depending on someone reading a comment. Rationale in
`docs/PINNING.md`.

### 2.10 Detectors are ported, not imported

The LLMShield repository is a read-only reference, not an installed
dependency, and its scanners implement a different interface
(`InputScanner.scan(prompt, PolicyConfig)`) that pulls in structlog and
pydantic policy models this project does not have.

So the *data* is reused verbatim -- 19 injection regexes with their ids and
severities, six PII patterns with their per-entity confidences and the Luhn
check -- while the matching plumbing is reimplemented behind this project's own
`Detector` contract. That is roughly twenty lines per adapter, against the cost
of dragging an incompatible interface and its dependencies across.

Rules live in `config/rules.yaml` rather than in Python. Nineteen regexes are
data, and FR-9 wants policy driven by a versioned file.

**One deliberate behavioural difference.** The dissertation calls
`pattern.search()` and keeps only the first match per rule, because it only
needed a binary flag for fusion. Both adapters here use `finditer()` and record
every match as a `Span`, because FR-5 has to mask *all* offending regions. The
score is unaffected -- it is binary for rules and max-confidence for PII either
way.

### 2.11 PII cannot leak through a detector result

`RawScore.detail` is typed `dict[str, float]` and `Span` carries integer
offsets plus an entity-type label. Neither can hold a matched value, so a PII
string cannot reach the decision log through a detector result at all (SEC-3,
NFR-4). This is enforced by the type, not by remembering to strip something,
and `test_a_full_result_can_be_serialised_without_leaking` checks the whole
serialised result.

`redact()` lives alongside the scanner for callers that need to mask the
original text. It merges overlapping spans rather than producing nested
placeholders, and applies them right to left so earlier offsets stay valid.

### 2.8 Stream wrappers rather than pump tasks

The gate could have been built by creating fresh `anyio` memory streams and
running two pump tasks that copy frames between them and the inner transport.
It instead wraps the stream objects directly: `ReadStream` and `WriteStream`
(`mcp/shared/_stream_protocols.py`) are five-method protocols, so a wrapper
that delegates and observes satisfies them without any concurrency of its own.

That removes an entire class of bug -- pump-task cancellation, shutdown
ordering, backpressure between two stream pairs -- none of which would have
bought anything, because M2 forwards every frame unchanged anyway.

The wrappers define `__getattr__` delegating to the inner stream. The SDK reads
`last_context` off a read stream, and a wrapper that hid attributes it did not
know about would silently change session behaviour, which is the opposite of
AC-1 transparency.

### 2.9 The decision-log schema is fixed before detection exists

`gating/audit.py` defines all four `Decision` values, the `Outcome`
vocabulary, and every column in M2 -- even though M2 only ever writes
`allow` with empty `detector_scores`. Fixing the schema now means the
logging-only baseline is directly comparable to later runs rather than being a
different format that shares a name.

`Outcome.PROTOCOL_ERROR` is separate from `Outcome.RESULT` for a measurement
reason, not a tidiness one: a JSON-RPC error carries no tool content (FR-15),
so counting those rows as benign allows would quietly inflate the denominator
of any later false-positive rate.

`latency_ms` (time inside the gate) and `roundtrip_ms` (client to server and
back) are separate columns. Conflating them would make NFR-1 unmeasurable --
server time swamps gate time by four orders of magnitude, as the M2 numbers
show.

### 2.7 Manual tool-use loop rather than the SDK's beta tool runner

The Anthropic Python SDK offers `client.beta.messages.tool_runner`, and
`anthropic.lib.tools.mcp.mcp_tool` converts an MCP tool declaration straight
into a runner-compatible tool. The `anthropic[mcp]` extra requires only
`mcp>=1.0`, already pinned, so that path would have cost no new dependency.

`ReferenceAgent` uses an explicit loop anyway, for three reasons:

1. The loop is the thing being instrumented. Every call needs a correlation ID,
   timing and a recorded result; the runner keeps its own history and does not
   expose it.
2. From M2 the transport underneath is replaced by the gating decorator. An
   explicit loop keeps that seam visible.
3. The runner is beta and does not auto-resume `pause_turn`, which would end a
   chain silently mid-recording. The evaluation path should not depend on that.

Cost: roughly fifteen lines of schema conversion (`to_anthropic_tool`) written
by hand. `mcp_tool` returns a `BetaFunctionTool` bound to the runner, so it was
not reusable outside that path.

### 2.6 Reproducibility without weights

Weights are not publishable (`prd.md` 7). Every evaluation run must emit a
per-item `scores.csv` — `item_id, source, threat_type, label, detector,
raw_score, config_hash` plus all four class probabilities. Every downstream
statistic recomputes from that file with no weights and no inference. Only the
forward pass is unreproducible; the statistics are not.

---

## 3. Reuse Inventory

Confirmed present in the LLMShield repository at
`<LLMShield checkout>` (read-only reference; **never
modified**).

| Asset | Path | Reuse plan |
|---|---|---|
| V0 TF-IDF + LR (5.5 MB) | `evaluation/experiment2/models/v0_tfidf_lr.joblib` | Loaded (M0) |
| V3 DeBERTa-v3-base (738 MB) | `evaluation/experiment2/models/v3_deberta_base/` | Loaded (M0) |
| Rule engine, PII scanner, ML classifier, risk fusion, policy engine, decision engine | `src/llmshield/pre_llm/` | Port in M3, M4 |
| Audit logger, escalation queue, policy loader | `src/llmshield/governance/` | Port in M2, M4 |
| 32 policy JSON files plus `schema.json` | `policies/` | Reference for M4 policy schema |
| Leave-one-source-out | `evaluation/experiment2/exp2_lobo.py` | **Not portable** -- retrains V0/V1 per fold, and this project never retrains. M8 builds its own corpus-source-holdout test on M7's calibration machinery instead (`plan.md` 2.20) |
| DeLong AUROC | `evaluation/experiment2/exp2_auroc_delong.py` | Ported in M7 (`gauge/stats.py:auroc_delong`) |
| Matched-FPR thresholding convention | `exp2_multi_fpr.py`/`exp2_eval.py`'s `thr_at_fpr`/`asr` | Convention ported in M7 (`gauge/calibrate.py`): achieved FPR always `<= target`, degenerate detectors flagged `unreachable` rather than given a fake number. Wilson/CP/McNemar themselves came from `statsmodels`, not this file. |
| MinHash decontamination method (shingle definition, 0.85 Jaccard threshold) | `exp2_data.py:_shingles/_minhash`, reused by `exp2_lobo.py` | Threshold/shingle-size reused in M6; reimplemented on `datasketch.MinHashLSH`, not ported line-for-line (`plan.md` 2.19) |
| V0/V3 training-data reference corpus (19,026 rows, post-decontamination) | `evaluation/experiment2/data/train.jsonl` | Decontamination reference set for M6, via `LLMSHIELD_TRAINING_CORPUS`/`config/decontamination.yaml` |

**Not reusable as-is:** `evaluation/metrics.py` uses hand-rolled `_t_value`,
`_confidence_interval` and `_percentile`. Proposal [9] requires established
library implementations (Wilson, Clopper-Pearson, McNemar, DeLong). M7 must
replace these with `statsmodels`/`scipy` and add known-answer tests. Only DeLong
is already implemented correctly.

**Decontamination targets for M6** (V3/V0 training sources, from
`evaluation/experiment2/exp2_data.py`): `deepset/prompt-injections`,
`xTRam1/safe-guard-prompt-injection`, `jayavibhav/prompt-injection`,
`jackhhao/jailbreak-classification`,
`TrustAIRLab/in-the-wild-jailbreak-prompts`, `rubend18`, `dolly`, `alpaca`.

---

### 2.12 Inherited policy settings are not adopted

`docs/POLICY-AUDIT.md` measures the LLMShield policy defaults against this
surface before M4 wires them in. The rule set survives; the fusion and
threshold configuration does not.

Load-bearing measurements:

- The `ml_probability >= 0.95` circuit breaker hard-blocks **7 of 8 benign
  documents** when applied to `not_benign` scores (V3 scores `README.md`,
  `config.py`, `docs/PINNING.md` and `config/servers.yaml` at 1.000). Under
  `injection` scores it fires on none. The score-mode choice in `prd.md` 9.2 is
  therefore not only a reporting decision -- with an inherited threshold it
  decides whether the system is usable.
- `rule_flag >= 0.5` against a binary rule score means any single regex match
  hard-blocks, whatever its severity.
- The `policy` weight (0.2) has no signal behind it here; `ml` (0.3) is one
  weight for two ML detectors; `low_max`/`high_min` were calibrated on the
  user-prompt surface.
- `escalation_enabled: false` cannot satisfy FR-7.
- The dissertation's own fusion ablation found all five modes identical
  (recall 0.659, FPR 0.265, McNemar p = 1.0), so there is no inherited evidence
  for preferring a mode.

Consequence for M4: thresholds are calibrated on this project's benign
reference sets at matched FPR (FR-11), not inherited. The policy file ships
with thresholds marked uncalibrated and refuses to run in blocking mode until
calibration has been performed -- an inherited number would silently invalidate
the cross-surface comparison the project exists to make.

### 2.13 Benchmarks replace hand-written test cases

The first policy audit measured rule recall at 38.1% on 21 hand-written cases.
The same rules score **0.0%** against real benchmarks. The hand-written cases
had been authored by someone who had just read the regexes, so they contained
the words those regexes match -- they measured the author's assumptions.

Adopted sources, both MIT, fetched by `scripts/benchmark_rules.py` and cached
under `corpus/external/` (gitignored):

* **BIPIA** (microsoft/BIPIA) -- 125 attacker objectives, 25 categories.
* **InjecAgent** (uiuc-kang-lab/InjecAgent) -- 62 attacker instructions.

Neither shares lineage with V0/V3's training corpora, which are all
user-prompt surface. They also give FR-12 two independent source families for
leave-one-source-out, with our own MCP-specific corpus as a third in M6.

Rule of practice from this: no detection claim in this project rests on cases
written by whoever wrote the detector.

### 2.14 MCP-* rules are derived, not invented

Candidate patterns came from discriminative phrase analysis over the benchmarks
against ~5,000 lines of benign repository content. Candidates with no measured
support were dropped, and a "tool invocation directive" candidate was rejected
for scoring 0% recall at 0.30% false positives.

Benchmark artefacts were deliberately excluded. The strongest raw n-grams were
`amy watson` and `gmail com` (InjecAgent's fixed attacker identity) and
`example com` (BIPIA's placeholder domain). Matching those would have scored
near-perfectly on the benchmark and detected nothing real.

`INJ-*` stays frozen at 19 rules, guarded by
`test_inj_family_is_frozen_at_the_dissertation_s_nineteen_rules`, so the
cross-surface comparison stays honest and each family's contribution is
separately measurable. Measured separately, they are opposites: `INJ-*`
contributes 0.0% recall and every false positive; `MCP-*` contributes all the
recall and none.

### 2.15 M4 fusion design, decided from measurement

Settled after the evidence in `docs/POLICY-AUDIT.md` 3c. Each decision traces
to a number, not a preference.

**Max / OR-style fusion, never weighted-linear averaging.** The detectors are
near-orthogonal (pairwise Jaccard 0.00-0.09) and none exceeds 20.3% recall.
Averaging four weak orthogonal signals at ~0.3 weight cannot reach any useful
threshold -- which is precisely the FM-5 failure the dissertation's own fusion
docstring blames for 75.7% of bypasses.

**PII is not an injection signal.** Its apparent 19.3% recall was InjecAgent's
hardcoded `amy.watson@gmail.com` (34 of 35 hits). It contributes to SEC-3 /
NFR-4 redaction only. The genuine signal beneath it -- an exfiltration
destination in an imperative context -- is MCP-006's job.

**INJ-\* stays enabled but carries zero decision weight.** It catches 0
payloads, contributes 0 unique detections, and produces every rule false
positive. Keeping it scored-but-inert means each run keeps reporting the 0.0%
transfer result, which is the finding, while it cannot degrade a live decision.

**Per-action FPR budgets, not one score cut into four bands.** At 5% FPR a
20-call agent chain carries roughly one false positive per chain -- tolerable
for a flag, not for destroying a tool result. Indicative targets, to be
calibrated in M7 rather than assumed:

| Action | FPR budget | Why |
|---|---|---|
| Block | ~0.1% | Destroys the tool result |
| Redact | ~1% | Masks a span, preserves the rest |
| Escalate | ~5% | Flags only; content still passes |

**Escalate is the default action on detection, not Block.** With 74.3% of
payloads caught by nothing, a Block-by-default policy would impose the full
false-positive cost while still missing three quarters of attacks. Escalate
keeps the agent working and the decision auditable.

**Thresholds ship uncalibrated and refuse to block.** FR-11 requires
matched-FPR calibration on this surface; an inherited or guessed threshold
would silently invalidate the cross-surface comparison.

### 2.16 What the system honestly is

With 74.3% of real indirect injections undetected by any component, this is a
**detection and audit layer with measured, poor coverage** -- not a guardrail
that blocks attacks. Documentation, the README and the eventual report must say
so. PROPOSAL.md section 15 anticipates exactly this: a well-evidenced negative
result is a legitimate and valuable outcome. The project's value is the
measurement, not the protection.

### 2.17 M4 implementation: precedence, ceiling and where redaction actually happens

`src/llmshield_mcp/gating/policy.py` implements 2.15's design. Three decisions
made during implementation, not measurement-driven like 2.15's but worth
recording because they resolve real ambiguity in "fuse into exactly one
decision" (FR-4):

**Decision-label precedence is BLOCK > ESCALATE > REDACT > ALLOW.** A tool
result can trigger both an injection signal (rules_mcp) and a redaction signal
(PII) at once. Since FR-4 allows only one label, the louder, more
security-relevant label wins the *log entry* -- Escalate over Redact -- rather
than picking whichever fired "first" or averaging anything (that would be the
FM-5 mistake again, just moved one level up).

**PII redaction is orthogonal to the decision label, not a competing action.**
`FusionOutcome.redacted` and `redact_spans` are separate fields from
`decision`. A result can be logged as `escalate` and still have its PII spans
masked in the content actually forwarded -- the two questions ("what do we
tell the reviewer" and "does sensitive data leave this gate") are independent,
matching 2.15's framing that PII carries zero injection weight and exists
purely for SEC-3/NFR-4. `redacted` is forced `False` whenever the decision is
BLOCK, since the whole result is replaced and a per-span mask is moot.

**`calibrated: false` is enforced once, centrally, not scattered across every
branch that could produce BLOCK.** `PolicyEngine._ceiling()` downgrades BLOCK
to ESCALATE regardless of whether the BLOCK came from a fired detector or from
`on_detector_failure: block`. `load_policy_config` also rejects
`on_detector_failure: allow` outright (SEC-6: a crashed detector must never
look like a clean scan) and validates every threshold is in `[0, 1]` at load
time, not at first use.

**Redaction has to survive multi-block results, not just the common
single-text-block case.** `extract()` in `gating/content.py` joins every
text-contributing content block with `"\n"` before a detector ever sees it, so
a `Span`'s offsets are only meaningful against that joined string. Masking the
*original* `tools/call` result therefore has to translate a joined-string
offset back to the specific block (and, for an embedded resource, the nested
`resource.text`) it came from. `_walk_blocks` is the single block-walking
routine both `extract()` and the new `apply_redaction()` call, so the two can
never disagree about where a block starts. `build_block_result()` is the
FR-6 counterpart: it does not carry any field of the original result forward,
so nothing survives a Block by accident.

**V0/V3 stay out of the gate in M4.** `detectors.injection` in
`config/policy.yaml` lists only `rules_mcp`. Wiring them in is explicitly M5's
job (`plan.md` milestone table); M4 fuses what M3/M3b already ported (rules,
PII) rather than pulling two more milestones' scope forward.

### 2.18 M5: V0/V3 wired in, shipped inert -- a deliberate departure from "use them fully now"

The instruction going into M5 was to actually use V0 and V3 to complete the
project, and defer any "what do we ship publicly" question to later. That is
what happened -- both are real, constructed with the real reused weights, and
run against every intercepted tool result -- but they ship in `config/policy.yaml`
`detectors.inert`, not `detectors.injection`. Reasoning:

`docs/POLICY-AUDIT.md` section 4.1 already measured the failure mode of
turning an unmeasured ML score into a live decision: `ml_probability >= 0.95`
hard-blocked 7 of 8 benign documents, because V0's `not_benign` score on
ordinary README-and-config-style content sits at 0.7-1.0. Promoting V0 to
`injection` today, on the ad-hoc percentile thresholds in section 3 ("directional,
not a result", by that document's own words), would reproduce exactly that
failure relabelled from Block to Escalate -- not destroying the result, but
drowning the audit log and defeating the entire point of Escalate being a rare
flag rather than the default outcome. `calibrated: false` already stops this
class of mistake for Block (2.15); there was no equivalent guard for Escalate
before M5, so "inert until calibrated" is that guard.

**What "wired in" means concretely:** `build_detectors()` (renamed from M4's
`default_detectors()`) is now a registry keyed by every name a policy's
`detectors.*` roles may use (`rules_mcp`, `rules_inj`, `pii`, `v0`, `v3`), and
constructs exactly the union of keys the given `PolicyConfig` actually names.
V0 and V3 sit in the registry unconditionally; whether they get built, and
whether building them costs a joblib load or a transformers/torch import,
is entirely a property of `config/policy.yaml`. Moving `v0` from `inert` to
`injection` and adding one threshold line is the whole ablation -- no code
changes, which is the milestone's own verification bar.

**Why this needed a companion decision about the test suite.** `models/` is
gitignored (`prd.md` A1: the weights are not publishable) and is not present
in CI or in a fresh git worktree -- only the original checkout has the local
junction to the author's copy. Once V0/V3 became part of the *shipped*
policy's inert set, a literal `Gate()` with no explicit detector override
would try to load them, which would have made most of the existing
plumbing-level gating tests suddenly require weights they were never about.
`tests/conftest.py`'s `light_detectors` fixture pins the M4-era,
decision-relevant set (rules + PII) for that majority of the suite -- provably
equivalent to the full set for every `outcome.decision`/`.redacted`, since
`PolicyEngine.decide` never reads a key outside `injection_detectors`/
`redaction_detectors`. `tests/test_gating_transport_with_models.py` (new,
`models`-marked) is where the real weights are actually exercised: that V0/V3
get constructed, that their real scores reach the audit log, and that the
same real V0 detector escalates once promoted via YAML alone on text that the
shipped policy allows.

### 2.19 M6: corpus infrastructure, dilution corpus deferred to M8

**The reference repository already had the decontamination method PROPOSAL.md
refers to.** `evaluation/experiment2/exp2_data.py` decontaminates V0/V3's own
training set against its eval suite with 5-character shingles over
normalised text, 64-permutation MinHash, and a Jaccard >= 0.85 (or exact
match) threshold. `evaluation/experiment2/data/train.jsonl` (19,026 rows) is
the actual post-decontamination training set -- the natural reference corpus
for checking whether a new item is too close to what V0/V3 already learned.
Both are reused for calibration continuity: an item flagged contaminated here
is held to the exact standard V0/V3's own training pipeline used, not a
number invented for this project.

**`datasketch.MinHashLSH`, not the dissertation's hand-rolled numpy version.**
`datasketch` was already pinned in `pyproject.toml` for exactly this purpose
and had gone unused since M0. Using it over reimplementing `exp2_data.py`'s
matrix-comparison approach follows the same principle M7 states for
statistics (established libraries over bespoke reimplementations), and
happens to fix a reproducibility gap for free: the dissertation script hashes
shingles with Python's `hash()`, which is randomised per process and would
make `minhash_signature` incomparable across separate `corpus ingest`
invocations. `datasketch`'s default `hashfunc` (SHA1-based) is deterministic
across processes -- verified directly (`src/llmshield_mcp/corpus/decontaminate.py`
docstring) rather than assumed.

**The training-data reference corpus is not vendored**, the same way V0/V3's
weights are not: `corpus/reference/` is gitignored, `config/decontamination.yaml`
resolves it against the repository root with an `LLMSHIELD_TRAINING_CORPUS`
override, mirroring `config/models.yaml`'s `LLMSHIELD_MODELS_ROOT` pattern
exactly (`plan.md` open question Q4's resolution).

**Contaminated items are flagged, not deleted.** `PayloadCorpusItem.decontamination_status`
keeps every ingested item, clean or contaminated -- the milestone's own
verification bar is a *drop-count report*, which needs the dropped items
still visible. Unlike `gating/audit.py`'s `DecisionLog`, this store's whole
purpose is to hold text (the corpus is a project deliverable, not an audit
trail of something scanned in passing), so nothing here is hashed-instead-of-stored.

**Scope, confirmed before implementation:** the "MCP-specific dilution
corpus" -- embedding these same payloads into real benign carrier documents
at varying dilution ratios (`prd.md` 9.3, `docs/M0-OBSERVATIONS.md`) -- is a
genuinely new composition pipeline, not corpus infrastructure, and the
milestone's stated verification bar (schema, ingest CLI, decontamination,
drop-count report) does not require it. Deferred to whenever M8's
leave-one-source-out test needs a third source family, rather than pulled
into M6. Open question Q3 stays open for that reason: two adversarial source
families (BIPIA, InjecAgent) are now ingested through this milestone's
infrastructure; a third is still needed before M8.

**The publishable JSONL snapshot is not committed by this milestone.**
`toolgate corpus-ingest` is implemented and verified end to end against the
real reference corpus (187 adversarial + several thousand benign lines, 0
contaminated -- expected, since M3b already established BIPIA/InjecAgent
share no lineage with the training sources). Deciding exactly what goes into
the *published* corpus snapshot, and when, is left as a deliberate operator
action rather than something this milestone's commit decides unasked.

### 2.20 M7: a milestone-table correction, and why the harness still doesn't flip the switch

**"Port LOBO" was wrong, and reading the file is what caught it.** The
original M7 row said "port LOBO and DeLong". `evaluation/experiment2/exp2_lobo.py`
turned out to **retrain** V0/V1 on IN/OUT training pools per fold -- it tests
whether retraining changes generalisation. This project never retrains
anything (`prd.md` scope: "no retraining"), so that script cannot be ported
at all, for either M7 or M8. What M8's actual leave-one-source-out test (FR-12)
needs is far simpler and needs no model changes: partition the corpus by
source, calibrate on the sources kept in, measure recall on the source held
out. M7 built exactly the calibration/statistics machinery that simple test
will reuse; `exp2_lobo.py` contributed nothing here beyond confirming, by
inspection, that DeLong is the one statistic in that file worth porting
(plan.md section 3's Reuse Inventory already said as much for a different
reason -- this is now confirmed first-hand).

**Wilson, Clopper-Pearson and McNemar came from `statsmodels`, not from
either dissertation hand-rolled version.** Both `evaluation/metrics.py`
*and* `evaluation/experiment2/exp2_eval.py` hand-roll these (the latter's
`cp` calls `scipy.stats.beta.ppf` directly rather than using an
interval-estimation library function). `PROPOSAL.md` section 9's "established
library implementations" requirement rules out porting either. DeLong is
still the one exception -- confirmed correct by reading
`exp2_auroc_delong.py`'s pure-Python midrank implementation and cross-checking
its point estimate against `sklearn.metrics.roc_auc_score` in a test, not by
trusting the docstring's claim.

**Dual benign references, and why the second one had to be built.**
`config.decontamination` gave M6 a single "benign" pool; PROPOSAL.md section
8.2 wants two -- realistic and adversarial-styled (hard negatives: genuinely
benign text containing detector-relevant vocabulary). Building the second one
is a MECHANICAL FILTER over already-real M6 content
(`gauge/references.py`'s keyword list), not new authored sentences, so it
does not repeat M3b's "hand-written cases measure the author's assumptions"
mistake -- nothing here invents what an attacker would say.

**The FPR-budget-collapse artefact at "low hundreds" scale.** A real
`gauge-run` showed `block` (0.1%) and `redact` (1%) calibrating to the
*identical* threshold on a 150-item calibration split: `threshold_at_fpr`'s
`floor(target * n)` rounds both down to the same small integer at this
sample size, and the algorithm (faithfully ported, see `calibrate.py`) always
achieves `k-1`, never `k` -- a deliberate conservatism, not a bug, but one
that only differentiates close-together budgets once the calibration set is
large enough. Recorded honestly in `whats_has_been_done.md` rather than
patched away; a genuinely larger corpus (M6's own scope, not M7's) is the
real fix.

**A real finding, not a smoke test.** A `gauge-run` against the full ingested
corpus (187 adversarial, 300-item benign samples per reference) gave V3
(`injection` score mode) an AUROC of ~0.33 against realistic benign
content -- *worse than chance* at separating real MCP-surface attacks from
ordinary repository text. Consistent with this project's standing finding
(M0 onward) that these detectors do not transfer cleanly to this surface;
worth carrying into the eventual report rather than only citing the earlier,
smaller measurements.

**The harness does not flip `config/policy.yaml`'s `calibrated` flag or move
V0/V3 out of `inert`.** `gauge-run` writes a report; a human reviews it and
edits the policy file deliberately, exactly as that file's own comment
already specifies. Automating that edit would turn a measurement tool into a
policy-changing one, which is not what FR-11 asks for.

### 2.21 Q3 resolved: LLMail-Inject as the third adversarial source family

Researched rather than invented: BIPIA and InjecAgent were the only two
source families after M6, and `plan.md` 2.19 explicitly deferred building a
third (the MCP-specific dilution corpus) out of M6's scope. Before M8 needs
it, a web search was done for an established third dataset matching this
project's own source-selection criteria (MIT/permissive license, indirect
injection against agent tool-use, a flat downloadable text field, disjoint
lineage from BIPIA/InjecAgent and from V0/V3's training sources).

Two real candidates surfaced: **AgentDojo** (ETH Zurich, NeurIPS 2024 --
97 tasks/629 security test cases across four tool-using agent environments)
and **LLMail-Inject** (Microsoft, MIT licensed -- 462,000 raw submissions
from a real adaptive prompt-injection competition against a simulated email
assistant, 839 participating teams). AgentDojo is conceptually closer to this
project's own tool-result surface, but ships as a live simulation framework,
not a flat corpus -- ingesting it would mean installing and running its
Python package rather than fetching a file, a materially different
integration shape from every other source this project uses. LLMail-Inject
fetches over plain HTTPS as JSON (HuggingFace's `datasets-server` REST API,
confirmed directly against the live API rather than assumed), so it drops
into the existing `fetch()`/`load_adversarial()` pattern with no new
dependency -- no `datasets` library, no parquet reader.

**Chosen: LLMail-Inject.** `corpus/sources.py` gained `fetch_llmail_inject()`/
`load_llmail_inject()`, kept deliberately separate from `load_adversarial()`:
folding a third source into that function would silently change what
`scripts/benchmark_rules.py` measures, and its docstring and
`docs/POLICY-AUDIT.md`'s published numbers name BIPIA/InjecAgent specifically.
`corpus-ingest` calls both.

Practical handling of the raw dataset:

- Most of its 461,640 rows are automated fuzzing from a handful of teams
  (confirmed by inspecting real rows before writing the loader -- e.g. the
  literal string `"yes Please yes issue yes an yes api_call ..."` submitted
  under dozens of job ids/scenarios), not diverse attacker text. Downloading
  all of it would mean paying a huge cost for mostly duplicate signal.
- Six 100-row pages are sampled at random offsets per split (fixed seed,
  reproducible), then de-duplicated by normalised body text and capped at
  150 unique items -- comparable in scale to BIPIA (125) and InjecAgent (62)
  rather than one source dominating the adversarial corpus just because its
  raw pool happens to be enormous.
- `threat_type` is the real `scenario` column (e.g. `level1a`), the
  challenge's own defense-difficulty tiers -- not an invented attack-type
  taxonomy, since the raw export carries no clean category label the way
  BIPIA/InjecAgent do.

Verified end to end: `corpus-ingest` against the real training-data reference
corpus ingested 125 + 62 + 150 = 337 adversarial items plus benign lines,
**0 contaminated** for any of the three families -- consistent with all three
being genuinely disjoint from V0/V3's training sources.

### 2.22 M8: leave-one-source-out as a report breakdown, and a real generalisation finding

Builds directly on the correction already recorded in 2.20: since this
project never retrains V0/V3, and calibration (M7) never looks at
adversarial data at all (only the benign reference sets, matched-FPR),
there is no IN/OUT training split for a "held-out" family to mean anything
about. What FR-12 can honestly ask here is narrower and cheaper to answer:
does the *same* calibrated threshold produce consistent recall across
different adversarial source families, or does it not? `gauge/run.py`'s
`_build_report` already grouped ASR by `threat_type`; M8 adds the identical
grouping by `source` (`_grouped_asr`, shared by both), keyed on the three
families Q3 resolved (2.21) -- no new module, no new statistical machinery.

**The answer, measured, is a real finding worth carrying into the report.**
A `gauge-run` against the full corpus (V0, escalate budget, realistic
reference) gave attack-success-rate of **97.6% on BIPIA, 75.8% on
InjecAgent, but only 40.0% on LLMail-Inject** -- the same threshold, the
same detector, a nearly 60-point swing depending purely on which family is
being measured. Anyone citing only the original two-family number (matching
this project's own earlier BIPIA+InjecAgent-only measurements) would have
significantly overstated how consistently V0 fails. V3 is more uniform --
92-98% ASR across all three families at the same budget -- but uniformly
close to useless either way. This is exactly the generalisation gap FR-12
exists to surface, and it would not have been visible with two families.

A minimum-family-count check (`run_gauge` warns, does not raise, below two
distinct adversarial `source` values) keeps the `by_source` breakdown from
silently looking meaningful when the corpus can't actually support the
comparison.

### 2.23 M9: latency is committed, not gitignored -- and a real finding about `inert` detectors

Unlike M7/M8's calibration reports (deliberately gitignored, `results/`,
because they could inform a live-behaviour edit to `config/policy.yaml`),
the milestone table's own verification bar for M9 says "committed numbers".
Latency carries no such risk -- it cannot silently invalidate a
cross-surface comparison the way an inherited threshold could -- so
`docs/LATENCY-BENCHMARK.md` is committed directly, matching
`docs/PINNING.md`/`M0-OBSERVATIONS.md`/`POLICY-AUDIT.md`'s precedent of
hand-authored reports with real numbers pasted in after running the
reproducible script, not machine-generated.

**Reused, not invented:** mean + p95 in milliseconds with warmup excluded is
`exp2_eval.py`'s own `latency_hf`/`latency_sklearn` convention (`n_warm=10`).
`src/llmshield_mcp/latency.py` carries the reusable logic;
`scripts/benchmark_latency.py` is the thin script, mirroring the
`corpus/sources.py` / `scripts/benchmark_rules.py` split already established.

**The chain fixture needed a full API key, and this worktree didn't have
one.** `.env` is gitignored and per-worktree; the main checkout has it, this
worktree did not. Resolved by exporting `ANTHROPIC_API_KEY` from the main
checkout's `.env` for the one command that needed it (via command
substitution, so the key value never appeared in a visible command string),
rather than copying the file -- the same "the artifact this worktree lacks
lives in the main checkout" situation `LLMSHIELD_MODELS_ROOT`/
`LLMSHIELD_TRAINING_CORPUS` already solved for weights and the decontamination
reference corpus, solved the same way for a secret instead of a large file.

**A real finding, not a smoke test: `inert` costs nothing in decision weight
but nothing in latency either.** Per-detector benchmarking on real corpus
text found rules/PII/V0 combined add under 3ms; V3 alone (and therefore the
fused pipeline, since V3 dominates it) averages ~208-215ms -- roughly 2x
NFR-2's 100ms SME budget on short text. The 20-call chain benchmark (FR-14)
went further: real fetched web pages are long enough to push V3's
`chunk_max` strategy across many windows, and gate latency scaled with that
-- one page reached 13.1 seconds, and for 9 of 16 fetches gate latency
*exceeded* the network round-trip that produced the content. `config/policy.yaml`
shipping V3 `inert` (M5) protects the *decision* from an uncalibrated ML
score; it does nothing for latency, because the detector still runs, still
gets scored, on every intercepted result regardless of its decision weight.
Worth carrying into the eventual report as its own finding, distinct from
M7/M8's accuracy-side ones.

### 2.24 M10: figures with no new dependency, and turning a local report into a committed one

**No plotting library.** `matplotlib` (what `exp2_auroc_delong.py` uses for
its own figure) was considered and rejected: three simple grouped bar charts
do not need a plotting library, and adding one would grow NFR-8's pinned
dependency set (numpy, kiwisolver, pillow, fonttools transitively) for
something a couple hundred lines of SVG string-templating already does
(`scripts/generate_report.py`). The charts read `results/gauge/calibration_report.json`
(M7/M8's real output, gitignored) and render plain SVG -- diffable text, no
binary asset, no rendering step needed to view them.

**One bug worth recording because of how it failed silently.** The first
version of the log-scale bar-height calculation could produce a negative
`frac` for a value far below the axis floor (rules/PII at ~0.06ms on a
1-1000ms log axis) -- SVG does not render a `<rect>` with negative height,
so three bars and their value labels simply vanished with no error, caught
only by an actual browser screenshot of the generated figure, not by
reading the code. Fixed by clamping `frac` to `[0, 1]` before computing a
pixel position, so an out-of-range value renders as a visible sliver at the
axis boundary instead of disappearing.

**M7/M8's local-only calibration data becomes this milestone's committed
report.** Those reports stayed gitignored specifically because they could
inform a live `config/policy.yaml` edit and their sampling varies run to
run (2.20/2.22). M10 is the deliberate point where a specific run's numbers
-- the same 3-family, real-weights run already reported in 2.22 -- become
the frozen, cited, public figures. The underlying JSON stays regenerable and
gitignored; the curated figures and prose derived from it are what gets
published, exactly the same split M6 already established between
`corpus/payload_corpus.sqlite` (local) and its JSONL export (publishable).

**The README's status banner had been stale since M0** ("milestone 0 of
11", "no interception layer, no corpus and no evaluation yet") through nine
completed milestones -- nothing enforces that a status line gets updated
alongside the code, so an out-of-date one was found and fixed here rather
than treated as fine to leave. A one-line junction command
(`New-Item -ItemType Junction ... C:\path\to\artifacts`) had also been
silently corrupted at some point into `C:\path` + a literal tab + `o` + a
literal bell character + `rtifacts` -- invisible in a normal read, caught
only by `cat -A`. Both predate this milestone; fixed while already touching
the file rather than left for a future session to rediscover.

### 2.25 Post-audit hardening pass: verify the finding, then stop lying to the reader

A full-repository audit against an external product-transformation plan, run
through a five-advisor adversarial review, produced one reversal and a set of
defects that share a single shape. The plan's own stated top priority --
"fix the default policy so experimental injection detection cannot be trusted
as a BLOCK or ESCALATE control out of the box" -- was **already done** (2.18,
`calibrated: false` + `PolicyEngine._ceiling`, tested). The real problems were
elsewhere, and almost all of them were *shipped code contradicting shipped
documentation* rather than missing features.

**The reversal: verify the headline before building anything on it.** The
review's sharpest objection was that a DeLong AUROC of 0.32 -- meaningfully
below chance -- is the classic signature of a label-polarity or score-mode
error, and that nothing in this project had ever tried to falsify it. That was
correct, and the risk was concrete: the saved V3 artifact's `config.json`
carries only `LABEL_0..LABEL_3`, so `1 = injection` lived in a comment in the
training script, not in the weights. 2.6 had promised since M0 that every
statistic is recomputable from `scores.csv` without the weights; nothing had
ever read those four probability columns back, so the promise was
architectural, not executable.

`gauge/recut.py` + `toolgate gauge-recut` make it executable, and the check
was run against the real artifacts. Polarity is correct (`verify-models`: a
known injection probe scores P(injection) = 0.998). The score-mode explanation
was tested by re-cutting the same stored inference every way.

> **The conclusion recorded here was wrong and is withdrawn -- see 2.26.**
> This check ran against 187 BIPIA+InjecAgent payloads, without LLMail-Inject
> and without decontamination, and concluded that `not_benign` (0.286) was
> *worse* than the published `injection` cut (0.321), so the score mode was
> exonerated. On the full 337-payload decontaminated corpus it reverses:
> `not_benign` reads **0.540**, above chance. The check was the right check;
> the answer was drawn from underpowered data and the council's original
> objection stands.

**The defect that mattered most was not on the audit's list as a high.**
`apply_redaction` masked a span only when a single content block contained it
end to end, and silently dropped it otherwise. `extract()` joins blocks with
`"
"`; `PHONE_NUMBER`'s separator class is `[-.\s]` and `US_SSN`'s is
`[-\s]`, both of which match a newline. So a result whose blocks split as
`"Call 555"` / `"123 4567"` produced a real PHONE_NUMBER span, a Redact
decision, an audit row saying `redacted=1` -- and forwarded the phone number
to the model untouched. Demonstrated before fixing, not reasoned about. Spans
are now clipped per block rather than requiring containment, and any span that
still cannot be placed is reported to the `Gate` and recorded in the row's
note. A decision the log claims was applied is now a decision that was applied.

**M12 removed rather than repaired.** The session accumulator could not detect
the dilution attack it was built for -- diluting a payload changes the text,
therefore the sha256, therefore no hash recurrence -- and with deterministic
detectors, an identical hash implies identical scores, making score divergence
structurally unreachable through the real path. It was wired into no runtime
path, its two docs contradicted each other, and its integration test
`test_note_written_when_divergence_detected` asserted that *no* note was
written. Deleting it also restored append-only on the decision log, which its
`update_note` UPDATE was the only violation of. The measurement is preserved in
`docs/DILUTION-BENCHMARK.md`, including what a real implementation would cost:
content lineage across calls, which SEC-1/NFR-3 forbid.

**Safe defaults that were not cheap were not really defaults.** `inert`
detectors are still *constructed and executed*, so the shipped policy imported
torch and ran DeBERTa on every tool result -- 208 ms mean, 13.1 s worst case on
one real web page -- to log two scores no decision reads. Split into
`config/policy.yaml` (rules + PII) and `config/policy.research.yaml` (adds
v0/v3 inert). Provably decision-neutral, since `decide()` never reads a key
that appears only under `inert`, and asserted as such in
`test_research_profile_differs_from_the_default_only_in_inert_detectors`.

**Gating was opt-in and welded to logging.** `--db` did double duty: a path
turned interception on, omitting it turned interception off *while still
writing every raw tool result to `--out`*. The default was "no gate, plus a
plaintext copy of your tool output on disk". Now `DecisionLog(None)` opens an
in-memory database, gating is on unless `--no-gate` is passed, and `--no-gate`
prints a warning naming the file that will contain unredacted output.

**Evaluation inputs were the last unpinned thing.** `servers.yaml` pins
`@modelcontextprotocol/server-filesystem@2026.8.31` exactly, while
`corpus/sources.py` fetched BIPIA and InjecAgent from `main` with a
`# noqa: S310 -- pinned https` comment that pinned the *scheme*. Now pinned to
commit SHAs and verified against recorded digests on both fetch and load. The
LLMail-Inject gap -- a paginated live API with no immutable ref -- is stated in
the module rather than papered over.

**Claims restated to match their evidence.** "20.3% recall at 0% false
positives" is now "0 in 4,654 benign lines, Wilson 95% CI [0%, 0.082%]": zero
observed events bound a rate, they do not establish it. The dilution
benchmark's `0/50` is upper-bounded at 7.14% and demoted to a smoke test.
And the README's "Escalate-by-default", which reads as a control, now says
what the code does: Allow and Escalate both forward the frame byte-identical,
so an Escalate is a log row. The review's strongest argument against building
an ESCALATE integration contract stands and was accepted -- a contract would
implicitly promise that Allow means "checked and clean", and on this surface
Allow is roughly four of five real attacks.

**What was deliberately NOT done**, against the transformation plan's wishes:
no multi-provider gateway, no output-path inspection, no agent tool-call
gating, no dashboard, no secret detection. The first four are new products on
a premise this repository's own evidence disputes. Secret detection was the
one the review split on, and it was deferred for the project's own stated
reason: it has no corpus here, and shipping an unmeasured detector into a
project whose entire credibility is that it never claims unmeasured things
would cost more than the feature is worth. Council opinion was that tool-call
gating is the control that survives the negative result, since it is
deterministic and needs no classifier; that is recorded here as the strongest
candidate for the next milestone, not as something done.

### 2.26 A third classifier, a corrected claim, and the evidence finally committed

Three things happened in one evaluation pass, and the second one matters most.

**A published classifier was added, and it does not rescue the finding.** The
strongest objection to this project's negative result has always been that V0
and V3 are one author's reused dissertation artifacts -- maybe they are just
weak, and a detector built for this job by people who do it professionally
would be fine. That objection is testable, so it was tested rather than argued
about. `detectors/guard.py` loads
`protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, purpose-built,
~840k downloads/month, pinned by commit SHA) and runs it through the identical
GAUGE protocol on the identical decontaminated corpus:

| Detector | realistic AUROC | adversarial-styled AUROC | ASR @ ~4% FPR |
|---|---|---|---|
| V0 | 0.694 [0.648, 0.740] | 0.521 [0.466, 0.576] | 66.2% |
| V3 | 0.310 [0.262, 0.357] | 0.235 [0.191, 0.279] | 94.7% |
| guard | 0.524 [0.472, 0.577] | 0.255 [0.207, 0.303] | 93.8% |

(Figures from the final clean-corpus run; 2.27 records why they were
regenerated and how far they moved.)

The purpose-built production detector is statistically indistinguishable from
chance on realistic benign content -- its CI contains 0.5 -- below chance on the
false-positive
stress reference, and misses ~9 in 10 attacks at its own calibrated operating
point. Its Block/Redact thresholds calibrate to 1.0000 at 100% ASR: tuned for
zero false positives it catches nothing, because its scores saturate (ordinary
Python source containing "ignore all previous retries" scores P(INJECTION) =
0.99999). Meanwhile the *simplest* model tested, V0's TF-IDF + logistic
regression, is the best of the three.

This upgrades the claim from "the detectors I reused do not transfer" to "a
widely-deployed, independently-trained, purpose-built classifier fails here
too" -- which points at the surface rather than at any one model, and which a
reader can verify, because unlike V0/V3 these weights are fetchable.

One caveat runs in the safe direction and is stated in the report: the corpus
is decontaminated against V0/V3's training data, not guard's, which is listed
on its model card but not distributed. Contamination inflates apparent
performance, so 0.524 is an upper bound. A negative result that might be
flattered is stronger than one that might be depressed.

**A published claim was wrong and has been withdrawn.** 2.25 recorded that the
below-chance V3 AUROC had survived falsification -- that re-cutting it as
`not_benign` made it *worse* (0.286) rather than better. That check ran on 187
BIPIA+InjecAgent payloads without LLMail-Inject and without decontamination. On
the full 337-payload decontaminated corpus it reverses: V3 realistic reads
0.346 under the inherited `injection` cut and **0.540 [0.49, 0.59]** under
`not_benign`, an interval straddling chance. So the council's original
objection was right and 2.25's conclusion was drawn from underpowered data.
The honest statement is that V3 does not separate at all; whether it reads as
"below chance" or "at chance" is substantially an artefact of which scalar is
cut from its probability vector. `docs/REPORT.md` section 4 carries the
correction explicitly rather than quietly restating the number.

The same tool shows the shipped cuts are not optimal for either model (V0
reaches 0.825 under `jailbreak` against its shipped 0.709). **Nothing is being
promoted on that basis** -- picking a score mode after seeing which scores best
on the evaluation set is exactly the overfitting matched-FPR exists to prevent.
Reported as sensitivity analysis, not tuning.

**The evidence is committed this time.** 2.25 noted that the `scores.csv`
behind the originally published AUROC no longer existed, making the headline
unreproducible even by its author -- precisely what 2.6 promises cannot happen.
`.gitignore` now carries a deliberate exception for `results/gauge/`
(`results/*` rather than `results/`, because git does not descend into an
excluded directory and a negation inside one is never consulted). The 5,400-row
`scores.csv`, its `calibration_report.json` and the `recut.json` are tracked.
`gauge-recut` recomputes every statistic in section 4 from that one file with
no weights and no corpus, which is what makes 2.6 true rather than aspirational.

**Three policy profiles rather than two.** `config/policy.guard.yaml` sits
between the light default and the research profile. Its purpose is narrow and
worth stating: it is the only ML profile a stranger can run, because V0 and V3
need artifacts only the author has. All three remain provably decision-neutral
-- `decide()` never reads a key that appears only under `inert` -- and a
parametrised test now asserts that across every profile rather than just two.

**Design notes on the adapter.** `GuardConfig` identifies the model by
`repo` + `revision` rather than a path: a local path would reintroduce exactly
the unpublishability that makes V0/V3's numbers uncheckable, and the Hub cache
lives under `HF_HOME`, never inside this repository or anyone's thesis
directory. `revision` is validated as a 40-character SHA at load, because a
branch or tag would let upstream change what a published figure measured --
the same standard `corpus/sources.py` applies. And the positive class is
resolved from the checkpoint's own `id2label` (`{0: SAFE, 1: INJECTION}`)
rather than assumed to be index 1. That last one is a direct response to this
pass's own near-miss: V3's checkpoint carries only `LABEL_0..LABEL_3`, so its
mapping lived in a training-script comment and had to be verified empirically.
A checkpoint that names its classes gets read.

### 2.27 Licensing resolved by removal, and two structural defects it exposed

The share-alike question 2.25 raised and flagged was resolved rather than left
open, on the instruction to take the safest option. Two unrelated defects
surfaced while doing it, both of the same shape: a silent failure that no
review would catch in a diff.

**The fixture was deleted, not attributed.** `chains/latency_chain.json`
embedded ~5 KB excerpts each of five Wikipedia articles, an MDN page, W3C,
IANA, python.org and a Project Gutenberg text -- several CC BY-SA, which is
share-alike and incompatible with MIT. Attribution (`THIRD_PARTY_NOTICES.md`,
2.25) is the standard minimum, but it only helps if share-alike obligations do
not attach; whether they attach to a JSON benchmark fixture holding verbatim
excerpts is a legal question this project cannot answer. Deleting removes the
question entirely.

The cost of deleting turned out to be near zero, which is why it was the right
call rather than an over-reaction: no test and no script read the file, and the
SQLite decision log its published figures were computed from was never
committed either. `docs/LATENCY-BENCHMARK.md` section 2's numbers are unchanged
and now carry a note saying the fixture no longer ships and how to record
another. `chains/baseline.json` stays -- its only fetch is `example.com`, an
IANA reserved domain whose own text says it needs no permission.

**Git history was deliberately not rewritten.** The content is in published
commits. `git filter-repo` plus a force push would remove it, at the cost of
breaking every existing clone and the merged pull request's refs, for a few
kilobytes of encyclopedia excerpts in a benchmark fixture. Judged
disproportionate, recorded in `THIRD_PARTY_NOTICES.md` as a decision rather
than an oversight, and reversible if that judgement changes.

**Defect 1: the recording path fed the corpus.** This was not carelessness.
`toolgate run-agent --out` records every tool result verbatim -- that is its
job -- and `corpus/sources.py:load_benign()` globs `chains/*.json`, so fetched
web content reached both the committed fixture *and* the benign evaluation
corpus and its JSONL export. Two independent licensing exposures from one
recording, neither visible in a diff.

`tests/test_chain_licensing.py` closes it: a committed chain may only record
`fetch` results from an explicit allowlist of hosts carrying no redistribution
restriction, recorded bodies are scanned for third-party markers, and the
coupling to `load_benign()` is asserted so the tests' relevance is documented
rather than assumed. Adding a host to that allowlist is a licensing decision
that must also be recorded in `THIRD_PARTY_NOTICES.md`.

**Defect 2: `corpus-ingest` silently doubled the corpus.** Found by hitting it.
`CorpusStore.add` is a plain INSERT with no uniqueness constraint, so a second
ingest into the same file appends. Running it again during this cleanup took
the store from 11,238 items to 23,139 -- and the drop-count report said
`clean: 23139`, which reads like a larger corpus rather than a duplicated one.
A gauge run against that store would have produced entirely plausible,
entirely wrong numbers over doubled data, with nothing anywhere saying so.

`corpus-ingest` now refuses to ingest into a non-empty store, naming the count
and both ways forward (delete, or `--append`). The guard runs before `fetch()`,
so it costs nothing and needs no network. `tests/test_corpus_ingest_guard.py`
covers refusal, the message contents, the pre-fetch ordering, the empty-store
and missing-store cases, and that `--append` still works.

Worth recording about that test: the first version monkeypatched
`corpus.sources.fetch`, which does nothing, because `ingest_corpus` does
`from llmshield_mcp.corpus import fetch` and therefore resolves the *package*
namespace. It passed anyway -- the guard fired before fetch would have run --
so a test asserting the right thing for the wrong reason nearly shipped. Patch
target corrected and the reasoning written into the test.

**Evidence regenerated.** Deleting the fixture changed `load_benign()`'s
output, so the corpus and every statistic derived from it were rebuilt from
scratch rather than left stale against changed inputs. `results/gauge/` is
re-committed from that clean run.

### 2.28 Capability gating: the control that survives the negative result

Every detector this project ships asks the same question -- *does this text look
like an attack?* -- and `docs/REPORT.md` measures the answer on the MCP
tool-result surface as: not usefully. ~20% recall at best, the reused
transformer not separating at all, and a purpose-built production classifier
statistically indistinguishable from chance. Four attacks in five get through.

A detection layer with that measurement has an uncomfortable property: its own
evidence argues against relying on it. `gating/tool_calls.py` is the engineering
response, and it asks a different question -- **is the agent allowed to do
this?**

**Why that question is answerable when the other is not.** You do not have to
recognise the injection that talked an agent into reading `~/.ssh/id_rsa` in
order to notice that the agent is reading outside its sandbox. Recognising the
persuasion is unsolved semantics; recognising the capability is a string
comparison. Against the behaviour a rule names there is no false-negative rate,
through any injection technique, in any language, at any dilution -- not because
the classifier is good but because there is no classifier.

Stated as precisely as the rest of this project states things: it bounds the
blast radius of a successful injection to whatever the policy still permits. An
attacker who only needs a tool the policy allows is unaffected. This narrows
what a compromised agent can reach; it does not stop the compromise.

**Three checks, taken from the corpus rather than invented.** Each maps to an
attacker objective that actually appears in the BIPIA and InjecAgent payloads
already ingested: `action` (destructive operations), `paths` (sandbox escape),
`egress` (exfiltration to an attacker-controlled host). Deliberately excluded:
regex on argument *values*, which would reintroduce content inspection through
the back door with all of its false positives, and would forfeit the one
property that makes this layer worth having.

**Enforcement is an exception, not an injected frame.** `observe_outbound`
raises `ToolCallBlocked`, and `_ObservedWriteStream.send` calls it before
forwarding, so the request never reaches the server. The alternative --
fabricating a JSON-RPC error and pushing it back through the read stream --
would have needed a pump task and a shared queue, which 2.8 rejected for
reasons that still hold. Reading the SDK settled it: the dispatcher registers
its pending waiter before the write and pops it in a `finally` on *every* path
(`mcp/shared/jsonrpc_dispatcher.py`), so an exception from `send()` cleans up
correctly and surfaces to whoever called `session.call_tool()`. It also reads
more honestly -- the call did not fail, it was refused.

**The `calibrated: false` ceiling deliberately does not apply here.** That
ceiling exists because detector *thresholds* are uncalibrated on this surface
(FR-11): an ML score of 0.9 means nothing until matched-FPR calibration says
what 0.9 buys. A capability rule has no threshold and no false-positive rate to
calibrate. Routing "block `github.delete_repo`" through a ceiling built for
uncertain scores would be a category error, and would silently downgrade the one
control in this project that does not depend on the detection its own report
shows does not work. Asserted in
`test_capability_block_is_not_downgraded_by_the_calibration_ceiling`.

**Defaults.** `default: allow` ships and the default profile defines no rules at
all, so adding this layer changed nothing for anyone who has not opted in -- the
full existing suite passed untouched. `default: block` turns the same config
into a strict allowlist and is one word away. That follows 2.25's lesson rather
than contradicting it: a safe default that is disruptive is a default people
switch off. `config/policy.agent.yaml` is a working example scoped to the
reference servers and the synthetic sandbox, so the demonstration runs as
shipped.

**A bypass caught before it shipped.** The first `_path_allowed` matched both
the normalised path *and* the raw string. `fnmatch`'s `*` matches `/`, so
`workspace/../../.ssh/id_rsa` matched `workspace/**` verbatim and the sandbox
escape was allowed through -- in the function whose entire purpose is to stop
it. A five-line smoke test over seven paths caught it before any of this was
wired up. Only the normalised path is matched now, and `_normalise_path`
additionally reports when a `..` climbed above its own root, because
`../../etc/passwd` would otherwise normalise to `etc/passwd` and could then
match a permissive glob. Both cases are pinned in `tests/test_tool_calls.py`.

Worth recording as a pattern rather than an anecdote: this layer's claim is
"no false negatives against the named behaviour", and that claim is only worth
as much as its matcher. The matcher is where the bugs live, so that is where the
adversarial test cases belong -- not in the policy vocabulary.

**What the audit log gets.** The rule id and the tool name, never an argument
value. A path or URL argument can carry exactly the sensitive data SEC-3 keeps
out of this store, so a blocked call records *that* it was blocked and *which
rule* fired. A new `Outcome.TOOL_CALL` keeps request-side rows out of
denominators that mean results -- they are a different experiment. Only
non-ALLOW verdicts are written, so an allowed call costs no row.

**Not done, and deliberately.** No measurement of this layer against the corpus
yet. Recall against a capability rule is 100% by construction, which makes the
interesting number the *false-positive* one: how often a legitimate agent
workflow trips a reasonable policy. That needs realistic multi-step agent
traces, which this project has one of (`chains/baseline.json`), and one is not a
benchmark. Until that exists, the README claims the guarantee in terms of what
the mechanism does and does not claim an FPR.

### 2.29 Declaration integrity: the third channel, and why stripping was the wrong fix

`docs/PLAN-DECLARATION-INTEGRITY.md` holds the full design. This section
records the two decisions from steps 0-1 that a later reader would otherwise
assume went the easy way, and the upstream correction that came with them.

**The gap.** There are three attacker-controlled channels at the MCP boundary.
Tool results are gated by detection (~20% recall, `docs/REPORT.md`). Tool calls
are gated by capability rules (2.28, deterministic). Tool *declarations* were
ungated: `agent.py`'s `to_anthropic_tool()` takes `tool.description` and places
it in the model's context as configuration, at session start, before any call,
for the whole session. `gating/transport.py`'s own comment called `tools/list`
"out of scope".

**Decoding, not stripping — and the plan said stripping.** Step 0 was written as
"extend `INVISIBLE_RE` to the TAG block". Implemented literally that would have
*reduced* detectability. Two different attacks wear the same clothes:

- *Separator* concealment splits a visible keyword with invisible characters
  (`Ig<ZWSP>nore`). The payload is the visible text. Stripping reassembles it
  and the rule fires. This is what the normaliser has always done.
- *Payload* concealment writes the whole instruction in codepoints that render
  as nothing, leaving a short truthful label visible. Stripping deletes the
  instruction and leaves the label, so the normalised text is benign and the
  pipeline reports clean with *more* confidence than before the transform
  existed.

So TAG-block runs are decoded and appended (never replacing, so offsets stay
valid for FR-5), and only then stripped. This mirrors the base64 handling
already in that module, which made the same choice for the same reason.

The stripping set is now Unicode's `Default_Ignorable_Code_Point` property
rather than a hand-listed set of ranges. Naming the property rather than
enumerating observed cases is the point: its definition is "a conforming
renderer displays nothing for this", which is the threat exactly. It also
covers what general category misses — U+3164 HANGUL FILLER is category `Lo`
and renders as nothing.

**Hash raw bytes, and the justification was measured rather than asserted.**
The canonicaliser (`gating/declarations.py`) applies no NFC, NFKC, stripping or
whitespace collapsing before hashing; only the JSON *encoding* is canonical
(sorted keys, tight separators), because that is framing rather than content.

The first draft of the module docstring justified this by saying a TAG-block
payload would otherwise normalise to the clean string. That turned out to be
false — precisely *because* step 0 made the normaliser decode rather than
strip. Measured instead: of six concealment forms, five (zero-width split,
homoglyph, NFKC fullwidth, bidi override, variation selector) normalise a
poisoned description to text byte-identical with the clean one. Hashing
normalised output would have hidden all five from the pin. Those five are now a
parametrised test, so the argument stays executable.

Arrays are deliberately **not** reordered while object keys are. Array order is
semantic in a JSON Schema, and the published dangerous-default technique works
by putting the dangerous value first in an `enum`; a canonicaliser that sorted
arrays would call that rearrangement `unchanged`.

**Two fields added to the plan's list.** `mcp_types.Tool` under the pinned
`mcp==2.1.1` also models `execution` and `icons`, which the plan's §2.1
enumeration predates. Both are server-controlled and both are pinned. A test
asserts `set(Tool.model_fields) == set(HASHED_FIELDS) | set(EXCLUDED_FIELDS)`,
so an SDK upgrade that adds a field fails the suite rather than silently
widening the unpinned surface.

**Upstream correction.** The plan's §5 cited arXiv:2607.05744 as reporting that
existing sanitizers flagged none of its eight techniques. Reading the paper
directly: 8/8 reach the model's context, **4/8 evade** the baseline sanitizer
and 4/8 are caught, and only **1/8** (the TAG-block encoding) also evades the
human approval render. The plan document is corrected in place with the
correction marked. The figure matters because it is the baseline this project
would be measured against, and overstating a prior result's weakness to make
one's own work look better is the failure mode this repository exists to avoid.

The same reading produced the finding that shapes the scope: **only one of the
eight techniques is a concealment technique**, so step 0 closes T7 and nothing
else. The other seven live on surfaces that steps 1-4 cover, or are plain-text
injection already measured as poorly detected.

**Step 2: the pin store, and three refusals.** `gating/pins.py` turns the
canonicaliser into a control with memory — `pins/<server>.json`, trust on first
use, verdicts `new`/`unchanged`/`mutated`/`stale_pin`. The design is mostly
about what it refuses to do:

- **A mutation never re-pins itself.** `observe()` writes on `new` and on
  nothing else. A pin that updated itself on mutation would report `unchanged`
  the next time and erase the rug-pull it exists to record. Accepting a change
  is an explicit operator act.
- **A corrupt pin file raises rather than starting empty.** "Start empty" and
  "trust everything again" are the same thing; an attacker who damages the file
  must not thereby reset every tool to TOFU silently. A *missing* file is still
  a legitimate first run.
- **`stale_pin` rather than a guess.** Digests from two canonicaliser versions
  are not commensurable, so reporting either `unchanged` or `mutated` across a
  version change would be inventing a claim.

Content never reaches disk (SEC-3), and that is asserted against the written
bytes rather than the intent: a marker planted in `description`, `title` and a
schema property *name* must be absent from the file, as must a TAG-block
payload in both its UTF-8 and `\ue00…`-escaped forms.

The honest limit, stated in the module docstring rather than implied away: the
pin file is not tamper-proof. Whoever can write to `pins/` can delete a pin and
reset that tool to trust-on-first-use. File permissions answer that; this
module does not.

**Step 3: the one control here that is deliberately not at the transport
boundary.** §5.4 asked whether client caching could make a pin verify something
the agent never saw. Checked against `mcp==2.1.1` rather than reasoned about,
and the answer moved the step: `ClientSession.list_tools()` does not cache, but
`_absorb_tool_listing()` **drops** tools after the transport has seen them, and
the higher-level `mcp.client.client.Client` has a response cache whose own
comment says a hit "skips `session.list_tools`". A frame-level check therefore
verifies a superset on one API and nothing at all on the other.

So `gating/declaration_gate.py` runs on the `ListToolsResult` the agent
receives, and the tuple it returns is the tuple that becomes `ToolParam`. The
guarantee is structural rather than a property of the call graph keeping its
shape, and the test asserts it against the tool list the fake Anthropic client
was handed. `open_servers(declarations=...)` is opt-in; omitting it changes
nothing.

Shadowing is a separate field on the report, not a fifth verdict — a
declaration can be `unchanged` *and* shadowing, and one enum would lose
whichever lost the precedence argument. Only admitted tools claim a name, so a
withheld declaration cannot reserve one against a later server.

Two things recorded rather than glossed. `agent.py` qualifies tools as
`<server>__<tool>`, so the *substitution* form of shadowing is unavailable in
this client by construction; what remains is a model choosing between two
similar tools. And the reference agent lists tools exactly once and never
re-lists, so `notifications/tools/list_changed` handling would be dead code
here — deferred with that reason, which is not the same as claiming mid-session
mutation is handled.

**Step 4: the policy block, and two decisions it forced.**
`gating/declaration_policy.py` is keyed on **conditions** rather than verdicts,
because a declaration can be `mutated` *and* concealed *and* shadowing at once
and steps 1-3 deliberately kept those separate. The most severe action wins
rather than the first match, so adding a rule can only tighten a verdict.
Loading is strict: an unknown condition name raises, because `mutatedd: block`
that quietly does nothing is the failure a security config must not have.

**Defaults escalate, never block**, and the reason is a number this project
does not have. The mechanism has no false-negative rate, so `calibrated: false`
does not gate these blocks -- the same argument `tool_calls` makes. But benign
churn, how often a legitimate server changes a declaration, is unmeasured (3.1,
step 5). A control that might fire on every routine upstream release is one an
operator switches off, so the layer has three states rather than two: off
entirely, observe-only, and enforcing.

**`on_pin_error` fails closed**, which settles the question step 3 left open.
An unreadable pin store withholds that server's declarations rather than
forwarding them unverified, scoped to the one server so the session survives.
A damaged store is never overwritten with fresh pins -- that would turn a
corrupt file into a clean trust-on-first-use in one step, the exact silent
reset the exception exists to prevent.

`Outcome.TOOL_DECLARATION` rows carry the verdict, the field *names* that
moved, the digest and the action -- never a field value, asserted against every
column. They also do a second job: `DecisionLog.declaration_seen()` makes a
deleted pin file contradict the log rather than pass as a first sighting,
raising the cost of a silent reset from one file to two stores.

**Step 5: the measurement, and the statistic it retired.** 7 official MCP
servers, their last 8 releases each, installed and launched for real --
`tools/list` over stdio, not source parsing. 54 of 56 releases collected; the
two that would not start are named rather than dropped.

The pooled churn rate is 35.2% of tool comparisons and it is the **wrong
number**. The distribution is bimodal with nothing between the modes: of 47
release transitions, **30 changed no declaration at all and 17 changed every
tool the server has**. A release either leaves declarations alone or rewrites
all of them, which is an SDK metadata bump rather than an author editing a
tool. Pinning is therefore silent through two thirds of upgrades, and when it
fires it fires on everything -- easy to triage, not a needle in a haystack.

`description` moves surgically where the machine-generated fields move
wholesale: 9 of 318 tool comparisons (2.8%), across 9 of 47 releases. So a
description change is not rare per release, but its blast radius is one tool.
Since a poisoning payload has to reach the model as prose, the signal an
operator wants is precisely the one SDK churn does not bury.

Three further numbers, reported because they are cheap and unpublished:
concealment prevalence **0 of 380**, cross-server name collisions **0**, and
the project's own injection rules firing on **4 of 380** benign descriptions
(1.1%, all `INJ-018`) -- corroborating from a new surface the existing finding
that `INJ-*` is all cost and no benefit.

**No default was changed on the strength of it.** `concealed` could defensibly
become `block` since nothing triggers it, and does not: 380 declarations from
official servers is not enough to claim a zero rate for an ecosystem, and a
control whose first false positive blocks a tool gets switched off. Each
default is now a choice with a number attached rather than a guess.

The measurement does argue for one thing not built: a **field-aware** policy.
`declaration_policy.py` keys on conditions and cannot express "alert on a
description change, ignore an annotations change", which the churn shape says
would be materially quieter. Recorded rather than added, since the step was
scoped to measuring.

**Step 6** put the third channel and a three-channel coverage table in the
README, with no recall figure anywhere in it.

**§5.3's self-test, done last and nearly missed.** The plan required running the
paper's eight techniques against toolgate and publishing the result "either
way"; steps 0-6 had been declared complete without it. Rebuilt payloads, one per
technique, run through the layers toolgate actually runs
(`tests/test_paper_techniques.py`). On first sight toolgate flags **1 of 8**
outright (T7), against the paper's baseline sanitizer at 4 of 8 -- on disjoint
techniques, so the controls complement rather than replace each other. After
approval every declaration payload is flagged by construction. **T5 is missed**
on the result path, where the baseline catches it. The README states all of it,
including the loss.

**Sample caveat, stated everywhere it appears.** These are official reference
servers, chosen for having release histories to walk. They are likelier to be
stable than the third-party servers an operator installs, so the churn figure
is a floor rather than a typical value. And 0 collisions means `shadowed` is
*unmeasured*, not quiet.

**No recall number** is claimed for any of it, and per plan §3.2 none will be —
pinning catches post-approval mutation by construction, and printing that as a
result next to a measured AUROC is the rigor slippage this project spent the
audit removing.

**Still open.** Hashing the parsed `mcp_types.Tool` cannot see fields the SDK
does not model, since pydantic drops unknown keys, so a nonstandard or future
field cannot be pinned. The canonicaliser takes a plain mapping, so a raw
`tools/list` frame could be fed to it — but §5.4 established that the frame is
the *wrong* object to verify, so closing this gap means reaching the unparsed
fields at the point the agent receives them, not moving verification back to
the transport.

Also open, and deliberately so until step 4: what a `PinStoreCorrupt` should
mean. It currently propagates, which fails closed. That is the safer default to
sit on, but it should be a policy decision rather than a consequence of where a
`try` block happens to be.

---

## 4. Open Questions

| # | Question | Blocks |
|---|---|---|
| Q1 | Anthropic API key location — existing env var / `.env`, or to be supplied? The LLMShield repo's `.env` is deliberately not read. | M1 |
| Q2 | Filesystem sandbox directory (SEC-4). Proposed default `D:\LLMSHIELD-MCP\sandbox\`, gitignored, with synthetic files. | M1 |
| ~~Q5~~ | ~~Add a tool-result rule family?~~ **RESOLVED: yes.** Six `MCP-*` rules derived from BIPIA and InjecAgent by discriminative phrase analysis, not invention. 20.3% recall at 0.000% false positives. `INJ-*` frozen at 19 and guarded by a test. | - |
| ~~Q3~~ | ~~Corpus source families for leave-one-source-out.~~ **RESOLVED**: three distinct adversarial source families now ingested via `corpus-ingest` -- BIPIA (125), InjecAgent (62), LLMail-Inject (150, sampled/deduplicated from a 462,000-row MIT-licensed real adaptive-injection competition corpus, `corpus/sources.py`). 337 adversarial items total, "low hundreds" as targeted. A fourth (the MCP-specific dilution corpus, `plan.md` 2.19) remains a candidate but is no longer blocking -- M8 can run with three. | - |
| ~~Q4~~ | ~~`config/models.yaml` absolute path~~ **RESOLVED**: root is now the repository-relative `models/` (gitignored), resolved against `REPO_ROOT`, with `LLMSHIELD_MODELS_ROOT` as override. Settled with D2. | - |

---

## 5. Known Risks

| Risk | Assessment | Mitigation |
|---|---|---|
| Detectors fail to transfer to the tool-result surface | Early evidence suggests substantial failure (`docs/M0-OBSERVATIONS.md`) | This is Objective 1, not a failure state. Report honestly. |
| Context dilution dominates, making chunking insufficient | Observed in M0 at smoke-test level | Dilution added as a corpus axis (`prd.md` 9.3). Alternative pooling functions to be tested. |
| Both detectors false-positive heavily on benign non-instruction text | Observed in M0 at smoke-test level | Measured directly via the dual benign reference sets in M7, not tuned away. |
| Transformer latency impractical for real agent loops | ~180-220 ms single window, ~5300 ms chunked at ~1500 tokens on CPU | Report honestly per NFR-2. Cascade detection is the documented deferred extension. |
| MCP SDK 2.x churn | SDK recently moved 1.x to 2.x | `mcp==2.1.1` pinned; `uv.lock` committed. Transport Protocol is a narrow, stable surface. |
| ~~CI failing~~ | Fixed; see section 6 D1 | - |
| Agent model choice affects chain realism | A weaker model produces a thinner call sequence (observed: opus 7 calls vs haiku 3 on comparable tasks) | Model is a `--model` flag; evaluation chains use the default, smoke runs use `claude-haiku-4-5` |

---

## 6. Immediate Defects

### D1 — CI workflow fails on every push

**Status:** open. **Confirmed**, not suspected.

- Run: `33842868936`, conclusion `failure`, 15s.
- Error: `error: No system Python installation found for Python 3.11`, then
  `Process completed with exit code 2`.
- Root cause: `.github/workflows/ci.yml` runs
  `uv pip install --system -e ".[dev]"`. `astral-sh/setup-uv@v7` provides a
  uv-managed Python, not a *system* Python, so `--system` has no target.
- Proposed fix: replace `uv pip install --system` with `uv sync --extra dev
  --frozen` and prefix each check with `uv run`. This also makes CI honour
  `uv.lock`, which is stricter for NFR-8 than the current workflow.
- Secondary consideration: on Linux, PyPI `torch` defaults to a CUDA build
  (multi-GB). Since the project is CPU-only by constraint A3, CI should resolve
  torch from the PyTorch CPU index. This is a correctness match to A3, not a CI
  workaround.

**Applied:** `uv sync --extra dev --frozen` plus `uv run` on every check step.
`--frozen` also makes CI fail on a stale lockfile, which is stricter for NFR-8
than the original workflow.

**Also applied, same root concern:** `torch` now resolves from the PyTorch CPU
index on Linux via `[tool.uv.sources]`. Re-locking removed every `nvidia-*`
CUDA package and `triton`, and pinned `torch 2.14.0+cpu` -- confirming CI was
about to download multi-gigabyte CUDA wheels on a project whose stated
constraint (A3) is CPU-only. Windows and macOS resolution is unchanged
(verified locally: `torch 2.14.0+cpu`, `torch.version.cuda is None`).

### D2 - Recorded chain fixtures embed absolute host paths

**Status:** FIXED (option 1).

`chains/baseline.json` records tool arguments exactly as the model issued them,
which for the filesystem server means absolute paths such as
`D:\LLMSHIELD-MCP\sandbox\README.md`. That is a faithful record of the run,
but it makes the committed fixture machine-specific and would disclose the
author's directory layout if the repository were made public.

**Applied:** the sandbox path is replaced by `SANDBOX_PLACEHOLDER`
(`{sandbox}`, shared with `servers.yaml`) in both tool arguments and result
text on write, and restored by `ChainRecord.read(path, sandbox_root=...)` on
read. `read` without a sandbox leaves the placeholder in place, which is what
inspection and diffing want. Normalisation happens only on the *stored* form --
the tool itself ran against the real path.

Accepted cost: the record is no longer byte-identical to what the model sent.
The placeholder is visibly a placeholder, so no fabricated path is written down.

**A field that had to be removed again.** The first implementation also stored
`recorded_sandbox_root` "for provenance". That reintroduced the exact
disclosure the placeholder exists to prevent, and nothing read it. It is gone,
with a comment in `chain.py` saying why, so it does not get re-added.

**How it was caught:** the first version of the guarding test built its own
record and set the offending field to empty, so it passed while the committed
fixture still contained `D:\LLMSHIELD-MCP\sandbox`. The test now reads the
real `chains/baseline.json`. A test written to pass rather than to catch is
worse than no test.

Q4 (`config/models.yaml` absolute path) was settled at the same time: the
checked-in root is now the repository-relative `models/`, which is gitignored,
with `LLMSHIELD_MODELS_ROOT` as the override.
