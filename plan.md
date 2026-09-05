# plan.md — Implementation Plan and Architecture Decisions

Companion to `prd.md` (what to build) and `whats_has_been_done.md` (what is
built). This file holds the plan, the architecture decisions and their
rationale, remaining work, and known risks.

**Current position: M5 complete. V0 and V3 wired into the live gate as scored-but-inert detectors, alongside rules and PII.**

---

## 1. Milestone Plan

Each milestone is independently testable and lands as its own commit.

| # | Milestone | Requirements | Verification | Status |
|---|---|---|---|---|
| M0 | Scaffold, pinned CPU stack, reuse audit for V0/V3 | NFR-8, A1, A3 | `mcp-shield verify-models`; contract tests | **Done** |
| M1 | Both reference MCP servers running + minimal Claude agent + committed tool-call chain fixture | SEC-4, [3.1] | Agent reads a file and fetches a URL; fixture committed | **Done** |
| M2 | Interception layer, **logging only, zero detectors** | FR-1, FR-8, FR-15, FR-16, NFR-5 | 10-call run produced exactly 10 log rows; gate overhead 0.03-0.06 ms | **Done** |
| M3 | Port rule engine and PII scanner as detector adapters | FR-2 (part), NFR-4, SEC-3, SEC-6 | 55 unit tests incl. fail-closed for both adapters; zero false positives on the benign sandbox | **Done** |
| M3b | Normaliser as a pre-detection stage; MCP-* rule family derived from benchmark data | FR-2 | 194 tests; MCP-* 20.3% recall at 0.00% FP where INJ-* scores 0.0% | **Done** |
| M4 | Fusion and policy engine; golden-set regression test begins | FR-4, FR-5, FR-6, FR-7, FR-9 | Table-driven decision tests; threshold change in YAML alters decision with no code edit; thresholds refuse to block until calibrated | **Done** |
| M5 | V0 and V3 wired into the live gating path | FR-2, FR-3 | Ablation by config alone | **Done** |
| M6 | Corpus schema, ingest CLI, MinHash decontamination | FR-10, AC-6 | Drop-count report; no surviving near-duplicate above threshold | Not started |
| M7 | GAUGE harness; port LOBO and DeLong; replace hand-rolled CIs | FR-11, NFR-6, NFR-7 | Known-answer tests for Wilson, Clopper-Pearson, McNemar, DeLong | Not started |
| M8 | Leave-one-source-out generalisation test | FR-12 | Per-held-out-family table | Not started |
| M9 | Latency benchmark: per-detector, fused, 20-call chain | FR-13, FR-14, NFR-1, NFR-2 | Reproducible script, committed numbers | Not started |
| M10 | Report generation; README headline numbers | AC-7, [18] | Tables and plots as static files | Not started |
| M11 | *(optional)* Standalone stdio proxy over the same gating core | [11.1] option A | Agent config points at proxy, nothing else changes | Not started |

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
| Leave-one-source-out | `evaluation/experiment2/exp2_lobo.py` | Port in M8 |
| DeLong AUROC | `evaluation/experiment2/exp2_auroc_delong.py` | Port in M7 |
| Multi-FPR calibration | `exp2_multi_fpr.py`, `exp2_calibration.py` | Port in M7 |

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

## 4. Open Questions

| # | Question | Blocks |
|---|---|---|
| Q1 | Anthropic API key location — existing env var / `.env`, or to be supplied? The LLMShield repo's `.env` is deliberately not read. | M1 |
| Q2 | Filesystem sandbox directory (SEC-4). Proposed default `D:\LLMSHIELD-MCP\sandbox\`, gitignored, with synthetic files. | M1 |
| ~~Q5~~ | ~~Add a tool-result rule family?~~ **RESOLVED: yes.** Six `MCP-*` rules derived from BIPIA and InjecAgent by discriminative phrase analysis, not invention. 20.3% recall at 0.000% false positives. `INJ-*` frozen at 19 and guarded by a test. | - |
| Q3 | Corpus source families for leave-one-source-out. Needs >= 3, ideally 4, distinct families. Target corpus size within "low hundreds". | M6, M8 |
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
