# plan.md — Implementation Plan and Architecture Decisions

Companion to `prd.md` (what to build) and `whats_has_been_done.md` (what is
built). This file holds the plan, the architecture decisions and their
rationale, remaining work, and known risks.

**Current position: M1 complete. M2 not started.**

---

## 1. Milestone Plan

Each milestone is independently testable and lands as its own commit.

| # | Milestone | Requirements | Verification | Status |
|---|---|---|---|---|
| M0 | Scaffold, pinned CPU stack, reuse audit for V0/V3 | NFR-8, A1, A3 | `mcp-shield verify-models`; contract tests | **Done** |
| M1 | Both reference MCP servers running + minimal Claude agent + committed tool-call chain fixture | SEC-4, [3.1] | Agent reads a file and fetches a URL; fixture committed | **Done** |
| M2 | Interception layer, **logging only, zero detectors** | FR-1, FR-8, FR-15, FR-16, NFR-5 | 20-call chain produces 20 log rows; agent behaviour byte-identical to M1 | Not started |
| M3 | Port rule engine and PII scanner as detector adapters | FR-2 (part), NFR-4, SEC-3, SEC-6 | Unit tests incl. explicit fail-closed test | Not started |
| M4 | Fusion and policy engine; golden-set regression test begins | FR-4, FR-5, FR-6, FR-7, FR-9 | Table-driven decision tests; threshold change in YAML alters decision with no code edit | Not started |
| M5 | V0 and V3 wired into the live gating path | FR-2, FR-3 | Ablation by config alone | Not started |
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

## 4. Open Questions

| # | Question | Blocks |
|---|---|---|
| Q1 | Anthropic API key location — existing env var / `.env`, or to be supplied? The LLMShield repo's `.env` is deliberately not read. | M1 |
| Q2 | Filesystem sandbox directory (SEC-4). Proposed default `D:\LLMSHIELD-MCP\sandbox\`, gitignored, with synthetic files. | M1 |
| Q3 | Corpus source families for leave-one-source-out. Needs >= 3, ideally 4, distinct families. Target corpus size within "low hundreds". | M6, M8 |
| Q4 | Should `config/models.yaml` switch to a relative default path before the repository is made public? It currently embeds an absolute local path. | M10 |

---

## 5. Known Risks

| Risk | Assessment | Mitigation |
|---|---|---|
| Detectors fail to transfer to the tool-result surface | Early evidence suggests substantial failure (`docs/M0-OBSERVATIONS.md`) | This is Objective 1, not a failure state. Report honestly. |
| Context dilution dominates, making chunking insufficient | Observed in M0 at smoke-test level | Dilution added as a corpus axis (`prd.md` 9.3). Alternative pooling functions to be tested. |
| Both detectors false-positive heavily on benign non-instruction text | Observed in M0 at smoke-test level | Measured directly via the dual benign reference sets in M7, not tuned away. |
| Transformer latency impractical for real agent loops | ~180-220 ms single window, ~5300 ms chunked at ~1500 tokens on CPU | Report honestly per NFR-2. Cascade detection is the documented deferred extension. |
| MCP SDK 2.x churn | SDK recently moved 1.x to 2.x | `mcp==2.1.1` pinned; `uv.lock` committed. Transport Protocol is a narrow, stable surface. |
| CI currently failing | Confirmed: run 33842868936 | Root cause identified, fix proposed. See section 6. |

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

Not fixed yet: discovered while writing project memory, which is outside the
scope of that task (CLAUDE.md section 5). Awaiting go-ahead.

### D2 - Recorded chain fixtures embed absolute host paths

**Status:** open, by design pending a decision.

`chains/baseline.json` records tool arguments exactly as the model issued them,
which for the filesystem server means absolute paths such as
`D:\LLMSHIELD-MCP\sandbox\README.md`. That is a faithful record of the run,
but it makes the committed fixture machine-specific and would disclose the
author's directory layout if the repository were made public.

Options, none applied:

1. Store `sandbox_root` on `ChainRecord` and record sandbox-relative paths,
   rehydrating at replay time. Keeps fixtures portable; the record is no longer
   byte-identical to what the model sent.
2. Normalise only at publication time, keeping local fixtures literal.
3. Accept it and make the sandbox path itself non-identifying.

Same class as Q4 (`config/models.yaml` absolute path); both should be settled
together before the repository is made public.
