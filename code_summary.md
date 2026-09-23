# code_summary.md — Codebase Map

Factual map of what exists in this repository. Updated when structure changes.

**As of M10.** 4688 lines of source, 4160 lines of tests, 303 tests (285
weight-free + 18 marked `models`) -- unchanged from M9, since M10 is
reporting/documentation only, no new code. All four detectors -- rules
(both families), PII, V0, V3 -- run against every intercepted tool result
through the fusion/policy engine (`gating/policy.py`); V0/V3 ship **inert**
(scored, logged, zero decision weight). A payload corpus pipeline exists
(`corpus/`): fetch, label, MinHash-decontaminate, store -- three distinct
adversarial source families (BIPIA, InjecAgent, LLMail-Inject, 337 items). A
GAUGE harness (`gauge/`) calibrates V0/V3 at matched FPR budgets and reports
ASR/AUROC by threat type AND by source family (FR-12, leave-one-source-out)
with confidence intervals throughout, but does not itself flip
`config/policy.yaml`'s `calibrated` flag. Latency is benchmarked and
committed (`docs/LATENCY-BENCHMARK.md`): rules/PII/V0 trivial, V3 (and
therefore the fused pipeline) ~2x over its NFR-2 budget on short text and up
to 13 seconds on real fetched web content. The full write-up is
`docs/REPORT.md`, with three committed SVG figures (`docs/figures/`) and a
rewritten `README.md` stating the headline findings in plain English (M10,
AC-7): detectors do not transfer reliably, and whatever signal exists does
not generalise across source families.

---

## 1. Project Structure

```
D:\LLMSHIELD-MCP\
├── PROPOSAL.md                  MVP technical proposal (requirements source)
├── CLAUDE.md                    engineering rules for AI agents
├── prd.md                       requirements + amendments
├── plan.md                      milestones, architecture decisions, risks
├── whats_has_been_done.md       running implementation history
├── code_summary.md              this file
├── architecture_1.png           component/data-flow figure
├── pyproject.toml               package metadata, exact pins, tool config
├── uv.lock                      full transitive lock (111 packages)
├── config/
│   ├── decontamination.yaml      MinHash shingle/threshold + training-corpus
│   │                             reference path (FR-10, M6)
│   ├── models.yaml              paths + runtime settings for reused detectors
│   ├── policy.yaml               DEFAULT profile (rules + PII): calibrated
│   │                             flag, roles, thresholds, max_result_chars
│   ├── policy.guard.yaml       GUARD profile: adds `guard` under `inert`.
│   │                             The only ML profile runnable after a plain
│   │                             clone -- needs no unpublishable artifact
│   ├── policy.research.yaml     RESEARCH profile: adds v0/v3/guard under
│   │                             `inert`. Decision-neutral; needs the weights
│   ├── rules.yaml               25 rules: 19 INJ-* (frozen) + 6 MCP-*
│   └── servers.yaml             reference MCP server launch specs + sandbox
├── sandbox/                     synthetic benign corpus; filesystem server is
│                                confined to this directory (SEC-4)
├── chains/
│   ├── baseline.json            recorded benign tool-call chain (M1 fixture)
│                                 (latency_chain.json removed: it embedded
│                                 CC BY-SA web content -- THIRD_PARTY_NOTICES.md)
├── scripts/
│   ├── benchmark_rules.py       rule recall vs BIPIA + InjecAgent (imports
│   │                            loaders from llmshield_mcp.corpus.sources)
│   ├── benchmark_latency.py     per-detector + fused latency (FR-13, M9)
│   ├── generate_report.py       SVG figures from a GAUGE run (AC-7, M10)
│   └── collect_declarations.py  launches 7 real MCP servers across 8 releases
│                                each; writes results/declarations/snapshot-*.json
│                                and renders docs/DECLARATION-CHURN.md
├── corpus/
│   ├── external/                 fetched BIPIA/InjecAgent (gitignored)
│   ├── reference/                V0/V3 training-data reference corpus,
│   │                              train.jsonl (gitignored, not published)
│   └── payload_corpus.sqlite     ingested corpus store (gitignored, *.sqlite)
├── pins/                         tool-declaration pins, <server>.json
│                                  (gitignored by default; digests + field
│                                   names + timestamps, never content)
├── results/
│   ├── declarations/             committed churn snapshot (digests and
│   │                              metrics only, never declaration text)
│   └── gauge/                    scores.csv + calibration_report.json per
│                                  gauge-run (gitignored output directory)
├── docs/
│   ├── PINNING.md               why scikit-learn and transformers are pinned
│   ├── M0-OBSERVATIONS.md       M0 probe observations (explicitly not results)
│   ├── POLICY-AUDIT.md          pre-M4 policy/threshold audit, measured
│   ├── LATENCY-BENCHMARK.md     M9: per-detector, fused, 20-call chain latency
│   ├── REPORT.md                M10: the public write-up (AC-7)
│   ├── PLAN-DECLARATION-INTEGRITY.md  the declaration-integrity plan, all
│   │                            six steps done (plan.md 2.29)
│   ├── DECLARATION-CHURN.md     measured churn base rate, dated + frozen
│   └── figures/                 committed SVG charts REPORT.md embeds
├── src/llmshield_mcp/
│   ├── __init__.py              __version__ = "0.1.0"
│   ├── __main__.py              python -m llmshield_mcp
│   ├── agent.py                 reference Claude tool-use loop over MCP (230)
│   ├── chain.py                 recorded tool-call chain format (107)
│   ├── cli.py                   CLI entry point (188)
│   ├── config.py                config loading + score-mode collapse (145)
│   ├── latency.py               LatencyStats, summarize(), time_calls() (FR-13, M9)
│   ├── servers.py               MCP server config + sandbox resolution (88)
│   ├── settings.py              .env / environment secrets (38)
│   ├── gating/
│   │   ├── audit.py             SQLite decision log, Decision/Outcome (173)
│   │   ├── content.py           extraction, apply_redaction() (clips spans
│   │   │                        per block; reports unplaceable ones),
│   │   │                        build_block_result() (FR-5/FR-6)
│   │   ├── policy.py            fusion + policy engine (FR-4/FR-9) (240)
│   │   ├── tool_calls.py        capability gating for outbound tools/call:
│   │   │                        action/paths/egress rules, no content
│   │   │                        inspection (plan.md 2.28)
│   │   ├── declarations.py      tool-declaration canonicaliser: raw-byte
│   │   │                        per-field hashes, concealment flag,
│   │   │                        render_for_review() (plan.md 2.29)
│   │   ├── declaration_policy.py  tool_declarations block: conditions ->
│   │   │                        allow/escalate/block, most-severe-wins,
│   │   │                        on_pin_error fails closed (plan.md 2.29)
│   │   ├── declaration_gate.py  verifies the ListToolsResult the AGENT gets,
│   │   │                        not the frame (SDK filters + caches after the
│   │   │                        transport); shadowing view; off by default
│   │   ├── pins.py              TOFU pin store, pins/<server>.json; verdicts
│   │   │                        new/unchanged/mutated/stale_pin; digests and
│   │   │                        field names only, never content (plan.md 2.29)
│   │   └── transport.py         Gate + stream wrappers; wires detectors +
│   │                            PolicyEngine into observe_inbound (M4) (340)
│   ├── detectors/
│   │   ├── __init__.py          exports; V3 imported lazily (31)
│   │   ├── base.py              detector contract (118)
│   │   ├── normalise.py         canonicalisation + dual scan; NFKC, TAG-block
│   │   │                        decode, Default_Ignorable strip, homoglyph,
│   │   │                        base64 (plan.md 2.29)
│   │   ├── guard.py            published Apache-2.0 binary injection
│   │   │                        classifier from the HF Hub, pinned by commit
│   │   │                        SHA; positive class read from id2label
│   │   ├── pii.py               PII scanner + redact() (183)
│   │   ├── rules.py             injection rule engine (135)
│   │   ├── v0_lexical.py        V0 adapter (79)
│   │   └── v3_transformer.py    V3 adapter (108)
│   ├── corpus/                  payload corpus pipeline (FR-10, M6, M8)
│   │   ├── sources.py           fetch()/load_adversarial()/load_benign();
│   │   │                        fetch_llmail_inject()/load_llmail_inject()
│   │   │                        (3rd source family, Q3)
│   │   ├── decontaminate.py     MinHash shingling + datasketch.MinHashLSH
│   │   └── store.py             PayloadCorpusItem, CorpusStore, export_jsonl()
│   └── gauge/                   GAUGE harness: stats, calibration (FR-11, M7)
│       └── recut.py             re-derives AUROC from scores.csv under every
│                                score mode; no weights, no corpus. The
│                                falsification check for the below-chance
│                                V3 figure (plan.md 2.25)
│       ├── stats.py             wilson_ci/clopper_pearson_ci/mcnemar_test
│       │                        (statsmodels) + auroc_delong() (ported)
│       ├── calibrate.py         threshold_at_fpr(): matched-FPR calibration
│       ├── references.py        dual benign reference split (keyword filter)
│       └── run.py               run_gauge(): the harness, scores.csv + report
│                                (ASR by threat_type AND by source, FR-12)
├── tests/
│   ├── fixtures/
│   │   └── golden_set.json      frozen decision fixture (M4 regression test)
│   ├── conftest.py               `light_detectors` fixture: the weight-free,
│   │                              decision-relevant detector set (M5)
│   ├── test_agent.py            tool-use loop, faked client + sessions (13)
│   ├── test_chain.py            chain round-trip and schema (6)
│   ├── test_config.py           config + score-mode tests (15)
│   ├── test_corpus_decontaminate.py  MinHash correctness, config loading (13)
│   ├── test_corpus_llmail_inject.py  parsing, dedup, sampling cap (6)
│   ├── test_corpus_sources.py   load_benign() sanity (offline) (2)
│   ├── test_corpus_store.py     PayloadCorpusItem round-trip, export (7)
│   ├── test_detector_normalise.py  canonicalisation, dual scan, concealment (41)
│   ├── test_gating_declarations.py canonicaliser: adversarial cases (39)
│   ├── test_gating_pins.py      TOFU, rug-pull, corruption, SEC-3 bytes (42)
│   ├── test_gating_declaration_gate.py  verification at model input (22)
│   ├── test_gating_declaration_policy.py  policy, audit rows, fail-closed (38)
│   ├── test_declaration_churn.py  churn arithmetic vs synthetic snapshots (17)
│   ├── test_paper_techniques.py  arXiv:2607.05744 T1-T8 vs toolgate; backs
│   │                            the README table cell by cell (17)
│   ├── test_detector_pii.py     PII, redaction, SEC-3 leakage (31)
│   ├── test_detector_rules.py   rule loading, matching, SEC-6 (24)
│   ├── test_detector_base.py    contract tests (7)
│   ├── test_gating_audit.py     decision log store (7)
│   ├── test_gating_content.py   extraction, size policy, redaction, block (24)
│   ├── test_gating_policy.py    table-driven PolicyEngine.decide, FR-9 proof (23)
│   ├── test_gating_transport.py gate + fusion behaviour, stream wrappers (26)
│   ├── test_gating_transport_with_models.py  V0/V3 wiring + ablation, marked
│   │                              `models` (5)
│   ├── test_gauge_stats.py      Wilson/CP/McNemar/DeLong known-answer tests (11)
│   ├── test_gauge_calibrate.py  threshold_at_fpr correctness (8)
│   ├── test_gauge_references.py dual benign reference split (7)
│   ├── test_gauge_report.py     by_source grouping (FR-12), weight-free (2)
│   ├── test_gauge_run_with_models.py  end-to-end harness, marked `models` (5)
│   ├── test_golden_set.py       M4 golden-set regression test (6)
│   ├── test_latency.py          LatencyStats/summarize/time_calls, weight-free (7)
│   ├── test_latency_with_models.py  real-detector sanity check, marked `models` (1)
│   ├── test_servers.py          server config + sandbox validation (8)
│   └── test_adapters_with_models.py  reuse audit, marked `models` (7)
└── .github/workflows/ci.yml     lint, format, type-check, test (CURRENTLY FAILING)
```

Not tracked by git: `.venv/`, `models/`, `.env`, `*.joblib`, `*.safetensors`,
`logs/`, `*.sqlite`, `corpus/external/`, `corpus/reference/`, `results/`.

---

## 2. Major Modules

### `llmshield_mcp.config`

Loads and validates `config/models.yaml`. Validation is strict and happens at
load time so a typo fails immediately rather than mid-evaluation.

| Symbol | Kind | Purpose |
|---|---|---|
| `DETECTOR_CLASSES` | constant | `("benign", "injection", "jailbreak", "harmful")` — the trained label order for **both** V0 and V3. Reordering silently mislabels every score in the project. |
| `BENIGN_INDEX` | constant | Index of `benign` (0) |
| `SCORE_MODES` | constant | `{"not_benign"} | DETECTOR_CLASSES` |
| `LONG_TEXT_STRATEGIES` | constant | `{"truncate", "chunk_max"}` |
| `DEFAULT_CONFIG_PATH` | constant | `<repo>/config/models.yaml` |
| `scalar_from_proba(proba, mode)` | function | Collapses a 4-class probability vector to one score in [0,1]. `not_benign` returns `1 - P(benign)`; a class name returns that class's probability. |
| `V0Config` | frozen dataclass | `path`, `score_mode` |
| `V3Config` | frozen dataclass | `path`, `device`, `max_length`, `score_mode`, `long_text_strategy`, `chunk_stride`, `max_chunks`, `batch_size` |
| `ModelsConfig` | frozen dataclass | `v0`, `v3` |
| `load_models_config(path=None)` | function | Reads YAML, applies `LLMSHIELD_MODELS_ROOT` override, resolves a relative root against `REPO_ROOT`, validates, returns `ModelsConfig` |
| `REPO_ROOT` | constant | Repository root; relative config paths resolve against it |
| `SANDBOX_PLACEHOLDER` | constant | `{sandbox}` — shared by `servers.yaml` argument substitution and chain fixtures |
| `DEFAULT_AGENT_MODEL` | constant | `claude-opus-5`. Lives here, not in `agent.py`, so the CLI shows it in `--help` without importing anthropic and mcp |

### `llmshield_mcp.detectors.base`

The contract every detector implements. Owns timing and failure containment so
individual adapters cannot forget either.

| Symbol | Kind | Purpose |
|---|---|---|
| `Span` | frozen dataclass | Half-open `[start, end)` character range plus `label`. Enables Redact (FR-5) by marking only offending regions. Rejects negative or inverted ranges. |
| `RawScore` | frozen dataclass | What a concrete adapter returns from `_score`: `score`, `detail`, `spans`, `truncated` |
| `DetectorResult` | frozen dataclass | One detector's verdict: `detector`, `score`, `detail`, `spans`, `latency_ms`, `truncated`, `error`. Invariant: `score is None` **iff** `error is not None`. Property `failed`. |
| `Detector` | ABC | Subclasses implement `_score(text) -> RawScore` only. `score(text) -> DetectorResult` wraps it with timing and a `try/except` that converts any exception into a failed result. |

### `llmshield_mcp.detectors.rules`

`RuleDetector`, `name = "rules"`. Binary regex detector over the 19 injection
signatures in `config/rules.yaml`, ported verbatim from the dissertation.

Two families, filterable via `load_rules(families=...)`:

* **`INJ-*`** — the dissertation's 19 rules, **frozen**. Comparability baseline.
  Measured recall against real indirect-PI benchmarks: **0.0%**.
* **`MCP-*`** — 6 rules derived from BIPIA and InjecAgent for the tool-result
  surface. **20.3%** recall at **0.000%** false positives.

`load_rules()` compiles at load time and rejects a duplicate id, an unknown
severity, an uncompilable pattern, an empty rule list, or a file where every
rule is disabled — each of which would otherwise produce a scan that looks
clean for the wrong reason.

Score is binary (1.0 if any rule fires). `detail` maps rule id to 1.0. Every
match becomes a `Span`, not just the first, because FR-5 must mask all of them.

### `llmshield_mcp.detectors.normalise`

Canonicalisation, step 1 of the pipeline. `normalise(text) -> Normalised`
applies NFKC, invisible-character stripping, homoglyph folding and base64
decoding, reporting which transforms actually fired.

Base64 is **appended**, not substituted, so following offsets stay valid and
the encoded form survives as evidence.

`scan_normalised(detector, text)` scans both the original and the canonical
form, takes the higher score, and keeps spans only from the original -- a span
found in normalised text does not point at the same characters in the original,
and redacting with it would corrupt the tool result. When the canonical pass
finds something the original did not, `detail["normalisation_only"] = 1.0`
tells the policy engine that a detection exists with no redactable span, so it
is a Block rather than a Redact.

### `llmshield_mcp.detectors.pii`

`PiiDetector`, `name = "pii"`. Six pattern-based entity types with the
dissertation's confidences: `EMAIL_ADDRESS` 0.85, `PHONE_NUMBER` 0.75,
`CREDIT_CARD` 0.90 (Luhn-checked), `US_SSN` 0.85, `IBAN_CODE` 0.80,
`IP_ADDRESS` 0.75. Score is the maximum confidence among detected entities.

NER-only entities (`PERSON`, `LOCATION`, ...) are skipped rather than raising,
and exposed through `skipped_entities` so the gap is visible rather than
looking like a clean scan.

`redact(text, spans)` masks every span with `[REDACTED:<label>]`, merging
overlaps and applying right to left.

### `llmshield_mcp.detectors.v0_lexical`

`V0LexicalDetector(config: V0Config)`, `name = "v0"`.

Loads a joblib dict of `{"vectorizer", "classifier", "classes"}` produced by
`exp2_train.py:65`. On load it:

- promotes scikit-learn's `InconsistentVersionWarning` to a `ValueError`, making
  the version pin self-enforcing;
- asserts the saved class order equals `DETECTOR_CLASSES`;
- builds `_column_of`, mapping label index to `predict_proba` column via
  `classifier.classes_` rather than assuming column order.

No token limit — TF-IDF vectorises arbitrary-length input, so V0 is the only
reused detector that natively sees a whole tool result.

### `llmshield_mcp.detectors.v3_transformer`

`V3TransformerDetector(config: V3Config)`, `name = "v3"`.

`DebertaV2ForSequenceClassification`, 4 labels, CPU. Loading asserts
`num_labels == len(DETECTOR_CLASSES)`.

`_score` uses the tokenizer's own sliding window
(`return_overflowing_tokens=True` with `stride`), which builds per-window
special tokens correctly. Under `truncate` only window 0 is scored; under
`chunk_max` up to `max_chunks` windows are scored in batches of `batch_size`,
and the maximum scalar wins. `detail` carries the winning window's four class
probabilities plus `n_windows_total`, `n_windows_scored`, `winning_window`.
`truncated` is true when `scored < total`, i.e. content existed that was never
scored.

### `llmshield_mcp.servers`

Reads `config/servers.yaml`. `ServerSpec` holds one server's stdio launch
command; `ServersConfig` holds the resolved sandbox path and every spec.
`load_servers_config()` substitutes the `{sandbox}` placeholder into arguments
and **refuses to run if the sandbox directory does not exist** — creating it
would silently hand the filesystem server an empty directory, which looks like
a working run that happens to read nothing (SEC-4). `LLMSHIELD_SANDBOX_ROOT`
overrides the configured path.

### `llmshield_mcp.settings`

`Settings` (pydantic-settings) reads `ANTHROPIC_API_KEY` from the process
environment or `.env` at the repository root. `require_anthropic_api_key()`
raises with a usable message rather than letting the SDK fail later. The key is
never logged and never written to a chain record.

### `llmshield_mcp.chain`

The recorded tool-call chain format, `SCHEMA_VERSION = 2`.

| Symbol | Purpose |
|---|---|
| `ToolCallRecord` | One call: `index`, `correlation_id`, `server`, `tool`, `arguments`, `result_text`, `result_block_types`, `is_error`, `duration_ms` |
| `UsageRecord` | Tokens a chain cost: `api_calls`, `input_tokens`, `output_tokens`, both cache counters. `plus()` accumulates one response's usage and tolerates missing or `None` fields. |
| `ChainRecord` | One agent run: `task`, `model`, `created_at`, `servers`, `calls`, `usage`, `schema_version`; `to_json`/`write`/`read`/`from_dict`/`with_sandbox` |
| `normalise` / `restore` | Recursively swap the concrete sandbox path for `SANDBOX_PLACEHOLDER` and back, handling both native and POSIX spellings |

`from_dict` rebuilds tuples explicitly — JSON has no tuple type, so without it
a round-tripped record compares unequal to a freshly built one. An unknown
`schema_version` is rejected rather than parsed optimistically.

`result_text` is the concatenation of text blocks only. It is the field the
gating layer will scan and the field adversarial payloads are injected into at
evaluation time; payloads are never stored in the sandbox or in a fixture.

Fixtures store the sandbox as `{sandbox}` rather than a concrete path, so a
committed chain is portable and discloses no host directory layout (D2). Only
the *stored* form is normalised — the tool ran against the real path.
`read(path, sandbox_root=...)` resolves it back; `read(path)` keeps the
placeholder, which is what inspection and diffing want.

`ChainRecord` deliberately does **not** record the sandbox path it was made
against. An earlier version did, "for provenance", which reintroduced exactly
the disclosure the placeholder prevents.

### `llmshield_mcp.agent`

The reference agent. Not a product — it exists only to produce realistic chains.

| Symbol | Purpose |
|---|---|
| `qualified_tool_name` / `split_tool_name` | Flatten two servers into one Anthropic tool namespace as `server__tool`. Two servers may expose the same tool name, and Anthropic tool names allow only `[a-zA-Z0-9_-]`. |
| `to_anthropic_tool` | `mcp_types.Tool` -> `ToolParam`. Note `mcp` 2.x exposes `input_schema` (wire alias `inputSchema`); the 1.x attribute name would fail. |
| `flatten_result` | `CallToolResult` -> (text, block types). Only text and text-resource blocks contribute text; images and binary resources are recorded by type but never scanned (PROPOSAL.md section 19). |
| `ConnectedServer` | A live session plus its declared tools |
| `open_servers` | `AsyncExitStack` context manager launching every server and initialising sessions. Takes a `transport_factory`, defaulting to `stdio_client` — **this is the M2 seam**. |
| `ReferenceAgent.run` | The manual tool-use loop |

Loop invariants worth knowing:

- Every `tool_result` for one assistant turn goes back in a **single** user
  message. Splitting them across messages trains the model out of parallel
  tool calls.
- A tool that raises is still recorded, with `is_error=True` and the exception
  text as the result. Dropping it would leave a hole in the sequence and
  misalign later indices.
- `pause_turn` re-sends the turn unchanged rather than ending the loop.
- `max_iterations` (default 40) bounds a model that never stops calling tools.

### `llmshield_mcp.gating`

The interception layer (M2) plus the fusion/policy engine wired into it (M4),
now running all four detectors (M5). Observes every frame, runs whichever
detectors the policy names, fuses their results into one decision, and logs
it -- rewriting the frame itself for Redact/Block.

| Symbol | Purpose |
|---|---|
| `Decision` | `allow` / `redact` / `block` / `escalate` (FR-4) |
| `Outcome` | `result` / `protocol_error` / `detector_failure` — what kind of frame the row is about |
| `DecisionRecord` | One log row. `latency_ms` is time inside the gate; `roundtrip_ms` is client-to-server-and-back, kept separate so NFR-1 stays measurable |
| `DecisionLog` | Append-only SQLite store. Content is **hashed, never stored** (section 12) |
| `extract(result, max_chars)` | Raw `tools/call` result -> scannable text, block types, truncation flag, SHA-256 of the *full* pre-truncation text |
| `apply_redaction(result, spans)` | Rebuilds `result` with `spans` masked, returning `(result, unapplied_spans)` (FR-5). Shares `_walk_blocks()` with `extract()` so offsets always agree. **Spans are clipped per block, not required to sit inside one** — requiring containment silently dropped matches straddling the `"
"` block join (reachable: `PHONE_NUMBER`/`US_SSN` separators match a newline) while the row still recorded `redacted=1`. Any span that still cannot be placed is returned so the `Gate` can note the shortfall. |
| `build_block_result(is_error)` | The FR-6 replacement result: one text block, `BLOCK_MESSAGE`, nothing of the original carried forward |
| `PolicyConfig` / `load_policy_config()` | Validated `config/policy.yaml`: `calibrated`, `on_detector_failure`, detector-role sets, per-detector thresholds, `max_result_chars` |
| `PolicyEngine.decide(results)` | Pure fusion function: `dict[str, DetectorResult]` -> `FusionOutcome`. Max/OR across `injection_detectors`; PII (`redaction_detectors`) masks independently of the decision label; `calibrated: false` caps `BLOCK` to `ESCALATE` |
| `GateConfig` | `max_result_chars` (FR-16/SEC-2, now sourced from `policy.yaml` by default), `max_pending` (NFR-5) |
| `Gate` | Runs `build_detectors(policy.config)` (or an injected set) through `scan_normalised`, calls `PolicyEngine.decide`, logs one row per tool result, and returns the (possibly rewritten) frame |
| `build_detectors(config)` | Factory registry keyed `rules_mcp`/`rules_inj`/`pii`/`v0`/`v3`; constructs exactly the union of keys named in `config`'s three role sets. `v0`/`v3` factories call `load_models_config()` lazily, so nothing imports torch/transformers or reads a joblib file unless a policy role actually names them |
| `gating_transport(inner, gate)` | Wraps any `Transport`, satisfying the same protocol |

Behaviours worth knowing:

- Frames are forwarded **byte-identical** for `Allow` and `Escalate` — the
  wrappers return the same object they received. For `Redact` and `Block`,
  `observe_inbound` returns a *new* `SessionMessage` built via
  `payload.model_copy()` + `dataclasses.replace()`; the original object is
  never mutated. Truncation still bounds *detection input only*.
- A JSON-RPC error is logged as `protocol_error` with no content extraction
  (FR-15). A tool-level failure (`isError`) is a normal `result` row with
  `tool_is_error` set — a different thing entirely.
- The pending-request map is bounded. A call whose response never arrives is
  evicted and the eviction is logged, so lost calls are visible rather than
  growing state (NFR-5).
- Only `tools/call` is tracked. `initialize`, `tools/list` and server-initiated
  requests produce no rows.
- `BLOCK` cannot surface while `config/policy.yaml` ships `calibrated: false`
  (FR-11) — `PolicyEngine._ceiling()` downgrades it to `ESCALATE` regardless of
  which branch produced it.

### `llmshield_mcp.corpus`

The payload corpus pipeline (FR-10, AC-6, M6): fetch raw sources, label them,
check them against V0/V3's own training data, store the result.

| Symbol | Purpose |
|---|---|
| `fetch()` / `load_adversarial()` / `load_benign()` | `sources.py`. BIPIA/InjecAgent (cached under `corpus/external/`, gitignored) and benign lines from this repository's own content. Moved here from `scripts/benchmark_rules.py`, which now imports them. |
| `fetch_llmail_inject()` / `load_llmail_inject()` | The third adversarial source family (`plan.md` Q3): `microsoft/llmail-inject-challenge` via HuggingFace's `datasets-server` REST API, sampled/deduplicated to 150 items. Deliberately separate from `load_adversarial()` -- folding it in would change what `scripts/benchmark_rules.py` measures. |
| `DecontaminationConfig` / `load_decontamination_config()` | `decontaminate.py`. Validated `config/decontamination.yaml`: shingle size, `num_perm`, Jaccard threshold, and the training-corpus reference path (`LLMSHIELD_TRAINING_CORPUS` override, same pattern as `config.py`'s `LLMSHIELD_MODELS_ROOT`) |
| `decontaminate(items, config, reference_texts=None)` | Flags near-duplicates (Jaccard >= threshold via `datasketch.MinHashLSH`) or exact normalised-text matches against the reference corpus. `reference_texts` lets tests supply a small in-memory reference set instead of the real ~19k-row file |
| `CorpusLabel` | `benign` / `adversarial` |
| `DecontaminationStatus` | `clean` / `contaminated` / `unchecked` -- distinct from `clean` so an unrun check cannot look decontaminated by construction |
| `PayloadCorpusItem` / `CorpusStore` | `store.py`. SQLite schema per `PROPOSAL.md` section 12. Unlike `DecisionLog`, stores the actual text -- the corpus is a project deliverable, not an audit trail |
| `CorpusStore.export_jsonl(path)` | The publishable snapshot -- one JSON object per row, field order matching the `PayloadCorpusItem` schema |

Behaviours worth knowing:

- Reused, not reinvented: the 5-char shingle definition and the 0.85 Jaccard
  threshold are `evaluation/experiment2/exp2_data.py`'s own values, so an item
  flagged contaminated here is held to the exact standard that kept V0/V3's
  training set disjoint from their eval suite. The MinHash *implementation*
  is `datasketch`, not a port of the dissertation's hand-rolled numpy version.
- Both labels are checked against the reference corpus, not just adversarial
  items -- the training set has a benign class too (dolly/alpaca), so a
  benign corpus item can be contaminated exactly as an adversarial one can.
- Contaminated items are kept, flagged via `decontamination_status`, never
  deleted -- a drop-count report needs them still visible.
- The training-data reference corpus (`corpus/reference/train.jsonl`) is not
  vendored, for the same reason V0/V3's weights are not: mixed-license public
  datasets this project has no redistribution rights over.

### `llmshield_mcp.gauge`

The GAUGE harness (FR-11, FR-12, NFR-6, NFR-7, M7/M8): statistics,
matched-FPR calibration, and the orchestrator that runs both against the
real corpus and weights.

| Symbol | Purpose |
|---|---|
| `wilson_ci(k, n)` / `clopper_pearson_ci(k, n)` | `stats.py`. Thin `statsmodels.stats.proportion.proportion_confint` wrappers (methods `"wilson"`/`"beta"`) -- not ported from either dissertation hand-rolled version |
| `mcnemar_test(a_correct, b_correct)` | `statsmodels.stats.contingency_tables.mcnemar`, exact binomial |
| `auroc_delong(positive, negative)` | Ported from `exp2_auroc_delong.py`'s pure-Python midrank DeLong implementation -- the one dissertation statistic confirmed correct rather than replaced |
| `threshold_at_fpr(scores, target_fpr)` | `calibrate.py`. Places the threshold so achieved FPR is always `<= target` (never above); flags `unreachable` for a constant-scored detector instead of a fake number. Convention from `exp2_multi_fpr.py`/`exp2_eval.py`, not their code |
| `partition_benign_references(items)` | `references.py`. Splits a benign pool into `(realistic, adversarial_styled)` via a word-boundary keyword filter -- independent of `config/rules.yaml`'s actual patterns |
| `run_gauge(db, output_dir, sample_size, seed)` | `run.py`. Loads the clean M6/M8 corpus, samples/splits the dual benign references, calibrates V0/V3 at each `config/policy.yaml` `fpr_budget`, computes ASR by threat type AND by source family (FR-12, M8 -- `_grouped_asr` shares one grouping implementation for both) and DeLong AUROC (all with CIs), writes `scores.csv` and `calibration_report.json` |

Behaviours worth knowing:

- `run_gauge` never edits `config/policy.yaml`. Flipping `calibrated: true`
  and moving `v0`/`v3` out of `inert` is a deliberate human decision after
  reading a run's report, per that file's own comment.
- Leave-one-source-out (FR-12) is a `by_source` ASR breakdown at the same
  calibrated threshold, not a retrain-with/without-family loop -- this
  project never retrains V0/V3, so there is no training-set-exclusion sense
  in which a family could be "held out" (`plan.md` 2.20/2.22). `run_gauge`
  warns (does not raise) if the corpus has fewer than two adversarial
  `source` values, since `by_source` needs at least two to compare.
- Every item is scored by every detector (`gauge/run.py:build_detectors`,
  distinct from `gating/transport.py`'s config-role-driven function of the
  same name) -- GAUGE always wants the full picture, unlike the live gate.
- Benign items are sampled (`DEFAULT_BENIGN_SAMPLE_SIZE = 300`, fixed seed)
  rather than scored in full, because V3's latency against ~7,500 ingested
  benign lines would take tens of minutes per run.
- `scores.csv` carries every item/detector pair plus a `config_hash` column
  fingerprinting the exact config files a run used -- the reproducibility
  file `plan.md` section 2.6 requires, since the weights themselves cannot be
  published.

### `llmshield_mcp.latency`

Latency measurement primitives (FR-13, FR-14, NFR-1, NFR-2, M9).

| Symbol | Purpose |
|---|---|
| `LatencyStats` | `mean_ms`, `p95_ms`, `n` |
| `summarize(durations_ms)` | Mean + p95 (linear-interpolation percentile, matching `numpy.percentile`'s default -- `exp2_eval.py`'s own convention) |
| `time_calls(fn, items, n_warm=10)` | Calls `fn` once per item, timing every call after the first `n_warm` -- warmup runs but is not counted, so one-time costs (lazy imports, cache fills) don't pollute the numbers |

`scripts/benchmark_latency.py` is the thin script pointing this at the real
detectors and corpus, mirroring the `corpus/sources.py` /
`scripts/benchmark_rules.py` split -- the reusable logic lives in `src/`,
the script is a runner with no logic of its own worth unit-testing.

### `llmshield_mcp.cli`

`main(argv)` — argparse, `--version`. Subcommands: `verify-models`,
`run-agent`, `corpus-ingest` (M6), `gauge-run` (M7/M8).

`verify_models(config_path, which)` loads V0 and/or V3, scores four probe texts
(`PROBES` plus `LONG_PROBE`), and for V3 instantiates once per long-text
strategy so the truncate/chunk contrast is directly visible. Returns 0 on
success, 1 if any detector failed, 2 if an artifact is missing.

`PROBES` and `LONG_PROBE` are smoke tests, not an evaluation corpus, and are
also imported by `tests/test_adapters_with_models.py`.

---

## 3. Data Flow (current)

```
config/rules.yaml, config/models.yaml, config/policy.yaml
   │  load_rules() / load_models_config() / load_policy_config()
   ▼
build_detectors(policy.config) ──► {rules_mcp, rules_inj, pii, v0, v3}
     (only the keys a role names;         │
      v0/v3 factories load weights        │
      lazily -- see gating/transport.py)  │
                                           ▼
                    tool-result text ────────┤ scan_normalised(detector, text)
                                              │   → DetectorResult (score|None, ...)
                                              ▼
                              {detector_key: DetectorResult}   (ALL detectors, incl. inert)
                                              │
                                              ▼
                             PolicyEngine.decide()  →  FusionOutcome
                                (Decision, redacted, redact_spans, note)
                                              │
                          ┌───────────────────┼────────────────────┐
                          ▼                   ▼                     ▼
                apply_redaction()   build_block_result()      DecisionLog.append()
                (Redact: mask       (Block: replace whole     (always: EVERY detector's
                 PII spans only)     result, FR-6)             score, incl. inert ones)
```

A third classifier, `guard`, joins them (`plan.md` 2.26): published,
Apache-2.0 and fetchable, so its measurements are reproducible by a reader in a
way V0/V3's can never be. It is inert too.

V0 and V3 are real detectors in this diagram (M5), but sit in
`detectors.inert`, not `detectors.injection` -- and as of the profile split
(`plan.md` 2.25) they are named only in `config/policy.research.yaml`, since an
inert detector still costs a full forward pass per tool result. --
`PolicyEngine.decide()` reads every detector's score into the log
unconditionally, but only consults `injection_detectors`/`redaction_detectors`
when deciding. Promoting either to `injection` (plus a threshold) is the
whole ablation; no code changes (`plan.md` 2.18).

---

## 4. Intended Data Flow (target, from `architecture_1.png`)

```
Reference Agent (Claude tool-use loop)
   │ (1) tool call — passes through unmodified
   ▼
Interception layer  ──(2) forward request──►  MCP server (filesystem / fetch)
   ▲                                                │
   │ (4) allowed / redacted / blocked result        │ (3) tool result
   │                                                ▼
   └──────────── Detection engine (parallel) ◄──────┘
                    rule engine │ V0 │ V3 │ PII scanner
                                  ▼
                     Signal fusion + policy engine
                     → Allow / Redact / Block / Escalate
                        │                        │
                        ▼                        ▼
                Audit / decision log      GAUGE evaluation harness
                     (SQLite)             (offline, batch, reproducible)
```

The figure draws the interception layer as a separate process. The M2-M10
implementation places the same interception point inside the client process at
the MCP SDK `Transport` boundary; see `plan.md` 2.1. M11 optionally recovers
the separate-process packaging over the same core.

---

## 5. Database

**None yet.** `PROPOSAL.md` [12] specifies SQLite with four tables —
`DecisionLog`, `PayloadCorpusItem`, `EvalRun`, `PolicyConfig`. `DecisionLog`
arrives in M2; the rest in M6 and M7. Raw tool-result content is not to be
retained by default; a hash is stored instead.

---

## 6. External Integrations

| Integration | Status |
|---|---|
| Reused LLMShield V0/V3 artifacts | Active, wired into the live gate as inert detectors (M5). Read from an external path; never modified. |
| Anthropic Claude API (`anthropic==0.86.0`) | **Active** — `ReferenceAgent`, model `claude-opus-5` |
| MCP Python SDK (`mcp==2.1.1`) | **Active** — client sessions over stdio. Transport interception is M2. |
| Official MCP filesystem server (`@modelcontextprotocol/server-filesystem@2026.8.31`, via `npx`) | **Active** — 14 tools, confined to `sandbox/` |
| Official MCP fetch server (`mcp-server-fetch==2026.8.18`, via `uvx`) | **Active** — 1 tool |
| HuggingFace `transformers` / `torch` | Active (V3) |
| `scikit-learn` / `joblib` | Active (V0) |
| `datasketch` | **Active** (M6) -- `MinHash`/`MinHashLSH` for corpus decontamination. |
| `statsmodels` | **Active** (M7) -- Wilson/Clopper-Pearson (`proportion_confint`), McNemar (`contingency_tables.mcnemar`). |
| `scipy` | Active (dependency of `statsmodels`/`scikit-learn`); no direct call from this project's own code yet. |

---

## 7. Key Dependencies

Python 3.11 (`requires-python = ">=3.11,<3.12"`). Managed with `uv`; full
transitive set locked in `uv.lock` (111 packages).

| Package | Version | Note |
|---|---|---|
| `mcp` | 2.1.1 | 2.x; types live in a separate `mcp-types` package |
| `anthropic` | 0.86.0 | |
| `torch` | 2.14.0 | CPU |
| `transformers` | 5.12.1 | **Load-bearing** — wrote V3's config |
| `scikit-learn` | 1.9.0 | **Load-bearing** — wrote V0's joblib |
| `numpy` / `scipy` | 2.4.3 / 1.17.1 | |
| `datasketch` | 2.0.0 | MinHash/LSH, M6 |
| `statsmodels` | 0.15.0 | **Active** (M7) -- Wilson, Clopper-Pearson, McNemar |
| `pyyaml` | 6.0.3 | Config |
| `joblib` | 1.5.2 | V0 artifact loading |

Dev: `pytest` 8.4.2, `pytest-asyncio` 1.3.0, `ruff` 0.14.4, `mypy` 1.18.2.

`tokenizers` and `safetensors` are deliberately not pinned directly — they are
`transformers`' own sub-dependencies and are constrained through `uv.lock`.

---

## 8. Conventions

- `src/` layout, package `llmshield_mcp`, CLI entry point `toolgate`.
- `from __future__ import annotations` in every module.
- Frozen, slotted dataclasses for value types.
- mypy `strict` for our own code; untyped third-party packages silenced by
  per-module override rather than by weakening strictness.
- ruff line length 100; rule set `E, F, I, UP, B, SIM`.
- Tests marked `models` require the reused artifacts and are deselected in CI.
- Comments explain *why*, not *what*, and are used where a decision would
  otherwise look arbitrary.
