# code_summary.md — Codebase Map

Factual map of what exists in this repository. Updated when structure changes.

**As of M2.** 1976 lines of source, 1596 lines of tests, 114 tests. The
interception layer exists and logs every tool result, but runs **no detectors**.
There is no policy engine, no corpus and no evaluation harness yet — M3 onward.

---

## 1. Project Structure

```
D:\LLMSHIELD-MCP\
├── PROPOSAL.md                  MVP technical proposal (requirements source)
├── CLAUDE.md                    engineering rules for AI agents (untracked)
├── prd.md                       requirements + amendments
├── plan.md                      milestones, architecture decisions, risks
├── whats_has_been_done.md       running implementation history
├── code_summary.md              this file
├── architecture_1.png           component/data-flow figure (untracked)
├── pyproject.toml               package metadata, exact pins, tool config
├── uv.lock                      full transitive lock (111 packages)
├── config/
│   ├── models.yaml              paths + runtime settings for reused detectors
│   └── servers.yaml             reference MCP server launch specs + sandbox
├── sandbox/                     synthetic benign corpus; filesystem server is
│                                confined to this directory (SEC-4)
├── chains/
│   └── baseline.json            recorded benign tool-call chain (M1 fixture)
├── docs/
│   ├── PINNING.md               why scikit-learn and transformers are pinned
│   └── M0-OBSERVATIONS.md       M0 probe observations (explicitly not results)
├── src/llmshield_mcp/
│   ├── __init__.py              __version__ = "0.1.0"
│   ├── __main__.py              python -m llmshield_mcp
│   ├── agent.py                 reference Claude tool-use loop over MCP (230)
│   ├── chain.py                 recorded tool-call chain format (107)
│   ├── cli.py                   CLI entry point (188)
│   ├── config.py                config loading + score-mode collapse (145)
│   ├── servers.py               MCP server config + sandbox resolution (88)
│   ├── settings.py              .env / environment secrets (38)
│   ├── gating/
│   │   ├── audit.py             SQLite decision log, Decision/Outcome (173)
│   │   ├── content.py           result extraction + size policy (133)
│   │   └── transport.py         Gate + stream wrappers (281)
│   └── detectors/
│       ├── __init__.py          exports; V3 imported lazily (31)
│       ├── base.py              detector contract (118)
│       ├── v0_lexical.py        V0 adapter (79)
│       └── v3_transformer.py    V3 adapter (108)
├── tests/
│   ├── test_agent.py            tool-use loop, faked client + sessions (13)
│   ├── test_chain.py            chain round-trip and schema (6)
│   ├── test_config.py           config + score-mode tests (15)
│   ├── test_detector_base.py    contract tests (7)
│   ├── test_gating_audit.py     decision log store (7)
│   ├── test_gating_content.py   extraction, size policy, section 19 cases (18)
│   ├── test_gating_transport.py gate behaviour + stream wrappers (20)
│   ├── test_servers.py          server config + sandbox validation (8)
│   └── test_adapters_with_models.py  reuse audit, marked `models` (7)
└── .github/workflows/ci.yml     lint, format, type-check, test (CURRENTLY FAILING)
```

Not tracked by git: `.venv/`, `models/`, `.env`, `*.joblib`, `*.safetensors`,
`logs/`, `*.sqlite`.

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

The interception layer (M2). Observes every frame and logs a decision per tool
result; **runs no detectors**.

| Symbol | Purpose |
|---|---|
| `Decision` | `allow` / `redact` / `block` / `escalate` (FR-4). M2 only emits `allow`. |
| `Outcome` | `result` / `protocol_error` / `detector_failure` — what kind of frame the row is about |
| `DecisionRecord` | One log row. `latency_ms` is time inside the gate; `roundtrip_ms` is client-to-server-and-back, kept separate so NFR-1 stays measurable |
| `DecisionLog` | Append-only SQLite store. Content is **hashed, never stored** (section 12) |
| `extract(result, max_chars)` | Raw `tools/call` result -> scannable text, block types, truncation flag, SHA-256 of the *full* pre-truncation text |
| `GateConfig` | `max_result_chars` (FR-16/SEC-2), `max_pending` (NFR-5) |
| `Gate` | Correlates requests to responses, logs one row per tool result |
| `gating_transport(inner, gate)` | Wraps any `Transport`, satisfying the same protocol |

Behaviours worth knowing:

- Frames are forwarded **byte-identical** — the wrappers return the same object
  they received. Truncation bounds *detection input only* and never alters what
  the agent sees.
- A JSON-RPC error is logged as `protocol_error` with no content extraction
  (FR-15). A tool-level failure (`isError`) is a normal `result` row with
  `tool_is_error` set — a different thing entirely.
- The pending-request map is bounded. A call whose response never arrives is
  evicted and the eviction is logged, so lost calls are visible rather than
  growing state (NFR-5).
- Only `tools/call` is tracked. `initialize`, `tools/list` and server-initiated
  requests produce no rows.

### `llmshield_mcp.cli`

`main(argv)` — argparse, `--version`, subcommand `verify-models`.

`verify_models(config_path, which)` loads V0 and/or V3, scores four probe texts
(`PROBES` plus `LONG_PROBE`), and for V3 instantiates once per long-text
strategy so the truncate/chunk contrast is directly visible. Returns 0 on
success, 1 if any detector failed, 2 if an artifact is missing.

`PROBES` and `LONG_PROBE` are smoke tests, not an evaluation corpus, and are
also imported by `tests/test_adapters_with_models.py`.

---

## 3. Data Flow (current)

```
config/models.yaml
   │  load_models_config()  → validates, applies LLMSHIELD_MODELS_ROOT
   ▼
ModelsConfig ──► V0LexicalDetector / V3TransformerDetector  (construction)
                          │
   text ──────────────────┤ Detector.score(text)
                          │   ├── times the call
                          │   ├── delegates to _score(text) → RawScore
                          │   └── contains any exception
                          ▼
                   DetectorResult   (score | None, detail, spans, latency, error)
```

There is no consumer of `DetectorResult` yet. The fusion and policy engine
(M4) will be the first.

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
| Reused LLMShield V0/V3 artifacts | Active. Read from an external path; never modified. |
| Anthropic Claude API (`anthropic==0.86.0`) | **Active** — `ReferenceAgent`, model `claude-opus-5` |
| MCP Python SDK (`mcp==2.1.1`) | **Active** — client sessions over stdio. Transport interception is M2. |
| Official MCP filesystem server (`@modelcontextprotocol/server-filesystem@2026.8.31`, via `npx`) | **Active** — 14 tools, confined to `sandbox/` |
| Official MCP fetch server (`mcp-server-fetch==2026.8.18`, via `uvx`) | **Active** — 1 tool |
| HuggingFace `transformers` / `torch` | Active (V3) |
| `scikit-learn` / `joblib` | Active (V0) |
| `datasketch` | Installed, unused. Decontamination is M6. |
| `statsmodels` / `scipy` | Installed, unused. Statistics are M7. |

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
| `statsmodels` | 0.15.0 | Wilson, Clopper-Pearson, McNemar, M7 |
| `pyyaml` | 6.0.3 | Config |
| `joblib` | 1.5.2 | V0 artifact loading |

Dev: `pytest` 8.4.2, `pytest-asyncio` 1.3.0, `ruff` 0.14.4, `mypy` 1.18.2.

`tokenizers` and `safetensors` are deliberately not pinned directly — they are
`transformers`' own sub-dependencies and are constrained through `uv.lock`.

---

## 8. Conventions

- `src/` layout, package `llmshield_mcp`, CLI entry point `mcp-shield`.
- `from __future__ import annotations` in every module.
- Frozen, slotted dataclasses for value types.
- mypy `strict` for our own code; untyped third-party packages silenced by
  per-module override rather than by weakening strictness.
- ruff line length 100; rule set `E, F, I, UP, B, SIM`.
- Tests marked `models` require the reused artifacts and are deselected in CI.
- Comments explain *why*, not *what*, and are used where a decision would
  otherwise look arbitrary.
