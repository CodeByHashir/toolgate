# code_summary.md — Codebase Map

Factual map of what exists in this repository. Updated when structure changes.

**As of M0.** 612 lines of source, 340 lines of tests. There is no interception
layer, no policy engine, no corpus and no evaluation harness yet — those are
M2 onward.

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
│   └── models.yaml              paths + runtime settings for reused detectors
├── docs/
│   ├── PINNING.md               why scikit-learn and transformers are pinned
│   └── M0-OBSERVATIONS.md       M0 probe observations (explicitly not results)
├── src/llmshield_mcp/
│   ├── __init__.py              __version__ = "0.1.0"
│   ├── __main__.py              python -m llmshield_mcp
│   ├── cli.py                   CLI entry point (126 lines)
│   ├── config.py                config loading + score-mode collapse (143)
│   └── detectors/
│       ├── __init__.py          exports; V3 imported lazily (31)
│       ├── base.py              detector contract (118)
│       ├── v0_lexical.py        V0 adapter (79)
│       └── v3_transformer.py    V3 adapter (108)
├── tests/
│   ├── test_config.py           config + score-mode tests (15 tests)
│   ├── test_detector_base.py    contract tests (7 tests)
│   └── test_adapters_with_models.py  reuse audit, marked `models` (7 tests)
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
| `load_models_config(path=None)` | function | Reads YAML, applies `LLMSHIELD_MODELS_ROOT` override, validates, returns `ModelsConfig` |

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
| Anthropic Claude API (`anthropic==0.86.0`) | Installed, unused. Reference agent is M1. |
| MCP Python SDK (`mcp==2.1.1`) | Installed, unused. Interception is M2. |
| Official MCP filesystem server (npm, Node v24.14.1 present) | M1 |
| Official MCP fetch server (PyPI `mcp-server-fetch`) | M1 |
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
