# whats_has_been_done.md — Running Implementation History

Companion to `prd.md` (what to build) and `plan.md` (how, and what's left).
This file is the log of what actually happened, oldest first, matching git
history. Append new entries at the end.

---

## M0 — Scaffold, pinned CPU stack, reuse audit for V0/V3

**Commit:** `50993de` — "M0: scaffold, pinned CPU stack, and reuse audit for V0/V3"

**What changed:**

- `pyproject.toml` — package `llmshield-mcp`, Python `>=3.11,<3.12`, exact
  version pins for every dependency (NFR-8). `scikit-learn==1.9.0` and
  `transformers==5.12.1` pinned specifically to match the serialisation
  versions of the reused V0/V3 artifacts (see `docs/PINNING.md`). CLI entry
  point `mcp-shield = "llmshield_mcp.cli:main"`. `pytest` marker `models`
  registered for tests that need the (unpublishable) reused weights.
- `src/llmshield_mcp/config.py` — `load_models_config()`, `V0Config`/
  `V3Config`/`ModelsConfig` frozen dataclasses, `DETECTOR_CLASSES =
  ("benign", "injection", "jailbreak", "harmful")`, `scalar_from_proba()`
  implementing the per-detector `score_mode` collapse (`not_benign` vs a
  named class). Validates `config/models.yaml` eagerly at load time.
- `src/llmshield_mcp/detectors/base.py` — the `Detector` ABC and
  `DetectorResult`/`RawScore`/`Span` contract. Subclasses implement only
  `_score()`; the base class owns timing and turns any exception into a
  failed result (`score=None`, never `0.0`/`NaN` — see `plan.md` 2.2).
- `src/llmshield_mcp/detectors/v0_lexical.py` — `V0LexicalDetector`, loads
  the joblib TF-IDF+LogisticRegression artifact, promotes scikit-learn's
  `InconsistentVersionWarning` to a hard `ValueError`, validates saved class
  order against `DETECTOR_CLASSES`.
- `src/llmshield_mcp/detectors/v3_transformer.py` — `V3TransformerDetector`,
  loads `DebertaV2ForSequenceClassification` on CPU. `_score()` uses the
  tokenizer's native `return_overflowing_tokens` sliding window (`truncate`
  vs `chunk_max` strategy, `chunk_stride`, `max_chunks` cap, `batch_size`).
- `src/llmshield_mcp/cli.py` — `mcp-shield verify-models`: loads V0/V3,
  scores four probe texts plus one long-content probe, prints per-class
  scores and latency.
- `tests/test_config.py`, `tests/test_detector_base.py`,
  `tests/test_adapters_with_models.py` — 29 tests total (22 contract tests
  runnable without weights, 7 marked `models`).
- `docs/PINNING.md`, `docs/M0-OBSERVATIONS.md` — pin rationale and four
  smoke-test observations (context dilution, benign false-positive rate,
  score-mode asymmetry, latency), explicitly labelled as not results.
- `README.md`, `LICENSE`, `.github/workflows/ci.yml`.

**Verification performed:** `uv run mcp-shield verify-models` — both
detectors load on CPU and score all probes; `uv run pytest` — full suite
green. Re-verified in this session on 2026-09-04: `29 passed` (all tests
including the `models`-marked ones, since the local weights path resolved).

**Known limitation carried forward:** `.github/workflows/ci.yml` fails on
every push (`No system Python installation found for Python 3.11` — `uv pip
install --system` has no target under `astral-sh/setup-uv@v7`). Root cause
identified, fix proposed in `plan.md` section 6 (D1). **Not fixed yet** —
out of scope for M0/the docs-sync pass that found it; awaiting go-ahead.

---

## Project memory sync (pre-M1)

**What changed:** `prd.md`, `plan.md`, `code_summary.md` written from a full
read of `PROPOSAL.md`, `README.md`, `docs/`, `src/`, `tests/`, and git
history, per `CLAUDE.md` section 7. This file (`whats_has_been_done.md`) added
to complete the set — it was referenced by `code_summary.md`'s own file tree
but had not actually been created yet.

**Why:** M0 was implemented and committed before these memory files existed,
so nothing recorded milestone scope, the interception-architecture decision,
or the M0 smoke-test findings' implications in a form a future session (or
another reader) could pick up without re-deriving it from the diff.

**Nothing in the source tree changed in this pass** — docs only.

---

*Next entry should be M1 (reference MCP servers + agent + tool-call-chain
fixture) once implemented.*

---

## Repository published to GitHub (private)

**What changed:** created `CodeByHashir/llmshield-mcp` (visibility `PRIVATE`)
and pushed `main`. Added `.gitattributes` (`* text=auto eol=lf`) to normalise
line endings.

**Why:** user request — offsite backup and CV artifact.

**Details:**

- The first push was rejected: the `CodeByHashir` token lacked the `workflow`
  scope and the commit contains `.github/workflows/ci.yml`. Resolved by the
  user granting it via `gh auth refresh -s workflow`; scopes are now
  `gist, read:org, repo, workflow`.
- The active `gh` account was switched from `hashirSynapse` to `CodeByHashir`
  and remains switched.

**Verification:** remote tree listed via
`gh api repos/CodeByHashir/llmshield-mcp/git/trees/main?recursive=1` —
24 blobs, no weights, no `.env`, no secrets.

**Known limitation:** `config/models.yaml` embeds an absolute local path
(`<LLMShield checkout>/...`). Harmless while the repository
is private; it must become a relative default before the repository is made
public. Tracked as open question Q4 in `plan.md`.

---

## M1 — Reference MCP servers, minimal agent, recorded chain fixture

**What changed:**

- `sandbox/` — synthetic benign corpus the filesystem MCP server is confined to
  (SEC-4): `README.md`, `notes/meeting-notes.md`, `src/config_loader.py`,
  `data/quarterly.csv`. Committed, not gitignored, so the benign baseline is
  reproducible. `config_loader.py` deliberately contains the words "ignore all
  previous" and `SYSTEM_PROMPT_DEFAULTS` in genuinely benign source code — the
  false-positive case PROPOSAL.md section 2 predicts.
- `config/servers.yaml` — launch specs for both reference servers, pinned
  (`@modelcontextprotocol/server-filesystem@2026.8.31` via npx,
  `mcp-server-fetch==2026.8.18` via uvx). An unpinned `npx`/`uvx` would upgrade
  silently between runs and make recorded chains irreproducible.
- `src/llmshield_mcp/servers.py` — `ServerSpec`, `ServersConfig`,
  `load_servers_config()`. Substitutes `{sandbox}` into arguments; raises
  `NotADirectoryError` if the sandbox is absent rather than creating it.
- `src/llmshield_mcp/settings.py` — `Settings.require_anthropic_api_key()`,
  reading `.env` via pydantic-settings (already a dependency; no dotenv package
  added).
- `src/llmshield_mcp/chain.py` — `ToolCallRecord`, `ChainRecord`,
  `SCHEMA_VERSION = 1`, JSON read/write.
- `src/llmshield_mcp/agent.py` — `ReferenceAgent`, `open_servers`,
  `to_anthropic_tool`, `flatten_result`, tool-name qualification.
- `src/llmshield_mcp/cli.py` — new `run-agent` subcommand.
- `src/llmshield_mcp/config.py` — added `REPO_ROOT`; `DEFAULT_CONFIG_PATH` now
  derives from it. No behaviour change.
- `tests/test_servers.py` (8), `tests/test_chain.py` (6), `tests/test_agent.py`
  (13) — all offline, with the Anthropic client and MCP sessions faked.
- `pyproject.toml` — `asyncio_mode = "auto"` for pytest-asyncio.

**Why a manual tool-use loop rather than the SDK's beta `tool_runner`:** the
loop is what is being instrumented (correlation IDs, timing, recorded results),
M2 replaces the transport underneath it, and the runner does not auto-resume
`pause_turn` — which would truncate a chain silently mid-recording. Full
rationale in `plan.md` 2.7. Cost was ~15 lines of hand-written schema
conversion.

**Evidence gathered rather than assumed:**

- `mcp` 2.x exposes `Tool.input_schema` and `CallToolResult.is_error`
  (snake_case, wire aliases `inputSchema`/`isError`). The 1.x-style attribute
  names used in the SDK's own published examples would have raised
  `AttributeError`. Verified by inspecting `mcp_types` model fields.
- `anthropic[mcp]` requires only `mcp>=1.0`, already pinned — so the official
  `mcp_tool` helper would have been free, but it returns a `BetaFunctionTool`
  usable only with the beta runner.
- Both servers were launched manually before any code was written.

**Verification performed:**

| Check | Result |
|---|---|
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | Clean |
| `uv run mypy` | Success, 12 source files |
| `uv run pytest` | **56 passed** |
| `uv run mcp-shield run-agent --servers filesystem,fetch` | Exit 0 |

The end-to-end run connected both servers (filesystem: 14 tools; fetch: 1),
made **7 tool calls** — `list_allowed_directories`, `fetch` of
`https://example.com`, `directory_tree`, and four `read_text_file` calls — and
wrote `chains/baseline.json`. SEC-4 was confirmed by the server's own startup
line: `allowed directories set from server args: [ 'D:\LLMSHIELD-MCP\sandbox' ]`.

**Known limitations:**

- The recorded chain has 7 calls. FR-14 requires a chain of at least 20
  sequential calls; that longer fixture is recorded in M9 when the latency
  benchmark needs it.
- Chain fixtures embed absolute host paths — defect D2 in `plan.md` section 6.
  Not fixed; it needs a decision, and it is the same class as Q4.
- The fetch server logs `A working NPM installation was not found ... reverting
  to pure-Python mode`. It falls back to Python article extraction, which works
  but may extract differently from Readability.js. Harmless for M1; worth noting
  because it affects what fetched text looks like in later corpora.
- No interception, no detection. The agent talks to the servers directly. That
  is M2 by design — interception transparency is proven before any detection
  exists.

---

## M0/M1 finalisation — D1, D2, Q4, model selection, cost visibility

Closes every open defect and question from M0 and M1 before M2 begins.

### D1 — CI fixed

`.github/workflows/ci.yml` used `uv pip install --system`, which fails with
`No system Python installation found for Python 3.11`: `astral-sh/setup-uv`
provisions a uv-managed interpreter, not a system one. The install step never
completed, so **lint, type-check and tests had never run in CI at all**.

Replaced with `uv sync --extra dev --frozen` plus `uv run` per step. `--frozen`
also fails the build on a stale lockfile, stricter for NFR-8 than before.

Second part, same root concern: constraint A3 is CPU-only, but on Linux PyPI's
`torch` is the CUDA build. `[tool.uv.sources]` now resolves torch from the
PyTorch CPU index under a `sys_platform == 'linux'` marker. Re-locking removed
`nvidia-nvjitlink`, `nvidia-nvshmem-cu13`, `nvidia-nvtx` and `triton`, and
pinned `torch 2.14.0+cpu`.

**Verified:** CI run `33896832340`, conclusion `success`, 1m18s. All eight steps
ran — Lint `All checks passed!`, Type check `Success: no issues found in 12
source files`, Test `49 passed, 7 deselected`. Windows resolution unchanged
(`torch 2.14.0+cpu`, `torch.version.cuda is None`).

### D2 — chain fixtures no longer disclose host paths

`chain.py` schema version 1 -> 2.

- `normalise()` / `restore()` recursively rewrite strings inside arguments and
  result text, handling both native and POSIX spellings of a Windows path.
- `SANDBOX_PLACEHOLDER` moved to `config.py` so `servers.yaml` handling and
  chain fixtures share one definition.
- `ChainRecord.read(path, sandbox_root=...)` resolves the placeholder; without
  it the portable form is returned, which is what inspection and diffing want.
- Normalisation applies only to the *stored* form. The tool ran against the
  real path.

**A field that had to be removed again.** The first cut also stored
`recorded_sandbox_root` "for provenance", which reintroduced the exact
disclosure the placeholder prevents, and nothing read it. Removed, with a
comment in `chain.py` recording why so it is not re-added.

**How that was caught.** The first version of
`test_committed_fixture_discloses_no_absolute_path` constructed its own record
and set the offending field to empty, so it passed while the committed fixture
still contained `D:\LLMSHIELD-MCP\sandbox`. It now reads the real
`chains/baseline.json`. A second iteration was needed after the naive `":/"`
marker matched `https://example.com` in legitimate fetched content; the check
is now a drive-letter regex with a lookbehind excluding URL schemes.

**Verified:** `chains/baseline.json` re-recorded and grepped — zero host paths,
`{sandbox}` present, no `recorded_sandbox_root` key.

### Q4 — model artifact path is now relative

`config/models.yaml` root changed from
`<LLMShield checkout>/evaluation/experiment2/models` to
`models`. `load_models_config` resolves a relative root against `REPO_ROOT`.
`models/` is gitignored; locally it is a directory junction to the LLMShield
artifacts.

**Verified:** `mcp-shield verify-models --detector v0` loads from
`D:\LLMSHIELD-MCP\models0_tfidf_lr.joblib` and produces scores identical to
before the change (0.8793 / 0.9400 / 0.9922 / 0.5718), confirming the same
artifact through the new path.

### Model selection

`--model` flag on `run-agent`. `DEFAULT_AGENT_MODEL` lives in `config.py`, not
`agent.py`, so `--help` does not import anthropic and mcp.

The two model IDs originally proposed are not usable:
`claude-3-5-haiku-20241022` was **retired** on 19 Feb 2026, and
`claude-3-haiku-20240307`'s retirement date of 19 Apr 2026 has passed. The
current cheap model is `claude-haiku-4-5`.

Default stays `claude-opus-5` for chains that feed the evaluation, because
PROPOSAL.md section 3.1 asks for *realistic* chains and a weaker model produces
a thinner sequence — measured: on comparable tasks opus made 7-9 tool calls
where `claude-haiku-4-5` made 3.

### Cost visibility

`UsageRecord` on every `ChainRecord`: `api_calls`, `input_tokens`,
`output_tokens`, and both cache counters, accumulated across the loop and
printed by the CLI. `plus()` tolerates missing or `None` fields, since not
every response carries every cache counter.

**Measured:** the committed baseline cost **6 API calls, 25,712 input / 1,396
output tokens** — about **$0.16** at Opus 5 rates. Under assumption A2 this is
a one-off per fixture and does not scale with corpus size.

### Recorded baseline

Re-recorded under schema 2: **9 tool calls** across both servers. Call 1 is a
genuine `directory_tree` failure — the model passed an absolute path where the
filesystem server wanted one relative to its root, so the server doubled it.
The agent recovered via `list_directory`. This is real agent behaviour, and the
chain records failures rather than dropping them.

Chains are not deterministic across runs: three recordings of the same task
produced 7, 8 and 9 calls with different tool choices. That is expected model
non-determinism and is why the fixture is committed rather than regenerated.

### Verification

| Check | Result |
|---|---|
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | 19 files already formatted |
| `uv run mypy` | Success, 12 source files |
| `uv run pytest` | **69 passed** |
| `uv run mcp-shield verify-models --detector v0` | OK, scores unchanged |
| `uv run mcp-shield run-agent` | Exit 0, 9 calls, usage reported |
| GitHub Actions | run 33896832340 **success** |

### Known limitations

- Chain length is 9 calls; FR-14 needs 20+ sequential calls, recorded in M9.
- The fetch server still runs in pure-Python extraction mode (no NPM found),
  which may extract differently from Readability.js.
- Cache token counters are recorded but currently always zero — prompt caching
  is not enabled on the agent. Worth revisiting if chain recording grows.

---

## M2 — Interception layer (logging only, zero detectors)

**What changed:**

- `src/llmshield_mcp/gating/transport.py` — `Gate`, `GateConfig`,
  `_ObservedReadStream`, `_ObservedWriteStream`, `gating_transport()`.
- `src/llmshield_mcp/gating/audit.py` — `Decision`, `Outcome`,
  `DecisionRecord`, `DecisionLog`, SQLite schema per PROPOSAL.md section 12.
- `src/llmshield_mcp/gating/content.py` — `extract()`, the size policy, and
  defined behaviour for every awkward case in section 19.
- `src/llmshield_mcp/agent.py` — `open_servers()` gained `gate_factory`. This
  is the seam left deliberately in M1; the agent code is otherwise unchanged.
- `src/llmshield_mcp/cli.py` — `--db` enables interception, `--max-result-chars`
  makes the FR-16 ceiling configurable without a code change.
- `tests/test_gating_transport.py` (20), `tests/test_gating_content.py` (18),
  `tests/test_gating_audit.py` (7).

**Why no detectors:** M2 ships logging-only on purpose. Interception
transparency has to be demonstrable on its own, so that when detection arrives
in M3-M5 any change in agent behaviour is attributable to the detectors rather
than to the plumbing.

### Design decisions

**Stream wrappers, not pump tasks.** `ReadStream`/`WriteStream`
(`mcp/shared/_stream_protocols.py`) are five-method protocols, so a delegating
wrapper satisfies them with no concurrency of its own. The alternative — fresh
memory streams plus two copy tasks — would have added cancellation, shutdown
ordering and backpressure concerns for no benefit, since every frame is
forwarded unchanged anyway.

**`__getattr__` delegates to the inner stream.** The SDK reads `last_context`
off a read stream; a wrapper that hid unknown attributes would silently change
session behaviour, which is the opposite of AC-1.

**The whole log schema is fixed now**, including all four `Decision` values and
`detector_scores`, even though M2 only writes `allow` with `{}`. A later
milestone must not need a schema change, or the logging-only baseline stops
being comparable.

**`Outcome.PROTOCOL_ERROR` is separate from `RESULT`** for a measurement
reason: a JSON-RPC error carries no tool content (FR-15), so counting those
rows as benign allows would inflate the denominator of any later
false-positive rate.

**`latency_ms` and `roundtrip_ms` are separate columns.** The M2 numbers show
why — gate time is ~0.04 ms against a 467 ms fetch round trip. One column would
have made NFR-1 unmeasurable.

### Verification

| Check | Result |
|---|---|
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | Clean |
| `uv run mypy` | Success, 16 source files |
| `uv run pytest` | **114 passed** |
| End-to-end with `--db` | **10 tool calls -> exactly 10 log rows** |

End-to-end run used `--model claude-haiku-4-5` (a verification run, not an
evaluation fixture; cost 8 API calls, 29,208 in / 714 out).

Log contents confirmed by direct query:

- 10 rows, **10 unique correlation IDs** — interleaving is attributable.
- All `fused_decision = allow`, all `detector_scores = {}`. If either ever
  differs in M2, detection leaked in early.
- **Gate overhead 0.029–0.055 ms** against round trips of 1.9–466.9 ms. Well
  inside the NFR-1 ~5 ms budget, though NFR-1 is really about the detector path
  that M5 adds.
- Two rows have `tool_is_error = 1` with `outcome = result` — tool-level
  failures, correctly *not* classified as protocol errors.
- Two rows share a `raw_result_hash` because their content was identical.
- **Zero raw content in the database.** Verified by scanning the SQLite file
  for four distinctive strings from the sandbox and the fetched page; all
  returned 0 occurrences (section 12).

### On "byte-identical agent behaviour"

The milestone's original wording was that gated agent behaviour should be
byte-identical to M1. That is not testable as stated: the model is
non-deterministic, and three recordings of one task already produced 7, 8 and 9
calls. What *is* established:

1. `test_read_wrapper_forwards_the_identical_object` and its write-side twin
   assert object **identity** (`is`), not equality — the session receives
   exactly the frame that arrived.
2. Tool results through the gate were byte-for-byte the same sizes as in
   ungated runs (330 / 572 / 597 / 151 characters for the four sandbox files).
3. All 15 tools across both servers functioned normally.

### Known limitations

- Chain length is 10 calls. FR-14 needs 20+ sequential calls; that fixture is
  recorded in M9.
- FR-15 is covered by unit tests but was not observed against a real
  server-generated JSON-RPC error, since neither reference server produced one.
  Tool-level `isError` was exercised for real.
- `max_result_chars` is a CLI flag, not yet part of a versioned policy file.
  FR-9 moves it there in M4.
- Gate latency was measured incidentally, not benchmarked. FR-13/NFR-1 proper
  measurement is M9.
- The gate logs but cannot yet modify a frame. Redact and Block need the policy
  engine (M4) and are unreachable in M2 by construction.

---

## M3 — Rule engine and PII scanner ported as detector adapters

**What changed:**

- `config/rules.yaml` — the dissertation's 19 injection regexes with their
  original ids and severities, carried across verbatim. `description` fields
  are annotation added here; the source rules carried none.
- `src/llmshield_mcp/detectors/rules.py` — `Rule`, `load_rules()`,
  `RuleDetector`.
- `src/llmshield_mcp/detectors/pii.py` — `PATTERNS`, `NER_ONLY_ENTITIES`,
  `luhn_valid()`, `redact()`, `PiiDetector`.
- `src/llmshield_mcp/detectors/__init__.py` — exports the two new adapters,
  `Rule`, `load_rules` and `redact`.
- `tests/test_detector_rules.py` (24), `tests/test_detector_pii.py` (31).

**Sources read before writing anything** (CLAUDE.md sections 1-3):
`src/llmshield/pre_llm/rule_engine.py`, `src/llmshield/pre_llm/pii_scanner.py`,
and `policies/default.json` in the LLMShield repository. Nothing was written
there.

### Ported, not imported

The LLMShield repo is a read-only reference and not an installed dependency,
and its scanners implement `InputScanner.scan(prompt, PolicyConfig)`, which
drags in structlog and pydantic policy models this project does not have. The
reused asset is the rule and pattern *data*; the matching plumbing is about
twenty lines per adapter behind this project's own `Detector` contract.

Rules are data, so they live in `config/rules.yaml` rather than in Python.

### One deliberate behavioural difference

The dissertation calls `pattern.search()` and keeps only the first match of
each rule, because it needed nothing more than a binary flag. Both adapters
here use `finditer()` and record every match as a `Span`, because FR-5 has to
mask every offending region rather than the first one. Scores are unaffected:
binary for rules, max-confidence for PII, exactly as before.

### SEC-3 / NFR-4 — PII cannot leak through a detector result

`RawScore.detail` is typed `dict[str, float]` and `Span` holds integer offsets
plus an entity-type label. Neither can carry a matched value, so a PII string
cannot reach the decision log through a detector result at all. That is
enforced by the type rather than by remembering to strip a field.
`test_a_full_result_can_be_serialised_without_leaking` serialises a complete
result containing four synthetic PII values and asserts none survives.

### SEC-6 — explicit fail-closed tests

Both adapters have a test that drives them with a pattern object that raises
during matching. Each produces a `DetectorResult` with `failed=True`,
`score=None`, the exception text in `error`, and empty spans and detail — not
an exception escaping into the gating path. Translating that into Block or
Escalate remains the policy engine's job in M4.

### Verification

| Check | Result |
|---|---|
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | Clean |
| `uv run mypy` | Success, 18 source files |
| `uv run pytest` | **169 passed** (55 new) |

Behaviour confirmed directly against the real artifacts: `load_rules()` returns
19 rules with ids `INJ-001`..`INJ-019`; `PiiDetector` reports six supported
entity types; a combined probe fired `INJ-001` and `INJ-007` with two spans.

### An observation worth recording

The rule engine produced **zero false positives** on all four sandbox files and
on both benign probes from `cli.PROBES` — including `sandbox/src/config_loader.py`,
which contains the string "Ignore all previous overrides" and
`SYSTEM_PROMPT_DEFAULTS`. INJ-001 requires the literal word "instructions", so
"overrides" does not match.

That is the opposite of the trained detectors on the same content: V0 scores
`config_loader.py`-style code at 0.94 and V3 at `injection = 0.996`
(`docs/M0-OBSERVATIONS.md`). On this surface the narrow hand-written regexes
look far more precise than the classifiers trained on user-prompt injection.

This is a smoke-test observation on four files, not a finding. It does suggest
the benign-reference sets in M7 should be sized to separate rule precision from
classifier precision, since they may differ sharply.

### Known limitations

- **Not wired into the gate.** The gate cannot act on multiple detector scores
  until fusion exists, so wiring happens in M4/M5. `Gate` still records
  `detector_scores = {}`.
- FR-2 remains only partly satisfied: rules and PII are done, V0 and V3 are
  adapters but not in the live path.
- The rule patterns were written for user prompts. Whether they transfer to
  tool results is the research question, and 19 English regexes will not
  generalise to non-English content (a stated section 19 limitation).
- `redact()` exists and is tested but nothing calls it yet; Redact as a
  decision needs the policy engine.
- PII coverage is pattern-based only. `PERSON`, `LOCATION` and other NER
  entities are skipped, as in the dissertation.
