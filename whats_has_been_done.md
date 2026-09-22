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

---

## M3b — Normaliser, MCP-* rule family, and benchmarks replacing hand-written cases

Prompted by the policy audit, and by a direction to stop treating the
dissertation as a constraint: only the *models* were required to be reused.
Anything else is improvable on evidence.

### The benchmark result that reframes the project

The first audit measured rule recall at 38.1% on 21 hand-written cases. Against
real benchmarks the same rules score **0.0%**.

The hand-written cases had been authored by someone who had just read the 19
regexes, so they contained the words those regexes match. They measured the
author's assumptions. This is recorded rather than quietly corrected because it
is the kind of error that silently validates a broken detector.

Adopted sources, both MIT, fetched by `scripts/benchmark_rules.py` into
`corpus/external/` (gitignored):

* **BIPIA** (microsoft/BIPIA) — 125 attacker objectives, 25 categories.
* **InjecAgent** (uiuc-kang-lab/InjecAgent) — 62 attacker instructions.

| Rule family | BIPIA | InjecAgent | Overall | Benign FP |
|---|---|---|---|---|
| INJ-* (ported, 19) | 0.0% | 0.0% | **0.0%** | 23 (0.49%) |
| MCP-* (new, 6) | 15.2% | 30.6% | **20.3%** | **0 (0.00%)** |

The ported family contributes zero recall and every false positive. Not one of
its 19 signatures appears in 187 real indirect injections, because indirect
injection does not need to override a system prompt — the content is already in
context, so a plain imperative suffices.

The reused classifiers are barely better: at 5% FPR, V0 reaches 10.7%, V3
4.3% under `injection` and 0.5% under `not_benign`.

### What changed

- `src/llmshield_mcp/detectors/normalise.py` — `normalise()`, `Normalised`,
  `scan_normalised()`. Ports LLMShield's pipeline step 1, missed in M3.
- `config/rules.yaml` — schema version 2. Adds a `family` key; `INJ-*` marked
  frozen, six `MCP-*` rules added.
- `src/llmshield_mcp/detectors/rules.py` — `Rule.family`, and
  `load_rules(families=...)` / `RuleDetector(families=...)` so each family can
  be enabled and measured alone.
- `scripts/benchmark_rules.py` — reproducible fetch-and-measure.
- `tests/test_detector_normalise.py` (22 tests); rule tests extended to 27.
- `docs/POLICY-AUDIT.md` — sections 2 and 3 rewritten with benchmark numbers.
- `.gitignore` — `corpus/external/`.

### Design decisions

**Spans and the dual scan.** Normalisation changes offsets, so a span found in
normalised text does not point at the same characters in the original.
Redacting with it would silently corrupt a tool result. `scan_normalised` scans
both forms, takes the higher score, keeps spans only from the original, and
sets `detail["normalisation_only"]` when the canonical pass found something the
original did not — telling the policy engine a detection exists that cannot be
precisely redacted, so it is a Block rather than a Redact.

**Base64 is appended, not substituted**, so following offsets stay valid and
the encoded form survives as evidence. Capped at 4,096 decoded characters
(SEC-2).

**MCP-* rules are derived, not invented.** Candidates came from discriminative
phrase analysis over the benchmarks against ~5,000 benign repository lines.
Candidates with no measured support were dropped, and a "tool invocation
directive" candidate was rejected for 0% recall at 0.30% false positives.

Benchmark artefacts were deliberately excluded. The strongest raw n-grams were
`amy watson` and `gmail com` (InjecAgent's fixed attacker identity) and
`example com` (BIPIA's placeholder domain); matching those would have scored
near-perfectly on the benchmark and detected nothing real.

**INJ-* stays frozen** at 19 rules, guarded by a test. It is the comparability
baseline, and its 0.0% is the finding — not a bug to patch away.

### Verification

| Check | Result |
|---|---|
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check` | Clean |
| `uv run mypy` | Success, 19 source files |
| `uv run pytest` | **194 passed** (25 new) |
| `uv run python scripts/benchmark_rules.py` | Table above, reproducible |

### Known limitations

- Benchmarks supply the *injected instruction*, not the composed document a
  gate sees. Embedding it in a host result is harder, so these are upper bounds.
- No decontamination yet (M6), no confidence intervals (M7), benign reference
  sets are ad hoc.
- `MCP-*` recall differs sharply by source (15.2% vs 30.6%), so it does not
  generalise across attack families. That is what FR-12 exists to measure.
- The normaliser is available but **not yet wired into the gate**; like the
  detectors, it waits on fusion in M4.
- Homoglyph coverage is a 25-character table, not the full Unicode confusables
  set.

---

## M4 — Fusion and policy engine

Wires the rules and PII detectors (M3/M3b) into the gate for the first time,
via a new fusion/policy layer. V0 and V3 stay out of the live path -- that is
M5's job (`plan.md` milestone table); M4's scope is exactly what M3/M3b
already ported.

### What changed

- `config/policy.yaml` -- new versioned policy file (FR-9). `calibrated:
  false`, `on_detector_failure: escalate`, detector-role groupings
  (`injection: [rules_mcp]`, `redaction: [pii]`, `inert: [rules_inj]`),
  per-detector per-action thresholds, and `gate.max_result_chars` (moved here
  from the `--max-result-chars` CLI flag, per the comment left in `cli.py` at
  M2).
- `src/llmshield_mcp/gating/policy.py` -- `PolicyConfig`, `load_policy_config()`,
  `FusionOutcome`, `PolicyEngine.decide()`. Pure function: a
  `dict[str, DetectorResult]` in, one `FusionOutcome` out, no I/O.
- `src/llmshield_mcp/gating/content.py` -- `_walk_blocks()` (shared by
  `extract()` and the new `apply_redaction()`), `apply_redaction()` (FR-5),
  `build_block_result()` / `BLOCK_MESSAGE` (FR-6).
- `src/llmshield_mcp/gating/transport.py` -- `default_detectors()` (two
  `RuleDetector` instances, `families={"mcp"}` and `families={"inj"}`, plus
  `PiiDetector`). `Gate.__init__` gained `policy` and `detectors` parameters
  (both optional; default `Gate()` now runs real detection). `observe_inbound`
  runs every configured detector through `scan_normalised()`, calls
  `PolicyEngine.decide()`, and returns the (possibly rewritten) frame instead
  of a bare `None`.
- `tests/test_gating_policy.py` (23 tests) -- table-driven `PolicyEngine.decide`
  cases, SEC-6 fail-closed cases, and the FR-9 proof (`config/policy.yaml`
  threshold changed in a temp file, same code, decision flips).
- `tests/test_golden_set.py` + `tests/fixtures/golden_set.json` -- the M4
  golden-set regression test: five frozen texts run through the real detector
  set and the shipped policy file, decisions pinned.
- `tests/test_gating_transport.py`, `tests/test_gating_content.py` -- extended
  for the M4 behaviour (see below).
- `src/llmshield_mcp/cli.py` -- `--max-result-chars` default changed to `None`
  (meaning "use the policy file"); still overrides it when passed explicitly.

### Design decisions

**Escalate is the default action on detection, not Block** (plan.md 2.15,
carried into `PolicyEngine._injection_signal`): an `rules_mcp` hit alone
produces `ESCALATE`. `BLOCK` additionally requires `calibrated: true` *and*
`detail["normalisation_only"] == 1.0` (the case `detectors/normalise.py`
flags as "found only after canonicalisation, cannot be redacted precisely").
Severity-aware refinement of that condition is left to M7 calibration
(`docs/POLICY-AUDIT.md` recommendation 4) rather than assumed now -- it would
be unreachable and untestable-for-real while `calibrated: false` anyway.

**`calibrated: false` is a hard ceiling, enforced once.**
`PolicyEngine._ceiling()` downgrades any `BLOCK` to `ESCALATE` whenever the
policy is uncalibrated, regardless of which branch produced it (a fired
detector or `on_detector_failure: block`). `test_block_is_downgraded_to_escalate_while_uncalibrated`
and `test_on_detector_failure_block_is_also_downgraded_while_uncalibrated`
both exercise this. FR-11 requires matched-FPR calibration on this surface
before Block is safe to ship live.

**Decision-label precedence is BLOCK > ESCALATE > REDACT > ALLOW, and PII
redaction is independent of which label wins.** A result can be logged
`ESCALATE` while its PII spans are still masked in the content actually
forwarded (`FusionOutcome.redacted`/`redact_spans` are separate fields from
`decision`). `test_mcp_rule_hit_escalates_and_still_masks_the_pii_span`
exercises the combined case directly: MCP-006 (exfiltration destination) and
a PII email in the same text. Full rationale in `plan.md` 2.17.

**Redaction has to survive multi-block results.** `extract()` joins every
text-contributing content block with `"\n"` before detection, so a `Span`'s
offset is only meaningful against that joined string, not the original
per-block JSON. `_walk_blocks()` is now the one routine both `extract()` and
`apply_redaction()` use to find block boundaries, so they cannot disagree
about where a block starts.
`test_apply_redaction_targets_only_the_block_the_span_falls_in` is the
regression guard for that offset arithmetic.

**Two `RuleDetector` instances, not one.** `RuleDetector.name` is a fixed
`"rules"` for both the `INJ-*` and `MCP-*` families, so the gate -- not the
detector -- assigns the keys `rules_mcp` / `rules_inj` used everywhere else
(policy config, `detector_scores` in the audit log). This kept `rules.py`
and `rules.yaml` completely untouched, which matters because `INJ-*` is
frozen and guarded by its own test (M3b).

**Frame rewriting is new, and deliberately narrow.** M2's stream wrappers
always forwarded the exact object they received; `observe_inbound` now
returns a different `SessionMessage` (built via `payload.model_copy()` +
`dataclasses.replace()`) whenever the fused decision is `BLOCK` or produces a
non-empty `redact_spans`. For `ALLOW`/`ESCALATE` the identity guarantee is
unchanged --
`test_read_wrapper_forwards_the_identical_object` still asserts `is message`
on ordinary benign text, and the new
`test_redact_returns_a_new_object_and_leaves_the_original_untouched` pins the
opposite case.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **224 passed**, 7 deselected (30 new) |
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check src tests scripts` | 36 files already formatted |
| `uv run mypy` | Success, 20 source files |

### Known limitations

- V0 and V3 are not in `detectors.injection` yet -- M5 wires them in and the
  same `PolicyEngine` machinery (thresholds already keyed generically, not
  rules-specific) is what will carry their graded scores.
- `BLOCK` cannot be reached through the shipped `config/policy.yaml`
  (`calibrated: false` by design) or through the real rule set today, since no
  `MCP-*` rule is currently written to set `normalisation_only` on its own --
  that detail comes from `scan_normalised`'s canonical-form comparison, not
  from a rule. The BLOCK path is therefore only exercised in tests via a fake
  detector (`_FixedDetector`) and a hand-built calibrated `PolicyConfig`.
  Real BLOCK reachability is an M7 calibration question.
- Only PII's own spans are ever redacted; `rules_mcp`'s matched spans exist
  (FR-5's span machinery is generic) but are not redaction candidates in M4 --
  2.15 assigns rules to Escalate/Block, not Redact.
- The golden-set fixture (`tests/fixtures/golden_set.json`) has five cases.
  It is a wiring regression guard, not a recall measurement -- recall claims
  still come only from `scripts/benchmark_rules.py` against BIPIA/InjecAgent.

---

## M5 — V0 and V3 wired into the live gating path

Runs the two reused classifiers against every intercepted tool result for the
first time. They ship **inert** (scored, logged, zero decision weight) in
`config/policy.yaml`, not weighted into `injection` -- promoting them on
today's uncalibrated numbers would repeat the exact ML-circuit-breaker mistake
`docs/POLICY-AUDIT.md` section 4.1 already measured, just relabelled from
Block to Escalate-spam. Full rationale in `plan.md` 2.18.

### What changed

- `src/llmshield_mcp/gating/transport.py` -- `default_detectors()` replaced by
  `build_detectors(config: PolicyConfig)`: a small factory registry
  (`rules_mcp`, `rules_inj`, `pii`, `v0`, `v3`) that constructs exactly the
  union of keys a `PolicyConfig`'s three role sets actually name. `_build_v0`/
  `_build_v3` import `V0LexicalDetector`/`V3TransformerDetector` and call
  `load_models_config()` lazily, inside the factory -- nothing pays for torch,
  transformers or a joblib load unless a policy file actually names "v0" or
  "v3" in a role.
- `config/policy.yaml` -- `detectors.inert` gained `v0` and `v3`, with a
  comment recording the specific ad-hoc threshold docs/POLICY-AUDIT.md section
  3 measured (`v0: {escalate: 0.94}` for roughly its 5.3%-recall-at-1%-FPR
  point) as a documented ablation starting point, not a live setting.
- `tests/conftest.py` -- new. `light_detectors` fixture: the decision-relevant,
  weight-free set (rules_mcp, rules_inj, pii), used by the bulk of the gating
  test suite so it stays independent of the reused (unpublished, CI-absent)
  LLMShield weights.
- `tests/test_gating_transport_with_models.py` -- new, `models`-marked (like
  `tests/test_adapters_with_models.py`). Proves, against the real weights:
  the shipped policy builds V0/V3 as inert; their real scores reach both an
  in-memory `PolicyEngine.decide` call and a real `Gate`'s audit log; the
  shipped policy does not escalate on benign-but-trigger-word-bearing text
  that scores V0 highly; and promoting `v0` to `injection` via a YAML file
  alone -- no code change -- escalates that same real detector on that same
  text. That last pair is the milestone's own verification bar, "ablation by
  config alone," proven with a real graded detector rather than only the
  binary rules.
- `tests/test_gating_transport.py`, `tests/test_golden_set.py`,
  `tests/test_gating_policy.py` -- updated to use `light_detectors` (or the
  updated `inert_detectors` set) instead of the removed `default_detectors()`.

### Design decisions

**Ablation is genuinely config-only, including the constructor cost.**
`build_detectors` does not construct-then-discard an unused V0/V3; it never
imports `v0_lexical`/`v3_transformer` at all unless a role names them. A
policy file that doesn't mention "v0"/"v3" costs nothing extra -- important
given V3's measured ~180-220ms single-window / ~5300ms chunked CPU latency
(`docs/M0-OBSERVATIONS.md`), which the rest of the system should not pay for
until M9 says it should.

**Weight-dependent tests are opt-in, not incidental.** Before M5, no ordinary
`Gate()` construction needed model weights. Making V0/V3 part of the shipped
inert set would have made that untrue for most of the existing suite by
accident. `tests/conftest.py`'s `light_detectors` fixture keeps that
invariant explicit and provable (inert detectors are provably inert to
`PolicyEngine.decide`, so substituting them changes no test's expected
outcome) rather than quietly making 224 tests need a private, unpublished
artifact.

**Verified with the real artifacts, not just asserted.** `LLMSHIELD_MODELS_ROOT`
(already a supported override in `config.py`, see M0/M1 finalisation) was
pointed at the author's local LLMShield checkout for this milestone's
verification; the artifacts are not vendored into this repository or this
worktree (`models/` is gitignored and absent here by default) but are
reachable at `<LLMShield checkout>\evaluation\experiment2\models`.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **224 passed**, 12 deselected |
| `LLMSHIELD_MODELS_ROOT=... uv run pytest -m models` | **12 passed** (5 new), 224 deselected |
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check src tests scripts` | 38 files already formatted |
| `uv run mypy` | Success, 20 source files |

### Known limitations

- V0/V3's only thresholds anywhere are the ad-hoc percentile numbers in
  `docs/POLICY-AUDIT.md` section 3, recorded as a comment for a future
  ablation run, not applied. Real promotion to `injection` is an M7
  calibration decision.
- `build_detectors` raises if a policy role names a key with no registered
  factory. There is no test corpus of "policy files with typos" yet -- the
  existing `load_policy_config` validation catches structural errors (bad
  YAML shape, out-of-range thresholds); an unknown detector *name* inside an
  otherwise well-formed role list is caught one layer later, at `Gate`
  construction, not at `load_policy_config` time.
- The new `models`-marked test file duplicates two small JSON-RPC frame
  helpers from `tests/test_gating_transport.py` rather than importing them
  (they are underscore-prefixed there). Small, deliberate duplication over a
  cross-test-module import of private helpers.

---

## M6 — Corpus schema, ingest CLI, MinHash decontamination

Builds the payload corpus infrastructure (FR-10, AC-6): a schema, a CLI that
fetches/labels/decontaminates/stores items, and MinHash decontamination
against V0/V3's own training data. Scope deliberately excludes the
"MCP-specific dilution corpus" (embedding payloads in benign carrier text at
varying ratios, `prd.md` 9.3) -- confirmed with the user before implementation
as out of scope for this milestone's stated verification bar; see `plan.md`
2.19.

### What changed

- `config/decontamination.yaml` -- new. `shingle_size: 5`, `num_perm: 64`,
  `jaccard_threshold: 0.85` (all three straight from `exp2_data.py`'s own
  calibration), `training_corpus_path` (default `corpus/reference/train.jsonl`,
  gitignored, `LLMSHIELD_TRAINING_CORPUS` override -- same pattern as
  `config/models.yaml`'s `LLMSHIELD_MODELS_ROOT`).
- `src/llmshield_mcp/corpus/sources.py` -- `fetch()`, `load_adversarial()`,
  `load_benign()`, moved here from `scripts/benchmark_rules.py` verbatim, now
  that `corpus-ingest` needs the same loaders. `scripts/benchmark_rules.py`
  imports them instead of defining its own copy.
- `src/llmshield_mcp/corpus/decontaminate.py` -- `_norm`, `_shingles`,
  `_minhash` (5-char shingles over NFKC-normalised, casefolded text),
  `DecontaminationConfig`/`load_decontamination_config()`,
  `ContaminationResult`/`decontaminate()`. Uses `datasketch.MinHash`/
  `MinHashLSH`, not `exp2_data.py`'s hand-rolled numpy version.
- `src/llmshield_mcp/corpus/store.py` -- `PayloadCorpusItem`, `CorpusLabel`,
  `DecontaminationStatus`, `CorpusStore` (SQLite, schema per `PROPOSAL.md`
  section 12), `export_jsonl()`.
- `src/llmshield_mcp/cli.py` -- new `corpus-ingest` subcommand:
  `ingest_corpus()` fetches, labels (adversarial from BIPIA/InjecAgent, benign
  from this repository's own content), decontaminates both labels against the
  training-data reference corpus, stores every item (clean and contaminated),
  prints a drop-count report, and exports a JSONL snapshot.
- `tests/test_corpus_decontaminate.py` (13 tests), `tests/test_corpus_store.py`
  (7), `tests/test_corpus_sources.py` (2) -- all run without network or model
  weights; `test_corpus_decontaminate.py` is the test PROPOSAL.md section 9
  names explicitly ("no near-duplicate above the similarity threshold survives
  decontamination").
- `pyproject.toml` -- `datasketch.*` added to the mypy untyped-third-party
  override list (already pinned as a dependency since M0; now actually used).

### Sources read before writing anything

`evaluation/experiment2/exp2_data.py` and `exp2_lobo.py` in the LLMShield
repository (read-only reference; nothing written there). Found, rather than
assumed: the "existing MinHash decontamination method" `PROPOSAL.md` refers to
is real and already calibrated (5-char shingles, 64 permutations, Jaccard
>= 0.85 or exact match), and `evaluation/experiment2/data/train.jsonl`
(19,026 rows) is the actual decontaminated set V0/V3 were trained on -- the
natural reference corpus, not something to reconstruct from raw HuggingFace
dataset names.

### Design decisions

**`datasketch.MinHashLSH`, not a ported reimplementation.** Already pinned in
`pyproject.toml` for this exact purpose and unused since M0. Follows the same
principle M7 states for statistics (established libraries over hand-rolled
code solving the same problem) and turned out to fix a reproducibility gap:
`exp2_data.py` hashes shingles with Python's `hash()`, randomised per process,
which would make a stored `minhash_signature` incomparable across separate
`corpus ingest` invocations. `datasketch`'s default `hashfunc` (SHA1-based) is
deterministic across processes -- confirmed directly by running the same hash
twice in separate process invocations, not assumed from documentation.

**The reference corpus is gitignored, matching V0/V3's own weights.**
`corpus/reference/` joins `models/` in `.gitignore`. Neither this project nor
the author has redistribution rights over eight mixed-license public datasets
merged into one file.

**Contaminated items are flagged, never deleted.** The store's whole point is
different from `DecisionLog`'s: it holds actual corpus text (a project
deliverable, per AC-6/AC-7) rather than hashing it away, and the milestone's
drop-count report needs dropped items still queryable.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **244 passed**, 12 deselected (20 new) |
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check src tests scripts` | Clean |
| `uv run mypy` | Success, 24 source files |
| `mcp-shield corpus-ingest` against the real `train.jsonl` | 187 adversarial + 6,617 benign lines ingested, **0 contaminated** (expected -- M3b already established BIPIA/InjecAgent share no lineage with V0/V3's training sources) |

### Known limitations

- The "MCP-specific dilution corpus" (prd.md 9.3, a real third source family
  for M8) is not built. `plan.md` open question Q3 stays open for this.
- The exported JSONL snapshot from the verification run was not committed --
  publishing a specific corpus snapshot is left as a deliberate operator
  decision, not something this milestone's commit makes unasked.
- Benign items are ingested at line granularity (`load_benign()`, unchanged
  from `scripts/benchmark_rules.py`); adversarial items are whole attacker
  instructions. `docs/POLICY-AUDIT.md` section 3 already documents the
  resulting length mismatch (median 65 vs 106 characters) as a caveat on any
  recall comparison -- inherited here, not solved.
- `CorpusStore.count()`/row queries are unindexed beyond the three columns in
  `SCHEMA`; fine at "low hundreds to low thousands" of rows, not something to
  scale past without revisiting.

---

## M7 — GAUGE harness: statistics, calibration, and a real calibration run

Builds the statistics and matched-FPR calibration machinery FR-11/NFR-6/NFR-7
require, and runs it against the real V0/V3 weights and the real M6 corpus.
Does not edit `config/policy.yaml` -- see "Design decisions" below.

### A milestone-table correction, found by reading the file

The M7 row said "port LOBO and DeLong". `evaluation/experiment2/exp2_lobo.py`
turned out to **retrain** V0/V1 per fold to test whether retraining changes
generalisation -- this project never retrains anything, so that script is not
portable for M7 or M8. `plan.md` section 2.20 records the correction; M8's
leave-one-source-out test (FR-12) will build its own, much simpler,
no-retraining source-holdout check on top of this milestone's calibration
code instead.

### What changed

- `src/llmshield_mcp/gauge/stats.py` -- `wilson_ci()`/`clopper_pearson_ci()`
  (thin `statsmodels.stats.proportion.proportion_confint` wrappers, methods
  `"wilson"`/`"beta"`), `mcnemar_test()` (`statsmodels.stats.contingency_tables.mcnemar`),
  `auroc_delong()` (ported from `exp2_auroc_delong.py`'s pure-Python midrank
  DeLong implementation -- the one dissertation statistic confirmed correct
  rather than replaced).
- `src/llmshield_mcp/gauge/calibrate.py` -- `threshold_at_fpr()`, porting
  `exp2_multi_fpr.py`/`exp2_eval.py`'s thresholding *convention* (achieved FPR
  always `<= target`; a constant-scored detector is flagged `unreachable`
  rather than given a fake threshold), not their code.
- `src/llmshield_mcp/gauge/references.py` -- `partition_benign_references()`:
  splits M6's benign pool into PROPOSAL.md section 8.2's two references
  (realistic / adversarial-styled) via a keyword filter over already-real
  content, independent of `config/rules.yaml`'s actual patterns.
- `src/llmshield_mcp/gauge/run.py` -- `run_gauge()`: loads the clean corpus,
  samples/splits the dual benign references, calibrates V0 and V3 at each of
  `config/policy.yaml`'s `fpr_budget` values, computes ASR by threat type
  (Wilson + Clopper-Pearson) and DeLong AUROC, writes `scores.csv` (`plan.md`
  section 2.6's per-item/per-detector reproducibility file) and a
  `calibration_report.json`.
- `src/llmshield_mcp/cli.py` -- new `gauge-run` subcommand.
- `tests/test_gauge_stats.py` (11), `tests/test_gauge_calibrate.py` (8),
  `tests/test_gauge_references.py` (7) -- weight-free. `tests/test_gauge_run_with_models.py`
  (4, `models`-marked) -- the real end-to-end run, against a small synthetic
  corpus for speed.
- `pyproject.toml` -- `statsmodels.*` added to the mypy untyped-third-party
  override list (already pinned since M0; now actually used).

### Design decisions

**DeLong is ported; Wilson/Clopper-Pearson/McNemar are not.** Both hand-rolled
dissertation versions (`evaluation/metrics.py` and `exp2_eval.py`) fail
`PROPOSAL.md` section 9's "established library implementations" requirement.
`statsmodels` was already pinned and unused for exactly this. DeLong has no
ready library implementation, so the one dissertation file confirmed correct
by direct inspection is ported, with its point estimate cross-checked against
`sklearn.metrics.roc_auc_score` in a test rather than trusted from the source
docstring alone.

**The harness never edits `config/policy.yaml`.** `gauge-run` prints and
writes a report; `calibrated: true` and moving V0/V3 out of `inert` remain a
deliberate, human-reviewed edit, exactly as the file's own comment already
says. Automating that edit would turn a measurement tool into a
policy-changing one.

**The second benign reference is a filter, not new writing.** M3b's audit
found hand-written adversarial cases measure the author's assumptions, not
real capability. `gauge/references.py`'s "adversarial-styled" split mines
already-real M6 content for detector-relevant vocabulary (word-boundary
matched, so "evaluate" doesn't trip on "eval") -- it does not invent what an
attacker would say, so it does not repeat that mistake.

**Benign items are sampled, not scored in full.** V3's ~180-220ms/window
latency (`docs/M0-OBSERVATIONS.md`) against ~7,500 ingested benign lines would
take tens of minutes per run. `DEFAULT_BENIGN_SAMPLE_SIZE = 300` (fixed seed)
keeps a run in the low hundreds per reference, matching `prd.md`'s own
corpus-scale target, and reproducible.

### A real finding

Running `gauge-run` against the full ingested corpus (187 adversarial items,
300-item benign samples per reference, real V0/V3 weights) gave:

| Detector | Reference | AUROC (DeLong 95% CI) |
|---|---|---|
| V0 | realistic | 0.616 [0.556, 0.676] |
| V0 | adversarial-styled | 0.436 [0.369, 0.504] |
| V3 | realistic | 0.330 [0.272, 0.388] |
| V3 | adversarial-styled | 0.239 [0.187, 0.292] |

V3 (`injection` score mode) separates real MCP-surface attacks from ordinary
benign content **worse than chance** on both references. Consistent with
every prior measurement since M0 that these detectors do not transfer
cleanly to this surface -- carried forward as data for the eventual report,
not smoothed over.

**Also observed:** at this run's calibration sample size (~150 items per
reference), the `block` (0.1%) and `redact` (1%) FPR budgets calibrated to
the *identical* threshold for V0 on the realistic reference.
`threshold_at_fpr`'s `floor(target * n)` rounds both down to the same small
integer at this scale, and the algorithm always achieves `k-1` (a deliberate
conservatism ported faithfully from `exp2_multi_fpr.py`'s convention, not a
bug) -- closely-spaced budgets only differentiate once the calibration set is
large enough. A real fix is a larger corpus (M6's scope), not a change to M7.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **270 passed**, 16 deselected (26 new) |
| `LLMSHIELD_MODELS_ROOT=... uv run pytest -m models` | **16 passed** (4 new) |
| `uv run ruff check src tests scripts` | All checks passed |
| `uv run ruff format --check src tests scripts` | Clean |
| `uv run mypy` | Success, 29 source files |
| `mcp-shield corpus-ingest` + `mcp-shield gauge-run` against real weights | Full run completed, real numbers above, `config/policy.yaml` untouched |

### Known limitations

- `config/policy.yaml` remains `calibrated: false` with V0/V3 `inert`.
  Reviewing this run's report and deciding whether/how to promote them is a
  deliberate follow-up action, not automated by this milestone.
- Calibration at "low hundreds" scale cannot cleanly separate closely-spaced
  FPR budgets (see "A real finding" above) -- a real fix needs a bigger
  corpus, tracked against M6/M8's scope, not M7's.
- M8's leave-one-source-out test still needs a third adversarial source
  family (`plan.md` open question Q3); M7 does not add one.
- `gauge/references.py`'s keyword list is a reasonable, documented net, not a
  formally validated one -- it is meant to produce a plausible hard-negative
  stress set, not a precisely calibrated category boundary.

---

## Q3 resolved — LLMail-Inject as the third adversarial source family

Closes `plan.md` open question Q3 ahead of M8: leave-one-source-out needs
>= 3 distinct adversarial source families; only BIPIA and InjecAgent existed
after M6.

### What changed

- `src/llmshield_mcp/corpus/sources.py` -- `fetch_llmail_inject()` /
  `load_llmail_inject()`, fetching `microsoft/llmail-inject-challenge` (MIT,
  HuggingFace) via the `datasets-server` REST API (plain JSON over HTTPS, no
  new dependency). Six random 100-row pages sampled per split (Phase1:
  370,724 rows; Phase2: 90,916 -- confirmed via the API's own `/size`
  endpoint), de-duplicated by normalised body text, capped at 150 items.
  Kept deliberately separate from `load_adversarial()` -- see `plan.md` 2.21
  for why.
- `src/llmshield_mcp/corpus/__init__.py` -- exports the two new functions.
- `src/llmshield_mcp/cli.py` -- `ingest_corpus()` fetches and ingests
  LLMail-Inject by default (`--no-llmail-inject` to skip, since it is 12
  network requests to a different host than BIPIA/InjecAgent).
- `tests/test_corpus_llmail_inject.py` (6) -- parsing, de-duplication and
  the sampling cap, against synthetic cached pages shaped like a real
  `datasets-server` response (confirmed against the live API before writing
  the loader, not assumed). No network call in the test itself, matching
  `fetch()`'s own untested-network-path precedent.

### Why LLMail-Inject over AgentDojo

Both are real, well-documented, MIT-licensed indirect-injection-against-agents
benchmarks (researched via web search, `plan.md` 2.21 has the full
comparison). AgentDojo is conceptually closer to this project's own
tool-result surface but ships as a live simulation framework -- ingesting it
would mean installing and running its Python package, not fetching a file.
LLMail-Inject fetches as plain JSON via HuggingFace's `datasets-server`,
dropping into the exact `fetch()`/`load_adversarial()` pattern BIPIA/InjecAgent
already use, with no new dependency.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **276 passed**, 16 deselected (6 new) |
| `uv run ruff check` / `mypy` | Clean, 29 source files |
| Live fetch against the real `datasets-server` API | 150 unique items after de-duplication, spanning scenarios `level1a`-`level3f` |
| `mcp-shield corpus-ingest` against the real training-data reference corpus | 125 + 62 + 150 = 337 adversarial items ingested, **0 contaminated** across all three families |

### Known limitations

- The `scenario` column used as `threat_type` reflects the challenge's
  defense-difficulty tiers, not an attacker-intent taxonomy (the "13
  objective categories"/"5 injection classes" reported in the paper's own
  downstream analysis are not columns in the raw export this project reads).
- A fourth family (the MCP-specific dilution corpus, `plan.md` 2.19) remains
  a candidate but is no longer blocking M8.

---

## M8 — Leave-one-source-out generalisation test

FR-12, built directly on M7's calibration machinery and the correction
already recorded in `plan.md` 2.20: this project never retrains V0/V3, so
there is no training-set-exclusion sense in which a source family can be
"held out". What M8 actually measures: does the same calibrated threshold
produce consistent recall across the three adversarial source families Q3
resolved, or not.

### What changed

- `src/llmshield_mcp/gauge/run.py` -- `_grouped_asr()` extracted (shared by
  the existing `by_threat_type` breakdown and the new `by_source` one, so
  both are the same grouping logic over a different item attribute).
  `_build_report()` now emits `by_source` inside every budget alongside
  `by_threat_type`. `run_gauge()` records `adversarial_source_families` in
  the report and warns (does not raise) if fewer than two are present --
  `by_source` needs at least two to say anything about generalisation.
- `src/llmshield_mcp/cli.py` -- `gauge_run` prints the per-family ASR table
  under each budget line, plus the family count/list up front.
- `tests/test_gauge_report.py` (2, weight-free) -- `_build_report` is pure
  post-processing over `ScoreRecord`s, so the grouping logic is fully
  testable with synthetic scores: one test confirms `by_source` separates
  two families with deliberately different recall while `by_threat_type`
  (grouping the same items together) does not; one confirms a single-family
  corpus still produces a one-entry breakdown rather than erroring.
- `tests/test_gauge_run_with_models.py` -- fixture now uses two distinct
  `source` values (`family_alpha`/`family_beta`) instead of one, and a new
  test confirms `by_source` covers both with real V0/V3 scores.

### A real finding

`gauge-run` against the full corpus (V0, `escalate` budget, `realistic`
benign reference) gave attack-success-rate of:

| Source family | ASR (Wilson 95% CI) | n |
|---|---|---|
| BIPIA | 97.6% [93.2%, 99.2%] | 125 |
| InjecAgent | 75.8% [63.8%, 84.8%] | 62 |
| LLMail-Inject | 40.0% [32.5%, 48.0%] | 150 |

The same detector, the same threshold, a ~58-point swing depending purely on
which family is measured. A report citing only the original BIPIA+InjecAgent
numbers (this project's own earlier measurements, before Q3 was resolved)
would have significantly overstated how consistently V0 fails to detect
real attacks. V3 is more uniform at the same budget (92.8%/96.8%/94.7%
across the three) but uniformly close to useless either way -- a different
failure shape, not a better one. Full numbers: `results/gauge/` (gitignored;
regenerate with `mcp-shield gauge-run`).

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **278 passed**, 17 deselected (2 new) |
| `LLMSHIELD_MODELS_ROOT=... uv run pytest -m models` | **17 passed** (1 new) |
| `uv run ruff check` / `mypy` | Clean, 29 source files |
| `mcp-shield gauge-run` against the real 337-item, 3-family corpus | Full run completed, table above, `config/policy.yaml` untouched |

### Known limitations

- `by_source` is computed at every FPR budget and every benign reference,
  same as `by_threat_type` -- no new statistical test (e.g. a formal
  cross-family significance test) compares families to each other pairwise.
  Non-overlapping Wilson CIs are visually convincing here but a McNemar-style
  paired test does not apply across families (different items, not paired
  observations); a two-independent-proportions test (Fisher's exact) would
  be the correct tool if a formal pairwise claim is needed later.
- The fourth candidate family (MCP-specific dilution corpus, `plan.md` 2.19)
  is still not built; three families were enough to produce the finding
  above.

---

## M9 — Latency benchmark: per-detector, fused, 20-call chain

FR-13, FR-14, NFR-1, NFR-2. Unlike M7/M8, this milestone's numbers are
**committed** (`docs/LATENCY-BENCHMARK.md`) -- the verification bar says so
explicitly, and latency carries none of the live-decision risk that kept the
calibration reports gitignored.

### What changed

- `src/llmshield_mcp/latency.py` -- `LatencyStats`, `summarize()`,
  `time_calls()`. Mean + p95 in ms, warmup excluded (`n_warm=10`) --
  `exp2_eval.py`'s own `latency_hf`/`latency_sklearn` convention, reused
  rather than invented.
- `scripts/benchmark_latency.py` -- per-detector and fused-pipeline latency
  against 50 items (10-warmup) sampled from the real ingested corpus.
- `chains/latency_chain.json` -- a new, committed, host-path-normalised chain
  fixture: 25 real tool calls (>= 20, FR-14) through the live fused gate
  (rules + PII + V0 + V3, real weights), recorded with
  `mcp-shield run-agent --db chains/latency_run.sqlite`. The SQLite decision
  log is not committed, matching every other `*.sqlite` in this project.
- `docs/LATENCY-BENCHMARK.md` -- the committed report: per-detector table,
  fused-pipeline number, and the chain's gate-overhead breakdown
  (fetch vs filesystem calls), each against its NFR budget.
- `tests/test_latency.py` (7, weight-free), `tests/test_latency_with_models.py`
  (1, `models`-marked sanity check that `time_calls` composes correctly with
  a real detector).

### Design decisions

**Committed, not gitignored, unlike M7/M8.** The distinction is risk, not
milestone number: a calibration report could inform a `config/policy.yaml`
edit that changes live behaviour, so those stay local until reviewed.
Latency numbers cannot do that -- there is nothing to protect by hiding them,
and the milestone's own verification bar wants them committed.

**No API key in this worktree.** `.env` is gitignored and per-worktree; only
the main checkout had one. Exported `ANTHROPIC_API_KEY` from the main
checkout's `.env` via command substitution for the one `run-agent` call that
needed it, rather than copying the file -- the key value never appeared in a
visible command string. Same class of fix as `LLMSHIELD_MODELS_ROOT`/
`LLMSHIELD_TRAINING_CORPUS` (this worktree lacking something the main
checkout has), applied to a secret instead of a large file.

**A cheap, explicit task for the chain, not the usual "realistic" one.**
M1's chains use `claude-opus-5` specifically because a stronger model
produces a more realistic, longer sequence when given an open-ended task.
Here the exact opposite was wanted: a *forced* count (fetch 16 named URLs
one at a time, then read 4 named files one at a time) to reliably clear
FR-14's 20-call floor without depending on model judgement, so
`claude-haiku-4-5` (cheaper, and perfectly adequate for following an
itemised list) was used instead and named explicitly as a deliberate choice,
not a silent reuse of the M1 default.

### A real finding

| Measurement | Result | vs budget |
|---|---|---|
| rules/PII (mean) | 0.06-0.07 ms | NFR-1 (~5ms): met |
| V0 (mean) | 2.07 ms | NFR-1: met |
| V3 (mean, short corpus text) | 208 ms | NFR-2 (100ms): missed, ~2x |
| Fused pipeline (mean) | 215 ms | NFR-2: missed, ~2x |
| Gate latency, real fetched web pages (mean / max) | 4,459 ms / **13.1 s** | far beyond NFR-2 |
| Gate latency, sandbox files (mean) | 240 ms | ~2x NFR-2 |

V3's `chunk_max` strategy scores every overlapping window of long content, so
gate latency scales with content length -- confirmed at chain scale on real,
unscripted fetched pages, not just the ~1500-token smoke probe
`docs/M0-OBSERVATIONS.md` first measured this shape on. For 9 of the 16
fetches in the recorded chain, gate latency **exceeded** the network
round-trip time that produced the content. Shipping V3 `inert` (M5)
protects the decision from an uncalibrated score; it does not save any
latency, because the detector still runs on every intercepted result
regardless of its decision weight. One fetched page's PII scanner fired for
real during this run (`fused_decision = redact`) -- a genuine detection on
live content, not a synthetic probe.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **285 passed**, 18 deselected (7 new) |
| `LLMSHIELD_MODELS_ROOT=... uv run pytest -m models` | **18 passed** (1 new) |
| `uv run ruff check` / `mypy` | Clean, 30 source files |
| `scripts/benchmark_latency.py` against the real corpus and weights | Numbers in `docs/LATENCY-BENCHMARK.md` |
| `mcp-shield run-agent` recording a real 25-call chain through the live gate | `chains/latency_chain.json` committed; gate-overhead numbers in the same report |

### Known limitations

- Both measurements are single runs, not repeated-and-averaged across
  sessions -- exact figures will vary with CPU load, model non-determinism
  (which URLs get fetched in what order/length), and network conditions for
  the live fetches. The *shape* of the finding (rules/PII/V0 trivial, V3
  dominant and length-dependent) is the reproducible part, stated as such in
  the committed report.
- The fetch server still runs in pure-Python article-extraction mode (no
  Node/NPM in this environment, noted since M1) -- extracted page length,
  and therefore V3's window count and latency, would likely differ under
  Readability.js.

---

## M10 — Report generation, README headline numbers

AC-7, PROPOSAL.md section 18. Turns M4-M9's measurements into the public
deliverable: a written report, three committed figures, and a README that
actually says what was found instead of the M0-era placeholder it had
carried through nine completed milestones.

### What changed

- `scripts/generate_report.py` -- reads `results/gauge/calibration_report.json`
  (M7/M8's output; gitignored, regenerable) and writes three plain SVG bar
  charts to `docs/figures/` (committed): ASR by source family (the
  leave-one-source-out finding), latency by component (log scale, against
  `docs/LATENCY-BENCHMARK.md`'s committed numbers), and DeLong AUROC by
  benign reference. No plotting library -- see design decisions.
- `docs/figures/asr_by_source_family.svg`, `latency_by_component.svg`,
  `auroc_by_reference.svg` -- committed, generated from the same real
  3-family GAUGE run already reported in M8's `whats_has_been_done.md`
  entry.
- `docs/REPORT.md` -- the full write-up: what the system is, the corpus,
  rule recall, GAUGE calibration/AUROC, the leave-one-source-out gap,
  latency, why the fusion/policy design follows from these numbers, and an
  explicit "what this does not claim" section (mirrors `plan.md` 2.16's
  framing, in public-facing form).
- `README.md` -- rewritten status banner (was still "milestone 0 of 11,
  no results" from M0), a new "Headline result" section stating the
  transfer-failure and generalisation-gap findings in plain English, and
  new "Build the corpus" / "Run the evaluation" sections documenting
  `corpus-ingest`, `gauge-run`, and all three benchmark/report scripts --
  none of which had been documented in the README since they were built.

### Design decisions

**No plotting library added.** Three grouped bar charts do not need one;
`scripts/generate_report.py` writes plain SVG directly (string
templating), keeping NFR-8's pinned dependency set unchanged and the
figures themselves diffable text rather than binary images.

**A specific run's numbers become the frozen, published figures.** M7/M8
kept `results/gauge/` gitignored because an inherited or stale calibration
number could invalidate a live policy decision, and its sampling varies run
to run. M10 is the deliberate point where one particular run -- the same
3-family, real-weights run M8 already reported -- gets promoted to a cited,
committed figure. The raw JSON stays local and regenerable; the curated
SVGs and prose derived from it are what ships, the same split M6 already
drew between the corpus SQLite store and its JSONL export.

### A bug worth recording

The first cut of the log-scale bar-height calculation could produce a
negative fraction for a value far below the chosen axis floor (rules/PII at
~0.06ms plotted against V3 at ~215ms on the same 1-1000ms log axis). SVG
does not render a `<rect>` with negative height -- it just doesn't appear,
no error, no exception. Three bars and their value labels vanished
silently; caught only by actually opening the generated SVG in the browser
and screenshotting it, not by reading the generation code. Fixed by
clamping the computed fraction to `[0, 1]` before converting to a pixel
position, so an out-of-range value renders as a visible sliver at the axis
boundary instead of disappearing.

### Two pre-existing bugs, fixed while already in the file

- README's status banner had said "milestone 0 of 11... no results are
  claimed" since M0, through nine subsequent completed milestones -- nothing
  enforces that a status line tracks the code, so it had simply gone stale
  and unnoticed.
- The Windows junction command example had been silently corrupted: what
  should read `C:\path\to\artifacts` contained a literal tab character and a
  literal bell character in place of two `\t`/`\a`-style backslash
  sequences that were evidently escape-processed at some point before this
  session. Invisible on a normal read; found with `cat -A`.

### Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **285 passed**, 18 deselected (no test changes this milestone) |
| `uv run ruff check` / `mypy` | Clean, 30 source files |
| `uv run python scripts/generate_report.py` against the real M8 calibration data | Three SVGs written, visually verified in-browser |

### Known limitations

- The figures are generated from one specific historical run
  (`results/gauge/calibration_report.json` as it stood after M8), not
  regenerated fresh for this milestone -- re-running `gauge-run` today would
  resample the benign reference sets (different seed state across sessions)
  and could shift the exact numbers slightly, though not the reported shape.
- `docs/REPORT.md` and the README's headline numbers will need a manual
  refresh if M7/M8 are ever re-run with different calibration budgets or a
  fourth source family; nothing regenerates them automatically.

---

## M12 Dilution Benchmark — critical research/evaluation review

**Work type:** Evaluation / research correctness, not a feature build.

**What changed:**

- `src/llmshield_mcp/dilution.py` — New file. Primitives for the dilution
  benchmark: `build_diluted_text()` (embeds payload in filler at a given ratio
  and position), `score_diluted()` (returns a `DilutionResult` dataclass),
  `build_dilution_sequence()` (interleaved benign/adversarial calls for session
  accumulator testing), `recall_at_ratio()`, `mean_score_at_ratio()`, and the
  critical `load_neutral_filler()` (screens candidate filler lines through all
  active detectors before use — see "Flaw found and fixed" below).

- `scripts/benchmark_dilution.py` — New file. Runs 187 adversarial payloads
  (BIPIA 125 + InjecAgent 62) × 4 dilution ratios × 3 positions × 3 light
  detectors (`rules_mcp`, `rules_inj`, `pii`). Also runs 4 synthetic session
  accumulator experiments and 50-item benign FP measurement. Uses
  `load_neutral_filler()` to construct the filler paragraph. Writes
  `results/dilution/dilution_results.json` (gitignored).

- `tests/test_dilution.py` — New file. 41 tests (up from 0), including 4 new
  tests for `load_neutral_filler` and the contamination regression
  (`TestLoadNeutralFiller::test_filler_does_not_inflate_recall_at_any_ratio`).

- `docs/DILUTION-BENCHMARK.md` — New file. Full research report with corrected
  numbers, documented methodology flaw and fix, separated measured results from
  synthetic session experiments, explicit statement of what M12 can and cannot
  claim.

**Flaw found and fixed (scientific integrity):**

The first run of the benchmark used `corpus.sources.load_benign()` directly for
filler, which returned lines from `CLAUDE.md` — a system-prompt file containing
imperative text such as *"provide evidence"* and *"your answer"*. At 75%
dilution ratio, the tiled filler concatenated `provide [payload-word] your answer`,
triggering MCP-002 on a payload that scored 0.0 in isolation. This inflated
`rules_mcp` recall from 20.3% to 20.7% at ratio=0.75 only — a pure
methodological artifact from contaminated filler, not a real dilution effect.

This was caught during the review, diagnosed to the specific rule match
(`provide Modify your answer`), fixed by introducing `load_neutral_filler()`,
and the corrected results show perfectly flat recall at 20.3% across all four
dilution levels. The contamination scenario is documented and regression-tested.

**Results (with verified-neutral filler):**

| Detector | isolated | 50% | 75% | 90% | FPR |
|---|---|---|---|---|---|
| `rules_mcp` | 20.3% | 20.3% | 20.3% | 20.3% | 0.0% |
| `rules_inj` | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| `pii` | 19.3% | 19.3% | 19.3% | 19.3% | 0.0% |

Score degradation at 90% dilution: 0.0000 for all three detectors.
Position (start/middle/end): no measurable effect.
Latency: rules < 0.20 ms mean, < 0.55 ms p95.

Session accumulator (M12): correctly distinguishes hash repetition with stable
score (recurrence, no divergence) from hash repetition with score drop
(recurrence + divergence). The score-divergence experiment uses synthetic scores
(not from a real detector run) and is labelled as such in the report.

**Key research claim supported:**

Rule-based and PII detectors are structurally immune to word-level dilution.
This is a consequence of their pattern-matching architecture, not a measured
security property. The M12 session accumulator adds evidence for the score-
divergence scenario (same hash, different context window → different ML score),
but only when the exact same content is processed twice in one session.

**Verification:**

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **368 passed**, 18 deselected |
| `uv run python scripts/benchmark_dilution.py` | Ran clean, results written |
| Recall flat at 0.203 across all ratios | Confirmed with corrected filler |
| Contamination regression test | Passes: fires with contaminated filler, does not fire with clean filler |


---

# Post-audit hardening pass (2026-09-22)

A full current-state audit against an external product-transformation plan,
pressure-tested through a five-advisor adversarial review. The review reversed
one of the audit's own recommendations and surfaced a defect the audit had
under-graded. Scope agreed with the user beforehand: verify the headline
finding, fix hygiene, split the policy profiles. Explicitly out of scope and
not built: multi-provider gateway, output-path inspection, agent tool-call
gating, secret detection, dashboard, and any rename.

## 1. Verified the headline finding against falsification

**What changed.** Added `src/llmshield_mcp/gauge/recut.py` (`load_rows`,
`recut`, `to_report`, `format_table`) and the `mcp-shield gauge-recut`
subcommand in `src/llmshield_mcp/cli.py` (`gauge_recut()`). It recomputes DeLong
AUROC from a saved `results/gauge/scores.csv` under every score mode, using the
four class probabilities already stored there. Needs no model weights and no
corpus.

**Why.** `docs/REPORT.md` section 4 publishes V3 at AUROC 0.32 -- below chance.
The review's strongest objection was that this is the classic signature of a
label-polarity or score-mode error and that nothing had ever tried to falsify
it. The risk was concrete: the saved V3 `config.json` carries only
`LABEL_0..LABEL_3`, so `1 = injection` lived in a training-script comment, not
in the artifact. `plan.md` 2.6 had promised since M0 that every statistic is
recomputable from `scores.csv` alone; nothing had ever read those columns back.

**Risk reduced.** The project's central published claim is no longer an
unexamined assumption.

**Remaining risk.** The `scores.csv` behind the *originally published* numbers
no longer exists (`results/` is gitignored and was not retained), so the
verification below is a re-measurement, not a re-analysis of that exact run.

**Tests / evidence.** `tests/test_gauge_recut.py`, 11 tests, including the
`AUROC(benign) == 1 - AUROC(not_benign)` identity as a self-check on the
machinery and a constructed case where a score mode moves a detector across
chance. Run against the **real reused weights**:

- `mcp-shield verify-models`: known-injection probe scores P(injection) =
  **0.998**, plain benign sentence **0.023**. Polarity is correct.
- `mcp-shield gauge-recut` on a real 487-row `scores.csv` (187 BIPIA+InjecAgent
  payloads, 150 benign per reference):

  | Reference | `injection` | `not_benign` | `jailbreak` | `harmful` | `benign` |
  |---|---|---|---|---|---|
  | realistic | 0.321 | 0.286 | 0.253 | 0.326 | 0.714 |
  | adversarial-styled | 0.248 | 0.143 | 0.299 | 0.552 | 0.857 |

  `stored` reproduced `injection` exactly (0.321) and `benign` reproduced
  `1 - not_benign` exactly, confirming the machinery. The realistic figure
  recovers the published 0.32 to three decimals on a differently-sampled run.

**Conclusion: the score-mode explanation is rejected.** `not_benign` is *worse*
(0.286) than the published cut, not better. Mean P(benign) across the 187
adversarial payloads is 0.451 -- V3 finds real attack payloads more
benign-looking than repository source and documentation. `docs/REPORT.md`
section 4 gained a subsection recording this.

## 2. Closed a silent redaction leak (the most serious defect found)

**What changed.** `src/llmshield_mcp/gating/content.py`: `apply_redaction()`
now clips each span against each contributing block and masks the overlap,
instead of requiring one block to contain the span end to end. It returns
`tuple[dict, tuple[Span, ...]]` -- the redacted copy plus every span it could
not place. `src/llmshield_mcp/gating/transport.py` records any shortfall as
`redaction incomplete: N span(s) unmasked (LABELS)` in the row's `note`.

**Why.** `extract()` joins content blocks with a newline. `PHONE_NUMBER`'s
separator class is `[-.\s]` and `US_SSN`'s is `[-\s]`; both match a newline. A
result whose blocks split as `"Call 555"` / `"123 4567"` therefore produced a
genuine PHONE_NUMBER span, a Redact decision, and an audit row stating
`redacted=1` -- while forwarding the phone number to the model completely
unmasked. Demonstrated by running it before changing anything.

**Risk reduced.** PII spanning a block boundary is masked. More importantly the
audit log can no longer assert a redaction that did not occur, which was the
worse half of the bug: it destroyed the evidence that anything went wrong.

**Remaining risk.** A straddling match now yields a placeholder in each block
it touches rather than one, which is uglier output. An unplaceable span is
reported, not fixed -- the result is still forwarded. Whether that should
escalate instead is a policy question deliberately left open rather than
decided inside a hygiene pass.

**Tests / evidence.** Four new tests in `tests/test_gating_content.py`
(cross-block masking, the same via the real `PiiDetector`, an unplaceable span
reported, non-list content) and two in `tests/test_gating_transport.py`
(nothing leaks to the agent; an incomplete redaction reaches the note). Five
existing call sites updated for the new return type.

## 3. Removed the M12 session accumulator

**What changed.** Deleted `src/llmshield_mcp/gating/session.py`,
`tests/test_session.py`, `docs/M12-SESSION-CORRELATION.md`,
`scripts/benchmark_session.py`; removed `Gate(accumulator=...)`,
`Outcome.SESSION_SUMMARY`, `DecisionLog.update_note`, the `gating/__init__.py`
exports, `dilution.build_dilution_sequence`/`SequenceCall`, and the session
experiments in `scripts/benchmark_dilution.py`.

**Why.** Three independent disqualifiers: (a) dilution changes the text and so
the sha256, so hash recurrence never fires on the threat it targeted -- the
project's own `different_dilution_levels` experiment measured
`hash_recurrence_count = 0`; (b) with deterministic detectors an identical hash
implies identical scores, making score divergence structurally unreachable
through the real path -- every divergence test hand-built `DecisionRecord`s,
and the integration test `test_note_written_when_divergence_detected` asserted
that *no* note was written; (c) it was never wired into any runtime path.
`docs/M12-SESSION-CORRELATION.md` called it "the one genuinely new threat that
session-level visibility exposes" while `docs/DILUTION-BENCHMARK.md` documented
that it could not see that threat.

**Risk reduced.** Removes a feature that would read as coverage it does not
provide, and restores append-only on the decision log -- `update_note` was the
only mutation in a store whose value is that rows do not change.

**Remaining risk.** No session-level correlation at all now. A real
implementation needs content similarity across calls (the MinHash machinery in
`corpus/decontaminate.py` already exists), which means holding content or
shingles across calls and directly contradicts SEC-1/NFR-3. That trade-off is
documented, not taken.

**Tests / evidence.** The finding is preserved in
`docs/DILUTION-BENCHMARK.md`'s new "Session-level correlation: measured, and
removed" section. `tests/test_gating_audit.py` gained
`test_the_log_exposes_no_mutation_api`, which fails if any update/delete method
is reintroduced.

## 4. Split the policy into light and research profiles

**What changed.** `config/policy.yaml` now lists only `rules_inj` under
`detectors.inert`; new `config/policy.research.yaml` adds `v0` and `v3`. New
`--policy` flag on `mcp-shield run-agent`.

**Why.** `build_detectors` constructs every key any role names, including
`inert`, so the shipped default imported torch and ran DeBERTa-v3-base on every
tool result -- 208 ms mean and 13.1 s worst case on one real web page
(`docs/REPORT.md` section 6) -- to log two scores that no decision reads. A safe
default that costs seconds per call is a default people turn off.

**Risk reduced.** The cheap configuration is now the default one. `rules_inj`
stays inert in the default (~0.06 ms) so its 0/187 transfer result keeps being
reported every run.

**Remaining risk.** Two near-duplicate YAML files that must be kept in sync;
a test asserts they differ only in `inert`.

**Tests / evidence.** `tests/test_gating_policy.py`:
`test_research_profile_differs_from_the_default_only_in_inert_detectors`,
`test_research_profile_is_still_uncalibrated`,
`test_neither_profile_lets_an_inert_detector_reach_a_decision`. Decision
behaviour is provably identical: `PolicyEngine.decide()` never reads a key that
appears only under `inert`.

## 5. Decoupled gating from logging

**What changed.** `DecisionLog(None)` opens an in-memory SQLite database and
exposes a `persistent` property; `decision_log()` accepts `None`.
`cli.run_agent` gained `gate_enabled` and `policy_path`, plus a `--no-gate`
flag. `--db` now only controls persistence.

**Why.** `gate_factory = (lambda spec: Gate(...)) if log else None` meant that
omitting `--db` disabled interception entirely -- while `--out` still wrote
every raw tool result to disk. The default mode of a security tool was "no
protection, plus a plaintext copy of your tool output".

**Risk reduced.** Gating is on by default and cannot be switched off as a side
effect of declining to keep an audit file. `--no-gate` prints a warning naming
the file that will contain unredacted output.

**Remaining risk.** In-memory rows are still built and discarded, so gating
without `--db` costs the same as with it minus disk I/O.

**Tests / evidence.** `tests/test_gating_audit.py::TestInMemoryLog`, four
tests including one asserting nothing is written to disk.

## 6. Pinned and digest-verified the evaluation corpus

**What changed.** `src/llmshield_mcp/corpus/sources.py`: `SOURCES` is now
`dict[str, Source]` carrying repo, commit SHA, path and sha256. Added
`CorpusIntegrityError`, `digest()` and `verify_cache()`; `fetch()` verifies on
download and `load_adversarial()` verifies before parsing.

**Why.** BIPIA and InjecAgent were fetched from a mutable `main` branch ref
with no commit pin and no checksum, behind a `# noqa: S310 -- pinned https`
comment that pinned the scheme rather than the content. `config/servers.yaml`
pins `@modelcontextprotocol/server-filesystem@2026.8.31` and
`mcp-server-fetch==2026.8.18` exactly, for precisely this reason; the
evaluation inputs were the one thing left floating.

**Risk reduced.** Upstream can no longer silently change what every published
recall figure measured. A locally modified cache is also caught.

**Remaining risk.** LLMail-Inject cannot be pinned this way -- it is a
paginated query against a live API with no immutable ref. Stated explicitly in
the module rather than papered over; figures from that family are weaker
evidence than BIPIA/InjecAgent ones.

**Tests / evidence.** Nine tests in `tests/test_corpus_sources.py` covering
commit-not-branch pinning, digest recording, tamper detection and error-message
contents. Verified against the real cache: all four files match their recorded
digests and `load_adversarial()` returns 187 cases, matching the published
count. Pins: BIPIA `5a48626a...`, InjecAgent `623f1bf3...`.

## 7. Restated claims to match their evidence

**What changed.**

- "20.3% recall at 0% false positives" became "0 in 4,654 benign lines, Wilson
  95% CI [0%, 0.082%]" in `README.md`, `docs/REPORT.md` and
  `docs/POLICY-AUDIT.md`.
- The dilution benchmark's `0/50` gained its Wilson upper bound of 7.14% and is
  demoted to a smoke test.
- "Escalate-by-default" is now explicit that Allow and Escalate both forward
  the frame byte-identical, so an Escalate is a log row, not an intervention
  (`README.md`, `docs/REPORT.md` section 1).

**Why.** Every other figure in this project carries a confidence interval
(NFR-7); the FPR was published as a bare point estimate. Zero observed events
bound a rate, they do not establish it. And "Escalate-by-default" reads as a
control to anyone who has not read the source.

**Risk reduced.** The two places where the documentation claimed more than the
code or the measurement supports.

**Remaining risk.** An ESCALATE integration contract was considered and
**rejected** on the review's argument: giving Escalate a callback implicitly
promises that Allow means "checked and clean", and on this surface Allow is
roughly four of five real attacks. Applications embedding this still have no
programmatic way to react to an Escalate. That is a deliberate position, not an
oversight.

## 8. Community and licensing files

**What changed.** Added `SECURITY.md` (reporting channel, in/out of scope,
explicit single-maintainer bus-factor and no-SLA statement, plus an
"if abandoned, say so" commitment) and `THIRD_PARTY_NOTICES.md`.

**Why.** `chains/latency_chain.json` is tracked, 69 KB, and embeds verbatim
excerpts of Wikipedia (CC BY-SA 4.0), MDN (CC BY-SA 2.5), W3C, IANA,
python.org, httpbin and Project Gutenberg content inside an MIT repository with
no attribution.

**Risk reduced.** Every source is now attributed with its licence.

**Remaining risk.** **Unresolved and flagged, not fixed.** Whether share-alike
obligations attach to a JSON benchmark fixture containing verbatim excerpts is
a legal question this project cannot answer, and `plan.md` section 16's own
instruction is to document and flag rather than assume. The cheap fix is
recorded (regenerate the fixture from permissively-licensed sources) and not
taken, because it would invalidate published latency figures for a reason not
yet established. **This needs a human decision.**

## 9. CI restored to green

**What changed.** Fixed 33 `ruff check` errors and 4 unformatted files.

**Why.** The two M12 commits at HEAD failed both `ruff check src tests` and
`ruff format --check src tests`, which CI runs. The last green CI run was the
M10 merge; the M12 commits were never pushed.

**Evidence.** `ruff check src tests` reports all checks passed;
`ruff format --check src tests` reports 62 files already formatted; `mypy`
reports no issues in 32 source files.

## Verification (whole pass)

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **352 passed**, 18 deselected |
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | 62 files already formatted |
| `uv run mypy` | Success, no issues in 32 source files |
| `mcp-shield verify-models` (real weights) | OK; V3 polarity confirmed |
| `mcp-shield gauge-recut` (real 487-row scores.csv) | Ran; score-mode confound rejected |
| `verify_cache()` against real corpus cache | 4/4 files match recorded digests |
| `load_adversarial()` | 187 cases, matching the published count |
| Cross-block PII leak | Reproduced before the fix, gone after |

## Not done, and why

| Item | Reason |
|---|---|
| Multi-provider LLM gateway | A different product on a premise this repository's own evidence disputes. No LLM-request path and no output path exist. |
| Output-path inspection | Same. Needs its own corpus and its own evaluation before any claim. |
| Agent tool-call gating | Out of the agreed scope for this pass. The review's view is that this is the control that *survives* the negative result -- deterministic, no classifier, and the seam already sees every `tools/call`. Strongest candidate for the next milestone. |
| Secret / API-key detection | Deferred behind its own corpus. Shipping an unmeasured detector would cost more credibility than the feature is worth. |
| ESCALATE integration contract | Rejected on argument, see section 7. |
| Rename | User decision: keep the name, fix the claims. |
| Dashboard / observability | Correctly deprioritised by the transformation plan itself. |

---

# Evaluation pass: third classifier, corrected claim, evidence committed (2026-09-22)

Ran the full GAUGE evaluation that the previous pass identified as missing, and
added a published classifier so the negative result is testable by someone other
than the author. Scope agreed with the user: use the thesis models read-only,
and if they do not perform, bring in a strong open-source model instead.

**Thesis repository was not modified.** `train.jsonl` and the V0/V3 weights were
read in place via `LLMSHIELD_TRAINING_CORPUS` and `LLMSHIELD_MODELS_ROOT`;
nothing was copied out and nothing written back. Verified afterwards: no file
under the thesis directory has a modification time inside the working window.
The Hugging Face cache for the new model lives under `HF_HOME`
(`~/.cache/huggingface`), not inside either repository.

## 1. Corpus rebuilt and decontaminated

`mcp-shield corpus-ingest` against the real 19k-row training corpus:

| Source | Items | Contaminated |
|---|---|---|
| BIPIA | 125 | 0 |
| InjecAgent | 62 | 0 |
| LLMail-Inject | 150 | 0 |
| Repository benign | 10,901 | 0 |

337 adversarial items, zero contamination — reproducing the published figure
exactly. Fetch is now digest-verified against the pinned commits added in the
previous pass.

## 2. Added `guard`, a published classifier anyone can run

**What changed.** New `src/llmshield_mcp/detectors/guard.py` (`GuardDetector`),
`GuardConfig` in `config.py`, a `guard` block in `config/models.yaml`,
registration in both detector registries (`gating/transport.py` and
`gauge/run.py`), and `guard` added to `CALIBRATABLE_DETECTORS`.

**Why.** V0/V3 are unpublishable, so no reader can check a single number this
project reports about them, and a stranger who clones the repo has no ML
detector they can run at all. `protectai/deberta-v3-base-prompt-injection-v2`
is Apache-2.0, purpose-built for prompt injection, ~840k downloads/month, and
fetchable — so its numbers are independently reproducible.

**Design decisions worth keeping.**

- Identified by `repo` + `revision`, never a local path. A path would
  reintroduce the unpublishability that makes V0/V3's numbers uncheckable.
- `revision` validated as a 40-character commit SHA at load. A branch or tag
  would let upstream silently change what a published figure measured — the
  same standard `corpus/sources.py` applies to its downloads.
- Positive class resolved from the checkpoint's own `id2label`
  (`{0: SAFE, 1: INJECTION}`), never assumed to be index 1. Direct response to
  this project's own near-miss: V3's checkpoint carries only
  `LABEL_0..LABEL_3`, so its mapping lived in a training-script comment.
- Binary, so it gets its own class rather than a flag on
  `V3TransformerDetector`: `scalar_from_proba` assumes the 4-class vector.
- Ships `inert`. Being measurable is not being trusted.

**Tests.** 14 config tests (`tests/test_config_guard.py`) covering parsing,
revision pinning, and rejection of branches/tags; 6 adapter tests
(`tests/test_guard_with_models.py`, `models` marker) covering label resolution,
the raise-on-missing-label path, windowing, and failure containment.

## 3. The result: a purpose-built production detector fails here too

Same corpus, same references, same matched-FPR protocol:

| Detector | realistic AUROC | adversarial-styled AUROC | ASR @ ~4% FPR |
|---|---|---|---|
| V0 (TF-IDF + LR, reused) | **0.723** [0.679, 0.767] | 0.536 [0.479, 0.592] | 70.6% |
| V3 (DeBERTa-v3-base, reused) | 0.356 [0.306, 0.406] | 0.257 [0.211, 0.304] | 94.7% |
| `guard` (ProtectAI v2, published) | 0.553 [0.501, 0.605] | 0.281 [0.230, 0.331] | 89.6% |

Per-source ASR at the escalate threshold, realistic reference:

| Source | V0 | V3 | `guard` |
|---|---|---|---|
| BIPIA | 98.4% | 92.8% | 97.6% |
| InjecAgent | 82.3% | 96.8% | 98.4% |
| LLMail-Inject | 42.7% | 95.3% | 79.3% |

**Findings.**

- The *simplest* model tested is the best. V0's TF-IDF + logistic regression
  beats both transformers on realistic benign content.
- `guard` is barely distinguishable from chance on realistic benign (CI starts
  at 0.501) and *below* chance on the false-positive stress reference.
- At its own calibrated escalate threshold `guard` misses ~9 in 10 attacks. Its
  Block/Redact thresholds calibrate to 1.0000 at 100% ASR: tuned for zero false
  positives it catches nothing, because its scores saturate. Ordinary Python
  source containing "ignore all previous retries" scores P(INJECTION) = 0.99999.
- Source-dependence is not model-specific: `guard` spans ~19 points across the
  three families, V0 ~56.

**Risk reduced.** The claim moves from "the detectors this author reused do not
transfer" to "an independently-trained, widely-deployed, purpose-built
classifier fails on this surface too" — which points at the surface, not at one
author's models, and which a reader can verify.

**Remaining risk.** The corpus is decontaminated against V0/V3's training data,
not `guard`'s (listed on its model card, not distributed). Contamination
inflates apparent performance, so 0.553 is best read as an upper bound — the
caveat runs in the safe direction. Also: upstream has archived the project, so
the weights are frozen.

## 4. Correction: a claim from the previous pass is withdrawn

The previous pass recorded that the below-chance V3 AUROC had survived
falsification — that re-cutting as `not_benign` made it *worse* (0.286). That
check ran on 187 BIPIA+InjecAgent payloads, without LLMail-Inject and without
decontamination. On the full 337-payload decontaminated corpus:

| V3, realistic | AUROC |
|---|---|
| `injection` (shipped cut) | 0.346 [0.30, 0.39] |
| `not_benign` | **0.540 [0.49, 0.59]** |
| `jailbreak` | 0.513 |
| `harmful` | 0.262 |

So the council's original objection was right. Corrected statement: V3 does not
separate on this surface at all; whether it reads "below chance" or "at chance"
is substantially an artefact of which scalar is cut from its probability
vector. `docs/REPORT.md` section 4 carries the correction explicitly, `plan.md`
2.25 is marked withdrawn in place, and `README.md`'s claim is rewritten.

The same tool shows the shipped cuts are not optimal for either model (V0
reaches 0.825 under `jailbreak` against its shipped 0.709). **Nothing is
promoted on that basis** — selecting a score mode by what scores best on the
evaluation set is the overfitting matched-FPR exists to prevent. Reported as
sensitivity analysis.

## 5. Evidence committed

`.gitignore` gained a deliberate exception for `results/gauge/`. Note the
mechanics: `results/*` rather than `results/`, because git does not descend into
an excluded *directory* and a negation inside one is never consulted.

Tracked: `scores.csv` (5,400 rows, 606 KB), `calibration_report.json` (609 KB),
`recut.json`. `results/dilution/` stays ignored.

This closes the gap the previous pass flagged: the `scores.csv` behind the
originally published AUROC had been discarded, making the headline
unreproducible by its own author. `mcp-shield gauge-recut` now recomputes every
statistic in report section 4 from that one committed file, with no weights and
no corpus.

## 6. Three policy profiles

| Profile | Adds | Cost/result | Runnable after a plain clone |
|---|---|---|---|
| `config/policy.yaml` | rules + PII | ~0.2 ms | Yes |
| `config/policy.guard.yaml` | `guard` | ~190 ms | **Yes** (~700 MB download once) |
| `config/policy.research.yaml` | `v0`, `v3`, `guard` | ~400 ms | No — needs unpublishable weights |

All three are provably decision-neutral; the parametrised test now asserts that
across every profile rather than two. `policy.guard.yaml` exists for one
reason: it is the only ML profile a stranger can run.

## 7. Figures

`scripts/generate_report.py` had a hardcoded `("v0", "v3")` detector list, so
the regenerated SVGs silently omitted `guard`. Replaced with
`scored_detectors(report)`, which reads the detectors the run actually
calibrated. Both figures now carry all three.

## Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **368 passed**, 24 deselected |
| `uv run pytest -m models tests/test_guard_with_models.py` | 6 passed |
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | 65 files already formatted |
| `uv run mypy` | Success, 33 source files |
| `corpus-ingest` | 337 adversarial, 0 contaminated |
| `gauge-run` | Completed; all 6 detectors scored |
| `gauge-recut` on the committed scores.csv | Reproduces section 4 with no weights |
| All three profiles load | injection/redaction identical, inert differs only |
| Guard profile end-to-end through a real `Gate` | Escalate; guard scored 0.99999 and carried zero decision weight |
| Thesis repository | No file modified |

---

# Licensing resolved by removal, and two defects it exposed (2026-09-22)

Instruction was to take the safest licensing option and make sure the problem
cannot recur. Removal, not attribution — and two unrelated silent-failure
defects surfaced while doing it.

## 1. `chains/latency_chain.json` deleted

**What changed.** The file was removed. `THIRD_PARTY_NOTICES.md` rewritten from
"here is the unresolved question" to "here is what was removed and why".
`README.md`, `docs/REPORT.md`, `docs/LATENCY-BENCHMARK.md` and
`code_summary.md` updated.

**Why.** It embedded ~5 KB excerpts each of five Wikipedia articles (CC BY-SA
4.0), an MDN page (CC BY-SA 2.5), W3C, IANA, python.org and a Project Gutenberg
text, inside an MIT repository. CC BY-SA is share-alike and incompatible with
MIT. Attribution is the standard minimum but only helps if share-alike
obligations do not attach; whether they attach to a JSON benchmark fixture
holding verbatim excerpts is a legal question this project cannot answer.
Deleting removes the question.

**Risk reduced.** No third-party content remains in any committed file. Checked
directly: `load_benign()` now returns no fetched third-party prose (the only
remaining marker hits are this project's own notices file describing the
problem).

**Cost.** Near zero, which is why removal beat attribution. No test and no
script read the file; the SQLite log its published figures came from was never
committed either. `docs/LATENCY-BENCHMARK.md` section 2's numbers stand as a
recorded measurement with a note explaining the fixture no longer ships and how
to record another. `chains/baseline.json` is retained — its only fetch is
`example.com`, an IANA reserved domain whose own text says it needs no
permission.

**Remaining risk, stated not hidden.** The content is in published git history.
`git filter-repo` plus a force push would remove it, at the cost of breaking
every existing clone and the merged PR's refs, for a few kilobytes of
encyclopedia excerpts in a benchmark fixture. Judged disproportionate and
recorded in `THIRD_PARTY_NOTICES.md` as a decision, reversible if the judgement
changes.

## 2. Defect: the recording path fed the evaluation corpus

**What changed.** New `tests/test_chain_licensing.py` (4 tests).

**Why.** Not carelessness — structure. `mcp-shield run-agent --out` records
every tool result verbatim (that is its job), and `corpus/sources.py:
load_benign()` globs `chains/*.json`, so fetched web content reached both the
committed fixture *and* the benign corpus and its JSONL export. Two licensing
exposures from one recording, neither visible in a diff.

**Risk reduced.** A committed chain may now only record `fetch` results from an
explicit allowlist of hosts carrying no redistribution restriction; recorded
bodies are additionally scanned for third-party markers; and the coupling to
`load_benign()` is asserted so the tests' relevance is documented rather than
assumed. Adding a host to the allowlist is a licensing decision that must also
be recorded in `THIRD_PARTY_NOTICES.md`.

**Remaining risk.** The allowlist covers `fetch`. A future tool returning
third-party content by another route is caught only by the marker scan, which
is necessarily incomplete.

## 3. Defect: `corpus-ingest` silently doubled the corpus

**What changed.** `ingest_corpus` refuses to run against a non-empty store,
naming the item count and both ways forward. New `--append` flag for the
deliberate case. New `tests/test_corpus_ingest_guard.py` (6 tests).

**Why.** Found by hitting it. `CorpusStore.add` is a plain INSERT with no
uniqueness constraint, so a second ingest appends. Re-running during this
cleanup took the store from 11,238 to 23,139 items — and the drop-count report
printed `clean: 23139`, which reads like a larger corpus rather than a
duplicated one. A gauge run against that store would have produced entirely
plausible, entirely wrong numbers over doubled data with nothing saying so.

**Risk reduced.** Impossible to do accidentally now. The guard runs before
`fetch()`, so it costs nothing and needs no network.

**Remaining risk.** `--append` still allows it deliberately, which is the
point.

**Worth recording about the test.** The first version monkeypatched
`corpus.sources.fetch`, which does nothing: `ingest_corpus` does
`from llmshield_mcp.corpus import fetch` and so resolves the *package*
namespace. It passed anyway — the guard fired before fetch would have run — so
a test asserting the right thing for the wrong reason nearly shipped. Target
corrected and the reasoning written into the test.

## 4. Evidence regenerated on the sanitised repository

Deleting the fixture changed `load_benign()`'s output, so the corpus and every
statistic derived from it were rebuilt from scratch rather than left stale
against changed inputs.

| | Before | After |
|---|---|---|
| Corpus items | 11,238 (one ingest) | 12,020 |
| Adversarial | 337, 0 contaminated | 337, 0 contaminated |
| Benign lines | 10,901 | 11,683 |

The benign pool grew rather than shrank: removing the fixture took ~800 lines
out, and `SECURITY.md`, `THIRD_PARTY_NOTICES.md` and the new test modules added
more back, since `load_benign()` globs the repository's own content.

**The figures moved, and the documents were updated to match.** An intermediate
draft of this entry claimed they were unchanged; that was written against a
stale `results/gauge/` (see below) and is corrected here.

| Detector | realistic AUROC, before | after | ASR before | after |
|---|---|---|---|---|
| v0 | 0.723 [0.679, 0.767] | **0.694 [0.648, 0.740]** | 70.6% | **66.2%** |
| v3 | 0.356 [0.306, 0.406] | **0.310 [0.262, 0.357]** | 94.7% | 94.7% |
| guard | 0.553 [0.501, 0.605] | **0.524 [0.472, 0.577]** | 89.6% | **93.8%** |

The material change is `guard`: its confidence interval now **contains 0.5**,
where before it started at 0.501. The honest claim strengthens from "barely
distinguishable from chance" to "not statistically distinguishable from
chance". Every document stating the old figure was updated: `README.md`,
`docs/REPORT.md` (headline, section 4 table, the score-mode table, the guard
subsection, the leave-one-source-out table), `config/policy.guard.yaml` and
`plan.md` 2.26.

`gauge-recut` on the new scores likewise shifts slightly: V3 realistic reads
0.325 under `injection` and 0.540 under `not_benign` -- the correction recorded
in 2.26 stands, and the gap between the cuts is if anything wider.

### Two process failures worth recording

**A killed background task's child process kept running.** The intermediate
ingest that doubled the corpus was stopped mid-gauge, but only the shell died;
the `uv run` child survived, finished against the doubled store, and overwrote
`results/gauge/` with a run over 674 adversarial items (2 x 337). Those numbers
were read and briefly reported as "unchanged" before the duplication was
spotted in the per-source `n` values. The output was discarded and
`results/gauge/` restored from the committed run before the clean rebuild
finished.

**Three attempts to wait on the run used file timestamps and all fired early**,
because an older artifact already satisfied the condition. The reliable signal
was the task's own completion notification plus a *content* check (337
adversarial, correct per-source counts), which is what finally confirmed the
run. Timestamps are not a completion signal when a stale file is present.

## Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | 378 passed, 24 deselected |
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | clean |
| `uv run mypy` | Success, 33 source files |
| `corpus-ingest` into a populated store | Refused, exit 1 |
| Third-party prose in `load_benign()` | None |
| Committed chains vs host allowlist | Pass |
| Corpus after clean rebuild | 12,020 items, single ingest, 0 contaminated |

---

# Capability gating of outbound tool calls (2026-09-22)

The engineering response to this project's own finding. Requested as the first
step of shaping the repository into a portfolio piece; chosen over the
"multi-provider gateway" direction because that would have been a thin
abstraction over commodity SDKs, while this is the one control the measured
result actually argues for.

## What changed

| File | Change |
|---|---|
| `src/llmshield_mcp/gating/tool_calls.py` | New. `ToolCallPolicy`, `ToolRule`, `evaluate_tool_call`, `ToolCallBlocked`, `load_tool_call_policy` |
| `src/llmshield_mcp/gating/transport.py` | `observe_outbound` now gates as well as observes; new `_judge_tool_call` |
| `src/llmshield_mcp/gating/audit.py` | New `Outcome.TOOL_CALL` |
| `src/llmshield_mcp/gating/policy.py` | `PolicyConfig.tool_calls`, parsed from a `tool_calls` block |
| `config/policy.yaml` | Documented example, deliberately not enabled |
| `config/policy.agent.yaml` | New working profile scoped to the reference servers |
| `tests/test_tool_calls.py` | New, 42 tests |
| `tests/test_gating_transport.py` | 7 new gate-level tests |
| `tests/test_gating_policy.py` | Agent-profile assertions |

## Why

Every detector here asks "does this text look like an attack?". `docs/REPORT.md`
measures that at ~20% recall at best on this surface, with a purpose-built
production classifier indistinguishable from chance. This layer asks "is the
agent allowed to do this?" instead, which needs no classifier.

**Risk reduced.** Against the behaviour a rule names there is no false-negative
rate — sandbox escape, exfiltration to a non-allowlisted host, and named
destructive operations are refused whatever prose talked the model into
attempting them.

**Remaining risk, stated plainly.** It bounds the blast radius of a successful
injection to whatever the policy still permits. An attacker who only needs a
tool the policy allows is unaffected. This narrows what a compromised agent can
reach; it does not stop the compromise.

## Design decisions worth keeping

**Enforcement is an exception, not an injected frame.** Reading the SDK settled
it: `mcp/shared/jsonrpc_dispatcher.py` registers its pending waiter before the
write and pops it in a `finally` on every path, so raising from `send()` cleans
up correctly and surfaces to `session.call_tool()`. Injecting a synthetic
JSON-RPC error would have needed a pump task and a shared queue, which
`plan.md` 2.8 rejected for reasons that still hold.

**The `calibrated: false` ceiling does not apply.** That ceiling exists because
detector thresholds are uncalibrated here; a capability rule has no threshold
and no FPR to calibrate. Applying it would silently disable the one control
that does not depend on the detection this project measured as not working.
Asserted in `test_capability_block_is_not_downgraded_by_the_calibration_ceiling`.

**Three checks, taken from the corpus.** `action`, `paths`, `egress` — each maps
to an attacker objective in the BIPIA/InjecAgent payloads. Regex on argument
*values* was deliberately excluded: it would reintroduce content inspection with
all of its false positives.

**Off by default.** The default profile defines no rules, so the full existing
suite passed untouched. `default: block` turns the config into a strict
allowlist and is one word away.

**No argument values reach the log.** Rule id and tool name only — a path or URL
argument can carry exactly what SEC-3 keeps out of the store. Two tests assert
a planted secret never appears in the verdict or the audit row.

## A bypass caught before it shipped

The first `_path_allowed` matched both the normalised path and the raw string.
`fnmatch`'s `*` matches `/`, so `workspace/../../.ssh/id_rsa` matched
`workspace/**` verbatim — the sandbox escape was allowed through, in the
function whose only purpose is to stop it. A five-line smoke test over seven
paths caught it before any wiring existed.

Fixed by matching only the normalised path, and `_normalise_path` now also
reports when a `..` climbed above its own root (`../../etc/passwd` would
otherwise normalise to `etc/passwd` and could match a permissive glob). Both
pinned as regressions.

The general lesson, recorded because it will recur: this layer's claim is "no
false negatives against the named behaviour", and that claim is worth exactly
as much as its matcher. The adversarial test cases belong in the matcher, not
in the policy vocabulary.

## Verification

| Check | Result |
|---|---|
| `uv run pytest -m "not models"` | **431 passed**, 24 deselected (was 378) |
| `uv run ruff check src tests` | All checks passed |
| `uv run ruff format --check src tests` | 69 files already formatted |
| `uv run mypy` | Success, 34 source files |
| Existing suite before any config opt-in | Passed untouched — the layer is inert by default |
| End-to-end through real `Gate`s | Sandbox escape, exfiltration and destructive call all BLOCKED; legitimate read and fetch ALLOWED; 3 audit rows, none carrying an argument value |

## Not done

No measurement of this layer against the corpus. Recall against a capability
rule is 100% by construction, so the interesting number is the **false-positive**
one: how often a legitimate agent workflow trips a reasonable policy. That needs
realistic multi-step agent traces; this project has one (`chains/baseline.json`)
and one is not a benchmark. Until that exists the README claims the guarantee in
terms of what the mechanism does, and claims no FPR.
