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
