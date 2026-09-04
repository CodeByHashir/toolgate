# whats_has_been_done.md — Running Implementation History

Companion to `prd.md` (what to build) and `plan.md` (how, and what's left).
This file is the append-only log of what actually happened, in commit order.

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
