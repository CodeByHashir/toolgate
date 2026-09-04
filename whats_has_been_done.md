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
