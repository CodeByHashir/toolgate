# LLMShield-MCP

A guardrail and evaluation layer for **indirect prompt injection delivered
through the Model Context Protocol (MCP)**.

Guardrail research, including the dissertation this work extends, has focused
on the *user prompt* surface. When an MCP-connected agent calls a tool, the
result is inserted straight into the model's context — a second injection
surface with different properties: results are longer, more heterogeneous, and
legitimately contain trigger words like "ignore" and "system" in benign
technical contexts such as source code.

This project asks whether detectors trained on user-prompt injection transfer
to that surface, and measures the answer with the same statistical rigour as
the dissertation (the GAUGE protocol).

> **Status: milestones 0-10 of 11 done.** Interception, four detector
> adapters, a fusion/policy engine, a decontaminated 337-item corpus across
> three independent attack sources, matched-FPR calibration,
> leave-one-source-out, a latency benchmark, and this report are all built
> and run against the real weights. The full write-up is
> [`docs/REPORT.md`](docs/REPORT.md); the short version is directly below.
> Only M11 (an optional standalone stdio proxy over the same gating core)
> remains.

## Headline result

**No, detectors trained on user-prompt injection do not transfer reliably to
the MCP tool-result surface -- and the failure is not even consistent.** The
reused transformer classifier (V3) separates real attacks from ordinary
benign content *worse than a coin flip* on this surface (DeLong AUROC 0.32,
chance is 0.5). A small rule set derived from real attack data catches
roughly one attack in five at zero measured false positives; the
dissertation's own 19 rules, unmodified, catch zero of 187. And whatever
signal exists does not generalise: the same detector, the same threshold,
misses **40% to 98%** of attacks depending purely on which of three
independent, real-world attack collections is being measured.

This is shipped as a **detection and audit layer with measured, poor
coverage** -- Escalate-by-default, Block structurally disabled until a real
calibration backs it -- not a guardrail that stops attacks. See
[`docs/REPORT.md`](docs/REPORT.md) for the full evidence, figures and what
this does *not* claim.

## Why this might be interesting

The reused V3 transformer has a **512-token window**. User prompts fit inside
it. Tool results routinely do not — a file read or web fetch is often 10–100×
that. An injection planted past token 512 of a long file is invisible to a
truncating detector, not because the detector is weak but because it never sees
the text. This project implements both a truncating and a chunking scorer and
reports the gap between them as a first-class result.

## Install

Requires Python 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
```

## Reused detector artifacts

Two detectors are reused from the LLMShield dissertation and are **not
retrained**:

| | Model | Classes | Token limit |
|---|---|---|---|
| **V0** | TF-IDF (word 1–2 + char_wb 3–5) + logistic regression | 4 | none |
| **V3** | DeBERTa-v3-base sequence classifier | 4 | 512 |

Both classify over `(benign, injection, jailbreak, harmful)`.

The trained weights are **not distributed with this repository** and are not
publishable. `config/models.yaml` defaults to a repository-relative `models/`
directory, which is gitignored — copy, symlink or junction your artifacts
there, or point `LLMSHIELD_MODELS_ROOT` at wherever they live:

```bash
# Windows (no admin needed)
New-Item -ItemType Junction -Path .\models -Target C:\path\to\artifacts
```

```bash
# macOS / Linux
ln -s /path/to/artifacts ./models
```

See
[docs/PINNING.md](docs/PINNING.md) for why the scikit-learn and transformers
versions are pinned exactly, and for how the statistical claims stay
independently reproducible without the weights.

## Verify the reuse audit

```bash
uv run mcp-shield verify-models
```

Loads V0 and V3 on CPU, scores a small set of probe texts, and prints per-class
probabilities and latency. The final rows contrast the `truncate` and
`chunk_max` strategies on an over-length input, which is the clearest
demonstration of the 512-token problem.

Probe texts are a smoke test, not an evaluation. Draw no conclusions from them.

## Build the corpus

```bash
uv run mcp-shield corpus-ingest
```

Fetches three independent adversarial source families (BIPIA, InjecAgent,
LLMail-Inject; all MIT), pulls benign reference lines from this repository's
own content, decontaminates every item against the ~19,000-row corpus V0/V3
were actually trained on, and stores the result in
`corpus/payload_corpus.sqlite` (gitignored — the store is regenerable, not a
one-off you need to guard). Prints a drop-count report: how many items were
flagged as near-duplicates of training data, per source.

## Run the evaluation

```bash
uv run mcp-shield gauge-run                # calibrate V0/V3, matched-FPR ASR + AUROC
uv run python scripts/benchmark_rules.py   # rule recall vs BIPIA + InjecAgent
uv run python scripts/benchmark_latency.py # per-detector + fused latency
uv run python scripts/generate_report.py   # regenerate docs/figures/*.svg
```

`gauge-run` needs a corpus already produced by `corpus-ingest`, plus the real
reused weights (like `benchmark_latency.py`); `benchmark_rules.py` only
exercises the rule engine and needs neither. `gauge-run` never edits
`config/policy.yaml` —
reviewing its report and deciding whether to promote V0/V3 out of `inert` is
a deliberate step for a human, not something the harness does for itself.
See [`docs/REPORT.md`](docs/REPORT.md) for the numbers these produced and
[`docs/LATENCY-BENCHMARK.md`](docs/LATENCY-BENCHMARK.md) for the full
latency breakdown.

## Test

```bash
uv run pytest              # contract tests, no weights needed
uv run pytest -m models    # reuse audit, requires the local artifacts
```

## Record a tool-call chain

```bash
uv run mcp-shield run-agent --servers filesystem,fetch --out chains/baseline.json
```

Launches both reference MCP servers, drives them with a Claude tool-use loop,
and records every call and result to a JSON fixture. The evaluation then runs
offline against that recording, so API spend is a one-off rather than something
that scales with the corpus.

Chains that feed the evaluation use the default model. For cheap smoke runs:

```bash
uv run mcp-shield run-agent --model claude-haiku-4-5 --servers filesystem
```

Each run reports and records its token usage, so the cost behind a fixture is a
measured number. Recorded fixtures store the sandbox path as a `{sandbox}`
placeholder, which keeps them portable across machines.

## Licence

MIT. See [LICENSE](LICENSE).
