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

> **Status: milestone 0 of 11.** The reuse audit and detector adapters exist.
> There is no interception layer, no corpus and no evaluation yet, and no
> results are claimed. Headline numbers will be stated here in plain English
> once the evaluation has actually been run.

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
publishable. Point `config/models.yaml` (or the `LLMSHIELD_MODELS_ROOT`
environment variable) at a local copy. See
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

## Test

```bash
uv run pytest              # contract tests, no weights needed
uv run pytest -m models    # reuse audit, requires the local artifacts
```

## Licence

MIT. See [LICENSE](LICENSE).
