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

> **Status: milestones 0-10 of 11 done.** Interception, six detector
> adapters, a fusion/policy engine, a decontaminated 337-item corpus across
> three independent attack sources, matched-FPR calibration,
> leave-one-source-out, a latency benchmark, and this report are all built
> and run against the real weights. The full write-up is
> [`docs/REPORT.md`](docs/REPORT.md); the short version is directly below.
> Only M11 (an optional standalone stdio proxy over the same gating core)
> remains. A twelfth milestone — session-level hash correlation — was built,
> measured, found unable to detect the threat it was built for, and removed;
> the finding is kept in
> [`docs/DILUTION-BENCHMARK.md`](docs/DILUTION-BENCHMARK.md).

## Headline result

**No -- and it is not a quirk of the models being reused.** Three classifiers
were measured on the same decontaminated 337-payload corpus, through the same
matched-FPR protocol, against the same benign references:

| Detector | AUROC, realistic benign | Attacks missed at ~4% FPR |
|---|---|---|
| V0 — TF-IDF + logistic regression (reused) | **0.694** [0.648, 0.740] | 66.2% |
| V3 — DeBERTa-v3-base (reused) | 0.310 [0.262, 0.357] | 94.7% |
| `guard` — [ProtectAI v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2), purpose-built, ~840k downloads/mo | 0.524 [0.472, 0.577] | 93.8% |

The **simplest** model tested is the best one. The purpose-built production
detector is **statistically indistinguishable from a coin flip** — its 95%
confidence interval, [0.472, 0.577], contains 0.5 — and it lets 19 in 20 real
attacks through at its own calibrated operating point. Against benign text that
merely *looks* suspicious (source code containing "ignore", docs about system
prompts) both transformers fall *below* chance.

A small rule set derived from real attack data catches roughly one attack in
five, with zero false positives observed in 4,654 benign lines — which bounds
its false-positive rate below 0.082% (Wilson 95%), and is not the same claim as
"zero". The dissertation's own 19 rules, unmodified, catch zero of 187.

None of it generalises: the same detector at the same threshold misses **39% to
100%** of attacks depending purely on which of three independent real-world
attack collections is measured.

This is shipped as a **detection and audit layer with measured, poor
coverage** -- Escalate-by-default, Block structurally disabled until a real
calibration backs it -- not a guardrail that stops attacks.

**Be precise about what "Escalate" does here, because the word oversells it.**
Of the four decisions, only two change what the agent receives: Block replaces
the tool result, and Redact masks the matched spans. Allow and **Escalate both
forward the frame byte-identical** -- an Escalate is a row in the decision log
and nothing else. It is a *record that something looked wrong*, not a control
that acted on it. There is deliberately no callback, exception or review-queue
hook yet: an integration contract would invite an embedding application to
treat Allow as "checked and clean", and on this surface Allow is roughly four
out of five real attacks. See [`docs/REPORT.md`](docs/REPORT.md) section 5. See
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

## Detector artifacts

| | Model | Classes | Token limit | Available to you? |
|---|---|---|---|---|
| **V0** | TF-IDF (word 1–2 + char_wb 3–5) + logistic regression | 4 | none | No — reused, unpublishable |
| **V3** | DeBERTa-v3-base sequence classifier | 4 | 512 | No — reused, unpublishable |
| **`guard`** | [ProtectAI `deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | 2 | 512 | **Yes** — Apache-2.0, fetched from the Hub |

V0 and V3 are reused from the LLMShield dissertation and are **not retrained**;
both classify over `(benign, injection, jailbreak, harmful)`. `guard` is a
published binary `(SAFE, INJECTION)` classifier pinned by commit SHA in
`config/models.yaml`, added so that at least one measured classifier is one a
reader can rerun. See `docs/REPORT.md` section 4 for how it scored — it is
included for verifiability, not because it works.

The V0/V3 trained weights are **not distributed with this repository** and are
not publishable. `config/models.yaml` defaults to a repository-relative `models/`
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
uv run mcp-shield gauge-recut              # re-derive AUROC from scores.csv, no weights needed
```

`gauge-recut` is the falsification check for the headline, and **it needs no
model weights and no corpus** — only the committed
[`results/gauge/scores.csv`](results/gauge/scores.csv). A DeLong AUROC below 0.5
has two explanations: the detector really is anti-correlated on this surface, or
the wrong scalar is being cut out of its four-class probability vector.
`scores.csv` stores all four class probabilities precisely so the second can be
tested by anyone, and `gauge-recut` re-derives the AUROC under every score mode
from the same stored inference.

It found a real problem. V3's published below-chance figure comes from the
`injection` cut inherited from the dissertation (0.325); under `not_benign` the
same probabilities give **0.540**, an interval straddling chance. So V3 is not
reliably anti-correlated — it simply does not separate, and how badly it reads
depends on the cut. `docs/REPORT.md` section 4 carries the full table and the
correction. Run this before quoting any AUROC from that section.

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

**Gating is on by default and is independent of logging.** `--db` persists the
decision log to SQLite; without it the log is in-memory and discarded, but the
gate still runs. `--no-gate` disables interception entirely and prints a warning
saying so, because `--out` then records raw, unredacted tool output to disk.

Three policy profiles ship. **The choice cannot change any decision** —
`PolicyEngine.decide()` never reads a detector that appears only under `inert`,
so a profile changes what is scored, logged and paid for, never the
Allow/Redact/Block/Escalate outcome. A test asserts this.

| Profile | Adds | Cost / result | Runnable after a plain clone? |
|---|---|---|---|
| `config/policy.yaml` (default) | — rules + PII | 0.08 ms | Yes |
| `config/policy.guard.yaml` | `guard` | 170 ms | **Yes** (downloads ~700 MB once) |
| `config/policy.research.yaml` | `v0`, `v3`, `guard` | 345 ms | No — needs the unpublishable weights |

```bash
uv run mcp-shield run-agent --db logs/decisions.sqlite                       # default
uv run mcp-shield run-agent --policy config/policy.guard.yaml --db logs/d.sqlite
```

`policy.guard.yaml` exists because it is the only ML profile a stranger can
run: V0 and V3 need artifacts only the author has. Read
`docs/REPORT.md` section 4 before reaching for it — `guard` measured at AUROC
0.524 on this surface, and it ships `inert` for the same reason everything else
does.

Chains that feed the evaluation use the default model. For cheap smoke runs:

```bash
uv run mcp-shield run-agent --model claude-haiku-4-5 --servers filesystem
```

Each run reports and records its token usage, so the cost behind a fixture is a
measured number. Recorded fixtures store the sandbox path as a `{sandbox}`
placeholder, which keeps them portable across machines.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability, what is in
and out of scope, and an honest statement of the single-maintainer response
expectations.

## Licence

MIT for this repository's own code, tests, configuration and documentation --
see [LICENSE](LICENSE).

Every committed file is covered by it. A recorded benchmark fixture that
embedded verbatim CC BY-SA web content was removed rather than attributed, and
`tests/test_chain_licensing.py` now prevents another one being committed.
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) records that decision, the
fetched-corpus licences, and why the reused model weights are not distributed.
