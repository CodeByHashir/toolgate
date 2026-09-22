# LLMShield-MCP: does prompt-injection detection transfer to the MCP tool-result surface?

This is the headline report AC-7 asks for: what was measured, what it says,
and what it does not say. Every number below traces to a script under
`scripts/` or `mcp-shield`'s own subcommands and is reproducible from the
committed corpus and code -- the reused model weights are the only
unreproducible input (`prd.md` A1), and every evaluation run emits a
per-item `scores.csv` specifically so the statistics recompute without them
(`plan.md` section 2.6).

**Headline answer: no -- and this is not a property of any one model.** Six
detectors were measured on the same decontaminated corpus through the same
protocol, three of them scored classifiers. The best separation on realistic
benign content comes from the *simplest* model tested (V0, TF-IDF + logistic
regression, AUROC 0.694). The reused transformer (V3) does not separate at all.
And a purpose-built, independently-trained, widely-deployed production
injection classifier (ProtectAI's `deberta-v3-base-prompt-injection-v2`, ~840k
downloads/month) reaches AUROC **0.524 [0.472, 0.577]** -- an interval
containing 0.5, so statistically indistinguishable from a coin flip -- while
letting **93.8%** of real attacks through at its own 4% false-positive
operating point.

Whatever partial signal exists also fails to generalise across attack sources:
the same detector at the same threshold produces attack-success rates from 39%
to 100% depending purely on which of three independent real-world attack
collections is measured.

---

## 1. What this system is

An interception layer sits at the MCP client's transport boundary and
inspects every tool result before it reaches the agent (`plan.md` 2.1). Six
detectors run against every result: a frozen 19-rule set ported from the
author's dissertation (`INJ-*`), a 6-rule set derived from real MCP-surface
attack data (`MCP-*`), a PII scanner, two reused-not-retrained classifiers
(V0, a TF-IDF+logistic-regression model; V3, a DeBERTa-v3-base transformer),
and `guard`, a published Apache-2.0 injection classifier that -- unlike V0 and
V3 -- anyone can fetch and rerun. A policy engine fuses their scores into one
of four decisions
-- Allow, Redact, Block, Escalate -- and every decision is logged.

Two of those four actually alter the frame the agent receives: Block replaces
the result, Redact masks the matched spans. **Allow and Escalate both forward
it byte-identical**, so an Escalate is an audit-log entry, not an intervention.
That is a deliberate choice rather than unfinished work: giving Escalate an
integration contract would implicitly promise that Allow means "inspected and
clean", and section 5 measures how far from true that is. The honest reading of
this system's output is "here is what was noticed", not "here is what was
stopped".

**This is a detection and audit layer with measured, poor coverage, not a
guardrail that blocks attacks** (`plan.md` 2.16). That framing is not a
disclaimer added after the fact; it is the actual finding, and the rest of
this report is the evidence for it.

## 2. The corpus

337 real adversarial items across three independent, disjoint source
families, ingested and decontaminated against V0/V3's own training data
(`mcp-shield corpus-ingest`, M6):

| Source | Items | What it is |
|---|---|---|
| [BIPIA](https://github.com/microsoft/BIPIA) | 125 | Attacker objectives across 25 categories (Microsoft, MIT) |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | 62 | Attacker instructions, direct-harm and data-stealing (MIT) |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | 150 | Sampled from 462,000 real submissions to a live adaptive prompt-injection competition (Microsoft, MIT) |

**Zero items from any of the three were flagged contaminated** against the
~19,000-row corpus V0/V3 were actually trained on -- these are genuinely
independent test data, not accidentally-recycled training examples.
Benign reference content (~7,800 lines) comes from this repository's own
real source, docs and sandbox content, split into two references PROPOSAL.md
asks for: ordinary text, and text that legitimately contains
detector-relevant vocabulary without being an attack (the false-positive
stress case -- `gauge/references.py`).

## 3. Rule recall: the ported rules do not transfer; new ones, derived from data, do a little

The dissertation's 19 rules (`INJ-*`), applied unmodified to this surface,
catch **0 of 187** real indirect-injection payloads (BIPIA + InjecAgent) and
produce every rule false positive measured. Six new rules
(`MCP-*`), derived by discriminative analysis over the same benchmarks
against ~5,000 benign lines -- never by hand-writing cases, which measures
the author's own assumptions rather than reality (`docs/POLICY-AUDIT.md`
section 2) -- reach **20.3% recall at 0 false positives in 4,654 benign lines
(Wilson 95% CI on the FPR: [0%, 0.082%])**. That interval is the honest form of
what an earlier revision of this report called "0% false positives": zero
observed events bound a rate, they do not establish it is zero, and the benign
set is repository text rather than the arbitrary web content a real tool result
carries. `INJ-*` stays
enabled and scored specifically so this zero keeps being reported every run,
not because it does anything.

## 4. Matched-FPR calibration and separation (GAUGE, M7)

V0 and V3 were calibrated against this project's own benign reference sets
at matched false-positive-rate budgets (0.1% / 1% / 5%), not against an
inherited threshold from the user-prompt surface they were trained for
(`docs/POLICY-AUDIT.md` section 4 measured why that would be unsafe: an
inherited `ml_probability >= 0.95` breaker hard-blocks 7 of 8 benign
documents on this surface).

![DeLong AUROC by benign reference](figures/auroc_by_reference.svg)

Threshold-free separation (DeLong AUROC, 95% CI) tells the same story
without needing any threshold at all:

| Detector | Realistic benign | Adversarial-styled benign |
|---|---|---|
| V0 (TF-IDF + logistic regression, reused) | 0.694 [0.648, 0.740] | 0.521 [0.466, 0.576] |
| V3 (DeBERTa-v3-base, reused) | 0.310 [0.262, 0.357] | 0.235 [0.191, 0.279] |
| `guard` (ProtectAI v2, published, Apache-2.0) | 0.524 [0.472, 0.577] | 0.255 [0.207, 0.303] |

Three things stand out, and none of them is comfortable.

**The simplest model is the best one.** V0 -- TF-IDF n-grams into a logistic
regression -- beats both transformers on realistic benign content. That is not
a result anyone hoped for.

**V3 does not separate at all.** See the score-mode analysis below: under the
cut this project inherited it reads below chance, under a fairer cut of the
same probabilities it reads as chance. Either way it is not a usable signal
here.

**Every detector collapses on the false-positive stress case.** Against benign
text that merely *looks* suspicious -- source code containing "ignore", docs
discussing system prompts -- V0 falls to 0.521 (an interval containing chance)
and both transformers fall below it. That reference is the one a detector most needs to survive,
because a real tool result is full of exactly that material.

### Is the below-chance figure real, or an artefact of the score mode?

**Partly an artefact. This section corrects an earlier claim in this report.**

An AUROC meaningfully below 0.5 deserves suspicion before it is published. It
has two explanations, and only one is a finding about the detector:

1. V3 really is anti-correlated on this surface; or
2. the wrong scalar is being cut out of its four-class probability vector.

Explanation 2 was never idle speculation here. V0 is scored `not_benign`
(1 - P(benign)) and V3 `injection` (P(injection)) -- an asymmetry inherited
from the dissertation's `exp2_eval.py` and recorded in `config/models.yaml`.
Worse, the saved V3 checkpoint's `config.json` carries only generic
`LABEL_0..LABEL_3`, so the mapping `1 = injection` lived in a comment in a
training script rather than in the artifact.

`mcp-shield gauge-recut` re-derives AUROC from the *same stored inference*
under every score mode, so any difference is attributable purely to the
projection. On the full decontaminated 337-payload corpus:

| Detector | Reference | `injection` | `not_benign` | `jailbreak` | `harmful` | `benign` |
|---|---|---|---|---|---|---|
| V3 | realistic | **0.325** | **0.540** | 0.515 | 0.258 | 0.460 |
| V0 | realistic | 0.765 | **0.704** | 0.838 | 0.249 | 0.296 |

(Bold marks each detector's shipped cut: `injection` for V3, `not_benign` for
V0.)

**The label polarity is correct** -- `mcp-shield verify-models` scores a known
injection probe at P(injection) = 0.998 and a plain benign sentence at 0.023,
so nothing is transposed. **But the cut matters a great deal.** Under
`not_benign`, V3's realistic AUROC rises from 0.325 to **0.540 [0.49, 0.59]**
-- an interval that straddles chance. The honest statement is therefore:

> V3 does not separate attacks from benign content on this surface. Under the
> score mode this project inherited from the dissertation it reads as *worse*
> than chance; under a fairer cut of the same probabilities it reads as
> *indistinguishable from* chance. "Useless here" is supported. "Reliably
> anti-correlated" is not.

An earlier revision of this report asserted the opposite -- that re-cutting
made V3 worse and the confound was therefore rejected. That check was run on
187 BIPIA+InjecAgent payloads without LLMail-Inject and without
decontamination, and it did not survive the full corpus. The claim is
withdrawn.

The same tool shows the shipped cuts are not the best available for either
model: V0 reaches 0.838 under `jailbreak` and 0.765 under `injection` against
its shipped 0.704. **No threshold is being promoted on that basis.** Choosing a
score mode after seeing which one scores best on the evaluation set is exactly
the overfitting the matched-FPR protocol exists to prevent; these columns are
reported as a sensitivity analysis, not as a tuning result.

### Does a current, purpose-built detector do better? No.

The obvious objection to everything above is that V0 and V3 are one author's
reused dissertation artifacts. Maybe they are simply weak models, and a
detector built for this job by people who do it professionally would be fine.

That objection is testable, so it was tested. `guard` is
[`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2):
Apache-2.0, purpose-built for prompt-injection detection, roughly 840,000
downloads a month, pinned here by commit SHA and run through the **identical**
GAUGE protocol on the **identical** decontaminated corpus and references.

| | Realistic AUROC | Adversarial-styled AUROC | ASR at 4% achieved FPR |
|---|---|---|---|
| `guard` | 0.524 [0.472, 0.577] | 0.255 [0.207, 0.303] | **93.8% [90.7%, 95.9%]** |

It does not do better. On realistic benign content its 95% confidence interval
**contains 0.5**, so its separation is not statistically distinguishable from a
coin flip. On the false-positive stress reference it is *below* chance, like
V3. At the escalate operating point it lets **19 in 20 real attacks through**
while still raising on 4% of benign content. Its Block and Redact thresholds calibrate to 1.0000 with a 100%
attack success rate: tuned for zero false positives it catches nothing at all,
because its scores saturate. A single benign probe makes the saturation
visible -- ordinary Python source containing the words "ignore all previous
retries" scores P(INJECTION) = 0.99999.

**One caveat, and it runs in the safe direction.** This corpus is
decontaminated against V0/V3's training data, not against `guard`'s -- its
training set is listed on its model card but not distributed, so no equivalent
check was possible. Contamination inflates apparent performance, so 0.524 is
best read as an *upper* bound. A negative result that might be flattered by
contamination is stronger than one that might be depressed by it.

Two limitations its own model card states are worth repeating, because both
land squarely on this surface: it does not detect jailbreak attacks, and its
authors do not recommend it on system-prompt-like text because it produces
false positives. The project has also been archived upstream, so these weights
are frozen.

**What this changes.** The finding is no longer "the detectors this author
reused do not transfer". It is that a widely-deployed, purpose-built,
independently-trained production classifier fails on the MCP tool-result
surface too -- which points at the surface rather than at any one model. That
is a claim a reader can check: unlike V0 and V3, `guard` is fetchable by
anyone, so every number in this section is independently reproducible.

`guard` ships `inert` like every other classifier here. Scoring poorly is not
why; scoring *at all* is not grounds for being trusted, and promotion to a
decision-carrying role still requires a calibration this data does not support.

## 5. Leave-one-source-out: the generalisation gap (FR-12, M8)

The dissertation's own leave-one-out protocol retrains a classifier with and
without each benchmark family. This project never retrains V0/V3
(`plan.md` 2.20), so the meaningful question here is narrower: does the
*same* calibrated threshold produce consistent recall across independent
attack sources, or not?

![Attack success rate by source family](figures/asr_by_source_family.svg)

At the escalate budget (5% target FPR, realistic benign reference), attack
success rate (Wilson 95% CI) -- the same detector, the same threshold,
against three genuinely disjoint real-world sources:

| Source | V0 ASR | V3 ASR | `guard` ASR |
|---|---|---|---|
| BIPIA | 96.8% [92.1%, 98.7%] | 92.8% [86.9%, 96.2%] | 97.6% [93.2%, 99.2%] |
| InjecAgent | 71.0% [58.7%, 80.8%] | 96.8% [89.0%, 99.1%] | 100.0% [94.2%, 100.0%] |
| LLMail-Inject | 38.7% [31.2%, 46.7%] | 95.3% [90.7%, 97.7%] | 88.0% [81.8%, 92.3%] |
| **Overall** | **66.2% [61.0%, 71.0%]** | **94.7% [91.7%, 96.6%]** | **93.8% [90.7%, 95.9%]** |

V0's failure rate swings by **~58 percentage points** depending purely on
which source is measured. A report built from only the first two families
(this project's own state before Q3 was resolved, `plan.md` 2.21) would have
significantly overstated how consistently V0 fails -- and would have missed
that it fails *least* on the family most like a live, adaptive attacker
(LLMail-Inject: real human submissions against real live defenses). V3 is
more uniform (93-97% ASR across all three) but uniformly close to useless
either way -- a different failure shape, not a better one.

`guard` shows the same source-dependence as V0 in direction, if not in degree:
98-100% ASR on BIPIA and InjecAgent against 88.0% on LLMail-Inject, a ~12-point
spread. So the generalisation gap is not an artefact of one model's training
data either. **Whichever detector you pick, the number you would quote depends
heavily on which benchmark you happened to evaluate against** -- which is the
most portable finding in this report, and the reason every figure here carries
a source breakdown rather than a single headline percentage.

## 6. Latency (FR-13, FR-14, M9)

![Per-call latency by component](figures/latency_by_component.svg)

| Component | Mean | vs budget |
|---|---|---|
| `rules_mcp` / `rules_inj` / `pii` | 0.02-0.03 ms | NFR-1 (~5ms): met |
| V0 | 2.24 ms | NFR-1: met |
| V3 | 172.52 ms | NFR-2 (100ms): missed, ~1.7x |
| `guard` | 169.92 ms | NFR-2: missed, ~1.7x |
| Fused pipeline (all six) | 313.97 ms | NFR-2: missed, ~3x |

Lexical detection is effectively free; the transformers are the entire cost,
and `guard` costs what V3 costs because it is the same backbone with the same
512-token window. This is what the policy profiles are for: the shipped default
names neither, and pays 0.08 ms of detector time per tool result.

That figure is on short corpus text. Across a real 25-call agent chain
gating live fetches of real web pages, V3's
`chunk_max` strategy -- scoring every overlapping window of long content --
pushed gate latency as high as **13.1 seconds** for one page, and for 9 of
16 fetches gate latency exceeded the network round-trip time that produced
the content in the first place. Full breakdown: `docs/LATENCY-BENCHMARK.md`.
Shipping a classifier `inert` (below) protects the *decision*; it saves none
of this latency, because the detector still runs on every result regardless of
its decision weight. The only way not to pay is to leave it out of the policy
file, which the default profile now does.

## 7. Why the system is still designed this way

Given detectors this weak, three design decisions (`plan.md` 2.15) follow
directly from the numbers above, not from caution for its own sake:

- **Max/OR fusion, never weighted-linear averaging.** The four detectors that
  existed when this was measured are near-orthogonal (pairwise Jaccard
  0.00-0.09); averaging weak orthogonal
  signals at ~0.3 weight each cannot cross any useful threshold -- the
  dissertation's own FM-5 failure mode, blamed for 75.7% of its bypasses.
- **V0 and V3 ship `inert`** (scored and logged on every result, zero
  decision weight) rather than promoted on today's numbers. Section 4's
  AUROC-below-chance result is exactly why: an uncalibrated ML score driving
  live decisions on this surface has already been measured to hard-block 7
  of 8 benign documents under one score mode.
- **Escalate, not Block, is the default action on detection.** With the
  majority of real attacks caught by nothing (section 5), a Block-by-default
  policy would pay the full false-positive cost of an imperfect detector
  while still missing most attacks. `calibrated: false` in
  `config/policy.yaml` makes Block structurally unreachable until a real
  calibration run backs it -- enforced in code
  (`PolicyEngine._ceiling`), not just documented.

## 8. What this report does not claim

- No claim that this system blocks attacks reliably. Section 5's own numbers
  are the argument against that claim.
- No claim about non-English content, non-text payloads, or transports
  beyond local stdio and reachable HTTP+SSE (out of scope, `prd.md` 3.2).
- The `MCP-*` rules' 20.3% recall does not generalise evenly across sources
  either (15.2% BIPIA vs 30.6% InjecAgent, `docs/POLICY-AUDIT.md`) -- the
  same generalisation caveat as section 5 applies to the rules, not only the
  classifiers.
- Every figure here is a point-in-time measurement against a "low hundreds"
  corpus. Confidence intervals are reported throughout specifically because
  point estimates alone would overstate precision.

## Reproduce

**Without any model weights**, from the committed run alone:

```bash
uv run mcp-shield gauge-recut               # every AUROC in section 4, from results/gauge/scores.csv
uv run python scripts/benchmark_rules.py    # rule recall vs BIPIA + InjecAgent
```

`results/gauge/scores.csv` is committed on purpose (`plan.md` 2.26): it carries
every per-item score behind section 4, so the statistics recompute with no
weights, no corpus and no network. It holds item ids and numbers only -- no
payload text.

**With the fetchable `guard` weights** (Apache-2.0, downloaded automatically):

```bash
uv run mcp-shield corpus-ingest
uv run mcp-shield gauge-run                 # scores guard alongside anything else configured
```

**With the reused V0/V3 artifacts**, which are not publishable (`prd.md` A1) and
so reproducible only by the author:

```bash
LLMSHIELD_MODELS_ROOT=/path/to/artifacts uv run mcp-shield gauge-run
uv run python scripts/benchmark_latency.py
uv run python scripts/generate_report.py    # regenerates the SVGs in docs/figures/
```

Exact figures vary run to run (benign sampling, model non-determinism in chain
recording). The reproducible *shapes* are: ported rules transfer at 0%, while
rules derived from real attack data reach ~20%; no classifier tested separates
usefully, including a purpose-built published one; recall does not generalise
across attack sources; and the transformers dominate fused latency.
