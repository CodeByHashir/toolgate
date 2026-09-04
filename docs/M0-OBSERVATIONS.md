# Milestone 0 observations

**These are smoke-test observations from four hand-written probe strings, not
results.** There is no corpus, no decontamination, no threshold calibration and
no statistics behind them. They are recorded because they shape the design of
later milestones, and nothing here should be quoted as a finding.

Setup: reused LLMShield V0 and V3, CPU, unmodified. Probes are in
`src/llmshield_mcp/cli.py`.

## 1. Context dilution, not the 512-token window, looks like the dominant failure

The project's premise was that V3's 512-token window would be the main obstacle
on the tool-result surface. A controlled probe says otherwise.

| Input | windows | P(injection) |
|---|---|---|
| Injection payload alone | 1 | **0.998** |
| Benign filler x5 + the same payload | **1** | **0.052** |
| Benign filler x15 + the same payload | 1 | 0.035 |
| Benign filler x60 + the same payload | 4 | 0.038 |

Row 2 is the important one. It fits in a **single** window, so nothing was
truncated and nothing was chunked -- the model saw the entire payload -- and the
injection signal still collapsed by roughly 95%.

Consequences:

* Chunking is necessary but **not sufficient**. It fixes "the model never saw
  the text"; it does not fix "the model saw the text and the surrounding benign
  context washed the signal out".
* The corpus (M6) needs **dilution ratio as a first-class axis** -- the same
  payload embedded in increasing amounts of benign carrier text. PROPOSAL
  section 19 lists an evasion sub-category for encoding tricks, homoglyphs and
  zero-width characters, but not for dilution. Recommend amending it.
* A per-window maximum may be the wrong pooling function. Worth testing
  segment-level scoring against sentence or paragraph units in a later
  milestone.

## 2. Both detectors fire hard on benign text

| Probe | V0 (not_benign) | V3 top class |
|---|---|---|
| Ordinary business prose | 0.879 | harmful = 0.961 |
| Source code containing "ignore" and "system" | 0.940 | injection = 0.996 |
| Benign filler paragraph, repeated | 0.999 | jailbreak = 0.959 |

The source-code case is exactly the false-positive risk PROPOSAL section 2
predicts. The business-prose and filler cases were not predicted and are worse:
neither contains a trigger word.

Likely cause is training distribution -- V0 and V3 learned "benign" from Dolly
and Alpaca *instructions*, so text that is not instruction-shaped falls off the
benign manifold regardless of content. If that holds up under the benign
reference sets in M7, it is a substantive transfer finding.

## 3. Score mode changes the apparent false-positive rate enormously

For the repeated benign filler, V3 scores:

* `injection` mode: **0.035** (looks fine)
* `not_benign` mode: **0.999** (looks catastrophic)

Same model, same input. This confirms the concern recorded in
`config.py:SCORE_MODES`: V0's dissertation default (`not_benign`) and V3's
(`injection`) are not comparable without saying so explicitly. Matched-FPR
calibration gives each its own threshold and so absorbs part of this, but
threat-type disaggregation will not. Both modes must be reported.

## 4. Latency is already well outside the NFR-1 budget

First-pass CPU numbers, single-threaded, no warmup, so treat as order of
magnitude only (proper benchmarking is M9):

| Path | Latency |
|---|---|
| V0, short input | ~2-3 ms |
| V0, ~1500-token input | ~14 ms |
| V3, short input (single window) | ~180-220 ms |
| V3, ~1500-token input, chunk_max (4 windows) | ~5300 ms |

NFR-1's ~5 ms lexical target is met by V0 only on short inputs. NFR-2 asks for
the transformer path to be measured honestly against the sub-100 ms SME budget:
on this hardware it is roughly 2x over that for a single window and ~50x over
for a moderately long tool result. That is the honest answer NFR-2 asks for, and
it is a strong argument for the cascade design deferred in section 26.
