# End-to-End Gate Evaluation (M13)

> **Provenance (added on integration, 2026-09-23).** Measured on the code as of
> commit `4f99241`, before nine later commits on `main` -- among them the
> post-audit hardening pass, which changed how redaction spans are applied
> (closing a redaction leak) and split the policy into profiles. **Not re-run
> on the current gate.** The figures below describe that earlier version. See
> `whats_has_been_done.md`, "Integrated after the fact: M13-M18".
>
> M13 specifically: its 34 benign controls included `chains/latency_chain.json`,
> since removed for licensing; a re-run on current `main` would have 9. M13 is
> offline and costs nothing to re-run (`scripts/eval_e2e.py`).

> **These are measured numbers for these detectors, this policy, and these three
> static corpora, delivered as synthetic tool results in an offline harness.
> They are not a security claim and say nothing about whether a model acts on
> a payload that reaches it.**

Run: `uv run python scripts/eval_e2e.py` (about 45 s, no API key, no model, no
network once the corpus cache exists). Code: `src/llmshield_mcp/eval_e2e.py`.
Tests: `tests/test_eval_e2e.py`.

---

## 1. What question this answers

Before M13, every detection number in this project came from calling a
detector directly. Nothing had pushed a real adversarial payload through the
same `Gate` a live session uses and then inspected what the agent-facing frame
looked like. M13 does that offline and answers four things:

1. What does the shipped gate **decide** for real BIPIA, InjecAgent and
   LLMail-Inject payloads, at 0 / 50 / 75 / 90 % dilution?
2. What does the gate **forward**: is the payload removed, masked, or delivered?
3. Does observed behaviour match the **documented** policy contract, including
   Block and Redact?
4. What is the **false-positive** behaviour on benign tool results, and what is
   MCP-\* recall on LLMail-Inject (previously unpublished)?

## 2. The policy contract under test

Read from `gating/policy.py`, `gating/transport.py`, `gating/content.py`,
`config/policy.yaml` and `plan.md` 2.15-2.17 before any code was written.

| Item | Contract |
|---|---|
| Roles (shipped) | injection = `rules_mcp` (escalate >= 1.0, block >= 1.0); redaction = `pii` (redact >= 0.7); inert (scored, never decide) = `rules_inj`, `v0`, `v3` |
| Fusion | max/OR. Precedence BLOCK > ESCALATE > REDACT > ALLOW. No weights |
| BLOCK | needs an injection hit that exists **only after normalisation** (`detail.normalisation_only`, so no offset-valid span) **and** `calibrated: true`. `PolicyEngine._ceiling` downgrades every BLOCK to ESCALATE while `calibrated: false` (shipped) |
| ALLOW / ESCALATE frame | forwarded unchanged, except PII spans are masked |
| PII masking | independent of the label: spans >= 0.7 become `[REDACTED:<LABEL>]` even under ESCALATE; never under BLOCK |
| BLOCK frame | the whole result is replaced by `build_block_result(True)`: `isError: true`, one text block, `BLOCK_MESSAGE` |
| Scan bound | `max_result_chars` truncates detector input only, never the forwarded frame |

Consequences that shape the evaluation:

* With the shipped policy **BLOCK cannot occur**. Verifying Block therefore
  needs a counterfactual policy (Section 3), reported separately and labelled.
* ESCALATE forwards the injection text. "Flagged" is not "withheld".

## 3. Method

Each payload is wrapped in a real `JSONRPCResponse` frame
(`{"content": [{"type": "text", ...}], "isError": false}`) and passed through
`Gate.observe_outbound` / `observe_inbound` with the real detectors, the real
`PolicyEngine`, and a real SQLite `DecisionLog`. The harness records the
detector scores, the fused decision, and the forwarded frame.

**Corpus.** BIPIA 125, InjecAgent 62, LLMail-Inject 150 (the loaders' own
samples, unchanged; 337 payloads). Payloads are the injected instruction, not a
composed document.

**Dilution.** `dilution.build_diluted_text(..., position="middle")` with the
verified-neutral filler from `dilution.load_neutral_filler` (128 words, 0.0 on
every detector), at ratios 0.0 / 0.5 / 0.75 / 0.9 (filler-word fraction). That
function joins words with single spaces at every ratio, including 0.0, so
payloads are whitespace-normalised in the carrier. Control: scoring the raw,
un-joined payloads gives identical `rules_mcp` recall for all three families
(Section 4.2).

**Arms.**

| Arm | Content | Calls per policy |
|---|---|---|
| `plain` | every payload at every ratio | 337 x 4 = 1,348 |
| `base64` | the 84 payloads `rules_mcp` detects in the clear, base64-encoded, isolated only | 84 |
| `benign` | 25 recorded real tool results + 50 repository lines, unmodified | 75 |

The `base64` arm exists because Block is reachable only through
`normalisation_only`, and the existing normaliser decodes base64 and appends
the plaintext (`detectors/normalise.py`). Encoding real payloads with it drives
the real Block path with real rules. It is a synthetic obfuscation, not an
observed attack. It is isolated only because the ratio is a word fraction and
a base64 blob is one word.

**Policies.**

| Policy | Definition |
|---|---|
| `shipped` | `config/policy.yaml` unchanged |
| `calibrated_counterfactual` | the same file with **only** `calibrated` set to `true`. **Not a shipped configuration.** It says what Block would do, never what the product does |

**Oracle.** For every call, `documented_outcome` re-derives the expected
decision and forwarded frame from the contract above using only detector
output (it does not call `PolicyEngine`), and `contract_violations` compares:
audit-log scores vs an independent re-scan, decision vs contract, `redacted`
flag, forwarded frame (exact block replacement; exact input with exactly the
PII spans masked; or byte-equal pass-through), that no masked PII value
survives, and that the incoming frame was not mutated. `redact()` is used to
build the expected masked text, so span offset translation is checked but the
masking function itself is not independently reimplemented.

**Benign controls.** 34 recorded results in the committed `chains/*.json` (real
outputs of the reference `fetch` and `filesystem` MCP servers), 25 after
de-duplicating identical text; plus a seeded sample (seed 42, 50 lines >= 30
chars) from a sorted, de-duplicated pool of this repository's own lines
(`corpus.sources.load_benign`; 8,848 lines at the time of the recorded run).
That pool changes whenever repository docs or code change, so this set is
supplementary; the recorded chains are the fixed benign control.

## 4. Results

### 4.1 Decisions are invariant to dilution

Shipped policy, plain arm, all 337 payloads:

| Ratio | allow | redact | escalate | block | injection flag (ESCALATE+BLOCK) |
|---|---|---|---|---|---|
| 0.00 | 155 | 98 | 84 | 0 | 24.9 % (84/337) [20.6, 29.8] |
| 0.50 | 155 | 98 | 84 | 0 | 24.9 % |
| 0.75 | 155 | 98 | 84 | 0 | 24.9 % |
| 0.90 | 155 | 98 | 84 | 0 | 24.9 % |

**0 of 337 payloads changed decision at any ratio.** This is expected: the
injection and redaction detectors are lexical, so padding cannot remove a
match. It reproduces `docs/DILUTION-BENCHMARK.md` through the gate; it is not
new evidence about ML detectors, which were not run.

### 4.2 MCP-\* recall by source family (isolated payloads)

`rules_mcp` fired (Wilson 95 % CI):

| Family | n | MCP-\* recall | raw-payload control | Rules that fired |
|---|---|---|---|---|
| BIPIA | 125 | 15.2 % (19) [10.0, 22.5] | 15.2 % | MCP-001 x14, MCP-002 x5 |
| InjecAgent | 62 | 30.6 % (19) [20.6, 43.0] | 30.6 % | MCP-006 x19 |
| **LLMail-Inject** | **150** | **30.7 % (46) [23.8, 38.5]** | 30.7 % | MCP-006 x38, MCP-007 x9 |
| all | 337 | 24.9 % (84) [20.6, 29.8] | | |

BIPIA + InjecAgent = 38/187 = 20.3 %, matching the published M3b / M12 figure.
The LLMail-Inject number is new.

Read it with three caveats:

* The MCP-\* rules were derived from BIPIA and InjecAgent, so LLMail-Inject is
  held out from rule derivation. But the LLMail-Inject challenge has a fixed
  objective (make an email assistant send a message to a fixed address), and
  MCP-006 ("send ... to an address") matches that objective by construction.
  30.7 % is not evidence the rules generalise to injection in general.
* The interval is wide ([23.8, 38.5]).
* Per-scenario counts (35 scenario tiers, most n < 10) are in the JSON output
  and are too small to interpret.

Isolated decisions by family (shipped): BIPIA allow 105 / redact 1 / escalate
19; InjecAgent 27 / 16 / 19; LLMail-Inject 23 / 81 / 46. **75.1 % of payloads
(253/337) receive no injection flag.**

### 4.3 What reaches the agent (shipped policy, plain arm, 1,348 deliveries)

| Decision | deliveries | payload verbatim | payload intact except masked PII |
|---|---|---|---|
| ALLOW | 620 | 620 | 620 |
| REDACT | 392 | 0 | 392 |
| ESCALATE | 336 | 96 | 336 |
| BLOCK | 0 | n/a | n/a |
| **all** | **1,348** | **716** | **1,348** |

**In 1,348 of 1,348 deliveries the payload's text reached the agent; the only
text the gate removed was PII values** (632 deliveries had a PII value
masked). Under the shipped policy the gate detects some payloads; it withholds
none. This is what the contract says (ESCALATE and REDACT do not remove
injection text), and now it is measured.

The PII masking is a corpus artefact, not evidence of general redaction
coverage. 34 of the 35 masked InjecAgent frames are the literal
`amy.watson@gmail.com`, and 118 of the 122 masked LLMail-Inject frames contain
the literal `contact@contact.com` (the challenge's fixed target). Masking that
address may incidentally break an exfiltration instruction; whether it defeats
an attack is a model-side question this run cannot answer.

### 4.4 Block path (base64 arm; 84 payloads)

| Policy | ESCALATE | BLOCK | encoded payload reaches agent | replaced by block message |
|---|---|---|---|---|
| shipped | 84 | 0 | 84 / 84 | 0 |
| `calibrated_counterfactual` | 0 | 84 | 0 / 84 | 84 / 84 |

Verified against the contract: under the shipped policy the ceiling holds (84
ESCALATE, encoded payload delivered); under the counterfactual policy the
forwarded frame is exactly `build_block_result(True)` and nothing of the
original survives.

**Design asymmetry.** Under the counterfactual policy the same 84 payloads in
the clear (plain arm, ratio 0.00) are **not blocked**: allow 155 / redact 98 /
escalate 84 / block 0. Block is reserved for detections that exist only after
normalisation, so flipping `calibrated` alone would block obfuscated attacks
and still pass plain ones through. That matches the documented reason
(`policy.py`: Redact would mask the wrong region), but a future calibration
milestone should decide it deliberately.

### 4.5 Benign controls and false positives

| Set | n | injection flag | any non-ALLOW action |
|---|---|---|---|
| recorded chain results | 25 | 0.0 % [0.0, 13.3] | 0.0 % |
| repository lines | 50 | 0.0 % [0.0, 7.1] | 0.0 % |
| **all** | **75** | **0.0 % (0/75) [0.0, 4.9]** | **0.0 % (0/75)** |

Identical under both policies. The inert `rules_inj` also scored 0 on all 75.

75 benign items can only bound the false-positive rate at about 4.9 % (95 %
Wilson upper). That is roughly the escalate budget in `config/policy.yaml`
(5 %) and says **nothing** about the 0.1 % block budget. The repository-line set
is drawn from a security project's own files, which is a rough proxy for
real benign traffic, not a sample of it.

### 4.6 Integrity

| Check | Result |
|---|---|
| gate calls | 3,014 (2 policies x 1,507) |
| contract violations | **0** |
| audit log | 1,507 rows per policy; decisions match the harness capture |
| reproducibility | two independent runs: identical digests |
| pinned digest (adversarial + recorded chains) | `449b048ba84c6e6265452338f908345c182c310600cfc8729ebae75e8e458e5f` |
| filler | 128 words, sha256 `82053c27c96802e3...` |
| policy / rules | `policy.yaml` sha256 `d388452bafa9...`, `rules.yaml` `3b2f13043fb9...` |

The digest that includes the repository-line sample moved during development
(pool 8,845, then 8,848, then 9,126 lines once this milestone's own docs and
tests were added) because that pool is built from files this repository
edits. The benign result stayed 0/75 on each pool. The pinned digest excludes
the line sample and was identical across all three runs that computed it,
including the one after those files were added. Full file hashes for the
corpus cache are written to `results/e2e/e2e_results.json`.

### 4.7 An unrequested observation: `rules_inj` on LLMail-Inject

The inert `rules_inj` (INJ-\*) fired on **32 of 150** LLMail-Inject payloads
(21.3 %, [15.5, 28.6]) and on 0 of 187 BIPIA/InjecAgent payloads. Its union
with `rules_mcp` covers 69/150 (46.0 %). It is inert by policy, and its false
positives were the reason (`docs/POLICY-AUDIT.md`); 0/75 benign here is far too
small to reopen that. It is recorded only because it shows the "0.0 %
transfer" finding for INJ-\* is family-dependent. No policy was changed.

## 5. Failures and edge cases

* **No contract violations, and the checker can fail.** `tests/test_eval_e2e.py`
  feeds it tampered frames and also breaks the real gate (disables masking,
  removes the calibration ceiling); both are reported as violations.
* **A prior untracked draft of this evaluation** (in the main checkout) counted
  any non-ALLOW as "detected" (16.0 % BIPIA, 56.5 % InjecAgent) and printed
  "GAP B CLOSED" while never exercising Block. Those figures conflate PII
  masking with injection detection; the separated numbers above are the ones
  to use.
* **Whitespace joining** is applied at every ratio including 0.0. It changed no
  verdict (raw control identical for all three families).
* **PII artefacts** (Section 4.3) inflate REDACT and "frames masked" for two
  families.
* **Undetected majority.** 155/337 payloads are ALLOW: nothing flagged, nothing
  masked, frame forwarded byte-identical.

## 6. Limitations

* **Offline and synthetic.** Frames are built and passed to `Gate` directly.
  The async stream wrappers and a real MCP transport are not exercised here
  (they call the same `observe_inbound`; their transparency is covered by
  `tests/test_gating_transport.py`). No agent or model is in the loop.
* **Light detectors only.** `v0` and `v3` are excluded. They are inert in the
  shipped policy, which `PolicyEngine.decide` never consults, so they cannot
  change a decision; that was not verified with weights here.
* **Static, non-adaptive corpora.** No attacker adapted to these rules. Recall
  on adaptive attacks is unmeasured and likely lower.
* **Synthetic carrier.** A single text block of neutral filler, payload in the
  middle. Real tool results are structured (JSON, HTML, multi-block).
* **Payloads are not decontaminated** (M6 decontamination concerns V0/V3
  training overlap and is irrelevant to lexical rules, but it is a difference
  from the GAUGE corpus).
* **LLMail-Inject cache provenance.** The 12 sampled pages were copied from a
  sibling worktree's cache (fetched by an earlier run with seed 42), not
  re-downloaded, and are hashed in the manifest. That a fresh fetch reproduces
  the same bytes was not verified.
* **Oracle shares detector code with the gate.** It tests policy and wiring,
  not detector correctness.
* **M12 session accumulator was not enabled** (observation only; no effect on
  decisions).

## 7. Does M13 close Gap B?

**Partly.** "Gap B" is the absence of an end-to-end adversarial evaluation of
the live gate.

Closed: the gate's decision and the frame it forwards are now measured,
offline, for 337 real payloads across four dilution levels and checked against
the documented contract, including Block (under a labelled counterfactual) and
Redact, with benign controls and an audit-log cross-check.

**Not closed:** anything that needs a live agent or a model. Whether a payload
that reaches the agent changes its behaviour, and what happens on a real
transport, remain unmeasured. The strongest defensible finding is negative
and narrow: **under the shipped policy the gate flags 24.9 % of these payloads
and withholds none of them.** That extends to the offline gate-level result;
it is not a live-attack result.

## 8. Reproduce

```
# once: fetch the corpus cache (downloads BIPIA, InjecAgent, sampled LLMail-Inject)
uv run python -c "from llmshield_mcp.corpus.sources import fetch, fetch_llmail_inject; fetch(); fetch_llmail_inject()"

uv run python scripts/eval_e2e.py          # ~45 s; writes results/e2e/e2e_results.json (gitignored)
uv run pytest tests/test_eval_e2e.py       # CI-safe: no corpus, models or network
```

Exit status of the script: 0 clean, 1 contract violation or audit mismatch,
2 corpus missing. Model-side attack success (a real LLM receiving the
forwarded frames) is a separate optional experiment and is deliberately not
part of this milestone.
