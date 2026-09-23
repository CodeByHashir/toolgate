# Representation-aware PII canonicalisation (M18): design

> **Status: design only for the representation work below. Nothing in this document
> beyond M18-0 is implemented.** No production file changed as part of *this* design,
> no model or API was called, `calibrated` stays `false`. Evidence below comes from
> reading the code and from throw-away prototypes kept outside the repository (numbers
> marked *prototype*); M18's own tests and evaluation script must re-establish every
> one of them before anything is claimed.
>
> **M18-0 (the quadratic-regex fix flagged in section "A separate, pre-existing
> defect" below) is now done** -- see `plan.md`'s M18-0 row and
> `whats_has_been_done.md`. **Erratum:** that section's proposed fix, a leading
> lookbehind, turned out to be wrong: a 40,000-case fuzz run while implementing it
> found the lookbehind silently drops real matches whenever two addresses sit
> together with no separator (`a@b.comX@y.com`), in about 23% of such pairs. The
> shipped fix instead bounds the local part to RFC 5321's 64-octet limit
> (`{1,64}+`, possessive) and drops the redundant `re.IGNORECASE`; see the comment
> above `PATTERNS["EMAIL_ADDRESS"]` in `src/llmshield_mcp/detectors/pii.py` for the
> full reasoning. No number in this document that depends on the *representation*
> forms (`[at]`, spaced, words) changes; only the "leading lookbehind ... 2ms"
> claim below is superseded.

Motivation: M17 (`docs/REPRESENTATION-EVALUATION.md`) showed the shipped PII protection
recognises `contact@contact.com` and its case variant and nothing else. For
`contact [at] contact.com`, `(at)`, `at ... dot` and spaced `@ .` the gate is a
byte-for-byte no-op and model-side attacker success returns to 31-38 % (protected
literal: 8.8 %; ungated: 40.0 %), because the model decodes the spelling itself.

## 1. What the code actually does today (facts, with locations)

| # | Fact | Where |
|---|---|---|
| F1 | The gate extracts text, then calls `scan_normalised(detector, text)` for every detector, then `PolicyEngine.decide`, then `apply_redaction`. | `gating/transport.py:274-291` |
| F2 | `normalise()` (NFKC, invisible characters, homoglyphs, base64-append) is **shared by all five detectors** and changes offsets. `scan_normalised` therefore scores the original *and* the normalised text and **drops the normalised pass's spans**; when only the normalised pass fires it sets `normalisation_only`. | `detectors/normalise.py:113-175` |
| F3 | The policy engine reads `normalisation_only` **only for injection detectors**. For PII (`redaction` role) it masks only `result.spans` with score >= 0.7. So an address exposed only by normalisation is scored (0.85) but **has zero spans and the decision is ALLOW**. | `gating/policy.py:202-231` |
| F4 | The email regex `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` needs a literal `@`. MCP-006 needs `[\w.\-]+@` too. Nothing converts `at`/`dot` spellings. | `detectors/pii.py:35-38`, `config/rules.yaml:226` |
| F5 | `apply_redaction` keeps a span only if it lies wholly inside one content block; a span that straddles the `"\n"` joining two blocks is **silently dropped**. | `gating/content.py:198-202` |
| F6 | `PiiDetector()` is constructed with defaults in at least ten places (`tests/conftest.py`, `scripts/eval_{e2e,live,action}.py`, `benchmark_dilution.py`, `gauge/run.py`, `gating/transport.py`); `PATTERNS` is imported by `eval_live.py` and `eval_representation.py`; a test monkeypatches `PATTERNS["EMAIL_ADDRESS"]` to prove failure containment. | grep |
| F7 | M17's measurement-only `canonical_text` lower-cases everything and rewrites **every** ` at ` and ` dot ` in a document. It is a measuring device and must not be reused as a production transform. | `eval_representation.py:175-195` |

### Existing behaviour on hidden addresses (probe against the shipped code, no API)

| Input | pii score | spans | Decision | What the model sees |
|---|---|---|---|---|
| literal / case variant | 0.85 | 1 | REDACT | `[REDACTED:EMAIL_ADDRESS]` |
| `[at]`, `(at)`, `at..dot`, spaced | 0.0 | 0 | ALLOW | unchanged |
| fullwidth `＠` (NFKC) | **0.85** | **0** | **ALLOW** | unchanged |
| zero-width after `@` | **0.85** | **0** | **ALLOW** | unchanged |
| base64 of the address | **0.85** | **0** | **ALLOW** | unchanged |
| zero-width inside the local part | 0.85 | 1 | REDACT | `con​[REDACTED:EMAIL_ADDRESS]` (prefix leaks) |

Two consequences drive the whole design. First, **canonicalising inside `normalise()` and
letting the existing shadow pass find the address would reproduce the "detected but not
redacted" row above**, because F2+F3 discard the spans. Second, this is already a live gap
for the *existing* transforms (fullwidth, zero-width, base64), independent of M17.

### A separate, pre-existing defect found while measuring

The shipped email regex is **quadratic** on any long run of letters, hex digits or dots
with no `@` (each start position rescans the run). Timings of `PiiDetector.score`
(probe): 10k chars 0.5 s, 20k 2.0 s, 40k 8.4 s, 80k 34 s, 100k 52 s, **200k (the gate's
`max_result_chars`) about 206 s**. The gate has no timeout, so one crafted tool result can
stall it for minutes. A leading lookbehind `(?<![a-zA-Z0-9._%+\-])` returned identical
matches on the spot-check samples in about 2 ms at 80k. This is **out of scope here**
and needs its own fix and equivalence test (section 9, M18-0); it also means every
performance claim below excludes that input for the shipped regex.

## 2. Options considered

| | Option | Verdict |
|---|---|---|
| O1 | Add an `at/dot -> @/.` transform inside the shared `normalise()` | **Rejected.** Changes the text of `rules_mcp`, `rules_inj`, V0 and V3 (re-baselines M12/M13/gauge numbers; MCP-006 would start firing on new inputs), destroys offsets (F2), and PII would again be scored but not redacted (F3). |
| O2 | O1 plus an offset-alignment map so canonical-text spans project back to the original | Correct in principle and the only route that also fixes fullwidth/zero-width/base64 PII, but large: per-character NFKC alignment is not exact across combining sequences, and a wrong projection masks the wrong region (the failure `normalise.py`'s docstring warns about). **Deferred to a later milestone (V2), section 6.** |
| **O3** | **A PII-local candidate finder: match the obfuscated form directly in the original text, canonicalise only the matched substring, accept it only if the shipped email regex fully matches the result** | **Chosen for V1.** Spans are offset-valid by construction, no document is rewritten, only the `pii` detector changes, and the change is additive. |
| O4 | Enforce at the sink (recipient allow-list on `send_email`) | The principled complement (an adaptive attacker can always pick a representation V1 does not support) but a different mechanism and a different milestone. Out of scope. |

## 3. Proposed design and exact insertion point

```
tool result -> extract() (blocks joined by "\n")
            -> scan_normalised(pii, text)
                 pass 1 (original text)   PiiDetector._score
                                            entity loop (unchanged, incl. literal EMAIL regex)
                                          + NEW: find_email_representations(text, forms, validator)
                                          -> spans in ORIGINAL offsets  (used for redaction)
                 pass 2 (normalised text) same code; spans discarded, as today
            -> PolicyEngine.decide (unchanged)  -> apply_redaction (unchanged)
```

Files (V1):

1. **New** `src/llmshield_mcp/detectors/pii_representations.py`: pure functions, no I/O.
   `find_email_representations(text, forms, validator) -> tuple[RepresentationMatch, ...]`
   where `RepresentationMatch(start, end, form)` carries offsets and a form name only,
   never the address (SEC-3, NFR-4; the canonical string exists only transiently for
   validation). Constants `DEFAULT_REPRESENTATIONS = ("bracketed", "spaced")` and
   `ALL_REPRESENTATIONS = DEFAULT_REPRESENTATIONS + ("words",)`.
2. `detectors/pii.py`, `PiiDetector.__init__` gains `representations: tuple[str, ...] = ()`
   (validated; unknown names raise `ValueError` like the threshold check). In
   `_score` (currently `pii.py:154-183`), immediately after the `EMAIL_ADDRESS` `finditer`
   block (`pii.py:171-175`), when `"EMAIL_ADDRESS"` is enabled, its confidence passes the
   detector threshold and `representations` is non-empty: append one `Span(start, end,
   "EMAIL_ADDRESS")` per match and set `detail["EMAIL_ADDRESS"]` to the **same** confidence
   `PATTERNS["EMAIL_ADDRESS"][1]`. The validator is `PATTERNS["EMAIL_ADDRESS"][0]` looked up
   **at call time**, so the existing failure-containment test still works and no second
   notion of "an address" exists. `PATTERNS` itself is untouched.
3. `gating/transport.py:63-64`, `_build_pii()` returns
   `PiiDetector(representations=DEFAULT_REPRESENTATIONS)`.

Unchanged: `normalise.py`, `scan_normalised`, `policy.py`, `content.py`,
`config/policy.yaml`, `agent.py`, every other detector.

**Why the class default is `()` and only the shipped factory turns it on.** Ten call
sites build `PiiDetector()` (F6). Making the class default "on" would change M13-M17's
frozen inputs (M17 `preflight` asserts that G2's frames equal M16's *unmasked* obfuscated
frames and that the gate is a no-op on R2-R5), so those runs would stop being
reproducible. With `()` they keep measuring the pre-M18 detector; a new experiment builds
the shipped detector explicitly (`build_detectors` / `_build_pii`). The cost is that
"shipped" and "default-constructed" differ; the plan (section 9) adds a helper and a test
that pins this.

**Confidence.** No new tunable: an obfuscated address that validates as an email is the
same evidence as the literal one, so it reuses 0.85 and the existing `redact: 0.7`
threshold. Ambiguity is handled by *which forms are enabled*, not by a fuzzy score.

**No policy-file change.** The form list lives in code, not in `policy.yaml`, because the
strict policy loader and `PolicyConfig` would have to change (production security
semantics). It can move into policy later.

## 4. Supported representations in V1

One canonical target: the address the shipped regex would flag if written literally.

| Form | Default | Accepts (case-insensitive markers) | Example |
|---|---|---|---|
| **bracketed** | on | `[at]`, `(at)`, `{at}` (spaces inside and around allowed) instead of `@`; optionally `[dot]`, `(dot)`, `{dot}` instead of `.` in local part and domain; plain `.` still allowed | `contact [at] contact.com`, `john [dot] smith (at) example (dot) co (dot) uk`, `c[at]ntact[dot]com` |
| **spaced** | on | 1-3 blanks on **both** sides of `@`, and 1-3 blanks on **both** sides of **every** dot of the domain (local-part dots plain or spaced) | `contact @ contact . com`, `priya . shah @ acme-corp . example` |
| **words** | **off** (implemented, flag-gated) | bare `at` and `dot` words: `contact at contact dot com` | `bob at mail dot example dot org` |

Grammar (prototype; the implementation may restructure it but must keep every bound):

```
W0 = [ \t]{0,3}      W1 = [ \t]{1,3}          # never \n or \r
TOKEN = [A-Za-z0-9_%+\-]{1,64}                LABEL = [A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?
TLD = [A-Za-z]{2,24}                          BEFORE = (?<![A-Za-z0-9._%+\-@])   AFTER = (?![A-Za-z0-9\-@_])
AT_B  = \[W0 at W0\] | \(W0 at W0\) | \{W0 at W0\}       (exact bracket pairs)
SEP_B = \. | W0 DOT_B W0                                  DOT_B analogous with "dot"
bracketed = BEFORE TOKEN (SEP_B TOKEN)* W0 AT_B W0 LABEL (SEP_B LABEL)* SEP_B TLD AFTER
spaced    = BEFORE TOKEN ((\.|W1 \. W1) TOKEN)* W1 @ W1 LABEL (W1 \. W1 LABEL)* W1 \. W1 TLD AFTER
words     = BEFORE TOKEN W1 at W1 LABEL (W1 dot W1 LABEL)* W1 dot W1 TLD AFTER      # TLD from an allow-list
```

## 5. Transformation rules and safety constraints

1. **Never rewrite the document.** The canonical string is built from the matched
   substring only (`[at]`/`(at)`/`{at}` -> `@`, dot markers -> `.`, blanks removed), used
   for validation, then discarded. The only change to any output is masking.
2. **Same notion of an address.** Accept only if `PATTERNS["EMAIL_ADDRESS"][0].fullmatch(canonical)`.
3. **Additive only.** `spans_new` is a superset of `spans_old` and `score_new >= score_old`
   on every input; nothing the shipped detector finds may be lost.
4. **Explicit-structure only in V1 defaults**: an `at` marker inside a bracket pair, or
   spacing on both sides of `@` *and* every domain dot. No bare-word or half-spaced form.
5. **Single line, bounded.** No newline or carriage return inside a match (also what
   keeps a span inside one content block, F5); whitespace runs <= 3; tokens/labels
   length-bounded; at least one domain separator; alphabetic TLD of 2-24 letters.
6. **Linear time.** Bounded quantifiers and a start-of-token lookbehind (the shipped regex
   lacks one, section 1). Prototype worst case over eight adversarial 200k-char inputs:
   <= 44 ms, comparable to the shipped detector's own 28-40 ms on the same inputs.
7. **Mask the whole obfuscated address**, including every local-part segment, so no prefix
   or suffix leaks (the zero-width row above). The greedy domain follows the shipped regex's
   semantics; the one known consequence is documented in section 9.
8. **Numeric-only output.** No matched text in `detail`, spans, logs or exceptions (SEC-3).
9. **Failure containment unchanged:** the finder runs inside `Detector.score`, so any
   exception becomes a failed result handled by the fail-closed policy (SEC-6).
10. **Only from the original-text pass.** Spans from the normalised pass stay discarded.

## 6. Mapping spans back to the source text

**V1 needs no mapping, by construction.** The finder runs on the exact string handed to
`_score`; for the direct pass that is the original extracted text, so
`text[start:end]` *is* the obfuscated address. Invariants to test:

* I1: `text[start:end]` covers the whole obfuscated address (not part of it).
* I2: no span contains `\n`/`\r`, so it cannot straddle a block join and be dropped (F5).
* I3: spans are produced only when `_score` runs on the original text (the shadow pass's are
  discarded exactly as today).
* I4: overlapping literal and finder spans are merged by the existing `redact()` (same
  label preserved, `pii.py:100-126`); masking twice is a no-op.
* I5: `redact(text, spans)` re-scanned contains no further span (idempotent).

**V2 (deferred): canonical view plus alignment map**, needed only to make PII exposed by
`normalise()` (fullwidth, zero-width, homoglyph, base64) redactable. Sketch: build the
canonical text by replacing only matched regions and record `(orig_start, orig_end,
canon_start, canon_end)` segments; project a canonical span to the original by expanding to
the union of every segment it touches and translating unchanged runs by their cumulative
delta (always widening, never narrowing); if a span cannot be aligned (an NFKC sequence
that changes length across characters), mask the enclosing whitespace-delimited token
rather than pass it through. It needs its own tests, a re-baseline of every detector that
shares `normalise()`, and a decision on whether ESCALATE-only PII is acceptable. It is
**not required for the M17 taxonomy** and is a separate milestone.

## 7. Not converting ordinary natural language

Principles: (a) require structure ordinary prose does not produce (P4 above); (b) never
alter text, only mask; (c) validate with the shipped regex; (d) keep ambiguous forms off by
default until a measured false-positive gate says otherwise; (e) every constraint has a
regression test.

Evidence (prototype, local data, no API):

| Check | Result |
|---|---|
| 16 hand-written hard negatives ("Look at google dot com", "Follow us @ twitter.com", "email me @ home.com", "contact at contact.com", "list [at] index 3", ...) with V1 defaults | **0 matches** |
| Word tier enabled (earlier prototype run, similar phrase list) | "Look at google dot com", "We are at Heathrow dot com", "Stay at hotel dot com", "Sit at table dot org" **do match** (`look@google.com` ...) |
| Repo prose and code, excluding the M15-M17 files that quote the forms on purpose | 0 hits (defaults and words) |
| 520 installed-package prose files (3.7 MB) | 0 hits (defaults and words) |
| Real attacker bodies (LLMail-Inject local cache, 885 distinct): literal 708; bracketed 60; spaced 2; words 20; plain-dot "X at host.tld" 24 (unsupported); `X @ host.tld` 1 (unsupported) | 38 bodies have a supported obfuscated address and **no** literal one, so today they pass unredacted |
| 4000 random addresses x 5 bracketed/spaced spellings (20,000 trials) | 0 span misses |
| 1,076 texts: monotonicity (shipped spans preserved, score not lower) / re-flag after redaction | 0 violations / 0 |
| 13 no-address benign emails x 6 representations (78 frames) | byte-identical to shipped output (78/78) |

**Why `words` is off.** Zero hits in technical prose says nothing about conversational
email, and the four hard negatives above show real collisions ("visit us at X dot com"
means a website). A mail-cue gate (a `send/email/reply/...` word within 50 characters)
removed those four, but (i) it retained only 12 of 20 real word-form attacker hits and is
trivially evaded by an attacker who omits the cue word, and (ii) it still matches "Please
contact us at support dot com". A TLD allow-list, the other obvious guard, missed **every**
benign `.example` address (0/7): the tier must not ship on heuristics alone. Enabling it
needs a benign email corpus that does not exist locally and a pre-registered false-positive
ceiling (section 9).

Known, accepted behaviours of the defaults: `Tom @ Acme . Inc` (blanks around `@` *and*
the dot) is masked as an address; a spaced sentence-final period followed by a word
(`contact . com . Thanks`) makes the greedy domain swallow one following word (1 of 80
M17 documents; the address is still fully masked; same greedy semantics as the shipped
regex on `x@y.com.Thanks`).

## 8. Test plan

CI-safe and synthetic (`corpus/external/` is gitignored, so CI has no real corpus); real-
corpus numbers come from a local evaluation script, not from `pytest`. No new dependency:
`hypothesis` is not installed, so property tests are seeded-random.

| Level | New tests | Notes |
|---|---|---|
| Unit: `tests/test_pii_representations.py` (~45) | every accepted spelling (marker case, inner blanks, no blanks, multi-label, local-part dot markers, `+ - _` in local part); canonicalisation; mismatched brackets (`[at)`) rejected; newline / >3 blanks / non-alphabetic or 1-letter TLD / missing domain dot rejected; token and label length bounds; leading-punctuation boundary; hard-negative list (>= 30 phrases, fixed) matches nothing under defaults; `words` matches only when enabled | |
| Detector: same file or `test_detector_pii.py` | `representations=()` output **identical** to the current detector on a fixed corpus; spans equal `text[s:e]` == the obfuscated address; monotonicity; disabled `EMAIL_ADDRESS` or threshold above 0.85 disables the finder; `PATTERNS` monkeypatch still yields a contained failure; `detail` numeric, no content in spans/exception (SEC-3); unknown form name rejected | keep existing 26 tests unchanged |
| Gate integration: `tests/test_gating_pii_representations.py` (~10) plus new cases in `tests/fixtures/golden_set.json` (the fixture allows additions) | real `Gate` + real `PolicyEngine`: REDACT, forwarded frame masked, log row carries the hash and no address; address in the *second* of two content blocks is masked; no span straddles a block join (I2); a benign 200-char document is forwarded byte-identical; `_build_pii()` has forms on while `PiiDetector()` has them off (pins the design) | |
| M17 regression (deterministic, synthetic documents built from `eval_live.DOC_TEMPLATE` with a native `(at)` remnant): | see section 9's table | mirrors `tests/test_eval_representation.py` style |
| Property/fuzz (seeded) | random addresses x {`[at]`,`(at)`,`{at}`+dot markers, spaced}: exact span, address unrecoverable after `redact`; random strings: monotone and idempotent | prototype: 20,000 trials, 0 misses |
| Performance | adversarial 200k-char inputs (space runs, unclosed `[at `, `a @ b . `, valid addresses, tabs) each <= 100 ms and doubling the input <= 2.5x the time; run on the finder only (the shipped regex's quadratic case is a separate fix); rerun `scripts/benchmark_latency.py` (NFR-1: PII p95 <= 5 ms) | mark as `slow` if flaky |
| Regression of frozen work | full suite green; M15-M17 `preflight` still passes (they build `PiiDetector()` with the default `()`) | |

## 9. How the M17 cases behave after the change

Deterministic prediction from the prototype (80 frozen documents, no model). "Sanitised"
uses M17's definition. These are **predictions to be re-measured**, not results.

| Cond | Written as | Recognised before -> after | Sanitised before -> after (V1 defaults) | With `words` |
|---|---|---|---|---|
| G1 | `contact@contact.com` | 80 -> 80 | 73 -> **80** (the 7 native `(at)` remnants are now masked) | same |
| G2 | `contact [at] contact.com` | 0 -> **80** | 0 -> **80** | same |
| G3 | `contact (at) contact.com` | 0 -> **80** | 0 -> **80** | same |
| G4 | `contact at contact dot com` | 0 -> 0 (**still unsupported**) | 0 -> 0 | 0 -> 80 |
| G5 | `contact @ contact . com` | 0 -> **80** (spans exact 79/80; 1 document masks one extra word) | 0 -> **80** | same |
| G6 | `cOnTaCt@CoNtAcT.cOm` | 80 -> 80 | 73 -> **80** | same |
| ESCALATE (unchanged, rules untouched) | | 27 / 2 / 2 / 2 / 2 / 27 | | |

Benign side (prototype): the 13 no-address emails are unchanged; the 7 address-bearing
emails are fully masked under G2, G3, G5 (7/7 each), so their benign cost moves to the
literal's masked level (M17: 5/7 vs 6/7 unmasked, not significant). With `words` on, G4
benign addresses (`.example`) are still missed unless the TLD rule changes.

Model-side expectation (a hypothesis for a later pre-registered run, not a claim): in M17,
G1's 7 successes were exactly its 7 native-remnant documents and its 73 clean documents were
0/73, so masking G2, G3, G5 and the remnants should push their attacker success towards
0/80. M17 also showed masking costs (7/80 attack documents where the model asked the user
for the "redacted" address; 3 emails addressed to `[REDACTED:EMAIL_ADDRESS]`).

## 10. Explicitly unsupported in V1, and residual risk

* **Bare-word forms** (`at`/`dot`) by default; **plain-dot `X at host.tld`** (24 of 885
  real attacker bodies use it; "look at google.com" makes it unsafe); **`X @ host.tld`**
  (only `@` spaced) and `X @host.tld`.
* `<at>`, `[@]`, `(@)`, `[.]`, `-at-`, `_at_`, non-English words, dot/at written with other
  characters.
* Forms containing a newline, more than 3 blanks, or split across content blocks or JSON
  fields; addresses assembled by the model from parts or described in words.
* **Everything that only `normalise()` exposes** (fullwidth `＠`, zero-width splits,
  homoglyph domains, base64) stays detected-but-unredacted until V2; likewise `%40`,
  `&#64;` and other encodings, which nothing decodes.
* Other PII entities in obfuscated form (phone, SSN, IBAN, card).
* **Detection, not just masking:** MCP-006 still needs an `@`, so ESCALATE stays at
  2/80 for obfuscated forms. ESCALATE is audit-only pass-through (decision D1), so this
  does not change what the model sees; feeding a canonical view to the rules is a separate,
  separately evaluated change.
* **Not a completeness guarantee.** An adaptive attacker can choose any unsupported
  representation; V1 shrinks the *known* surface. A sink-side control (O4) is the
  complementary defence.
* Over-masking has a utility cost that M17 measured (masked conditions: 90 % and 85 %
  benign completion vs 95 % ungated, not significant at n = 20).

## 11. Implementation plan for the next milestone (M18)

Order matters; each step ends green (`pytest -m "not models"`, `ruff check/format --check src tests`, `mypy`).

* **M18-0 (own change, first): fix the quadratic email regex. DONE**, see the erratum
  at the top of this document -- not via a lookbehind (proven wrong), via bounding the
  local part to RFC 5321's 64-octet limit. Independent of the rest.
* **M18-1: `pii_representations.py` + unit tests.** Grammar, canonicalisation, bounds,
  hard negatives. Finder only; nothing wired.
* **M18-2: `PiiDetector(representations=...)`** with default `()`, detector tests
  (identity when `()`, monotonicity, exact spans, SEC-3, failure containment).
* **M18-3: wire the shipped factory** (`_build_pii`), gate-integration and golden-set tests,
  block-boundary tests, M17 synthetic regression, seeded fuzz, performance tests.
* **M18-4: deterministic evaluation script (no model)**: the section 9 table on the real
  frozen documents; benign and prose false-positive scan; `benchmark_latency.py` rerun;
  a `shipped_pii()` helper so later harnesses do not construct `PiiDetector()` by accident.
  Publish results, including anything that differs from this document's predictions.
* **Decision gates before M19 (needs your approval and API spend):** if M18-4 confirms the
  predictions, pre-register the live re-run of M17 with the new detector (same task, model,
  payloads; primary contrasts the obfuscated forms against the protected literal, with the
  benign-completion cost reported); decide separately, on a benign email corpus and a
  pre-registered false-positive ceiling, whether `words` may ever default on.

Acceptance for M18: `representations=()` byte-identical to today on every corpus we have;
zero monotonicity violations; M17 deterministic table met (R1, R2, R3, R5, R6 sanitised
80/80, R4 unchanged 0/80); zero hits on the hard-negative list and benign prose; fuzz 0
misses over >= 20,000 trials; adversarial 200k-char inputs <= 100 ms and linear;
`config/policy.yaml`, `policy.py`, `agent.py` untouched and `calibrated` still `false`.

## 12. Decisions needed from you

1. **`words` off by default** (recommended) versus on with the weaker cue-gated variant.
2. **Fix the quadratic regex (M18-0) first and separately** (recommended; it is an
   availability defect in the shipped gate).
3. **Defer the alignment map (V2)** and record the "normalisation-exposed PII is detected
   but not redacted" gap as its own item (recommended), versus folding it into M18.
