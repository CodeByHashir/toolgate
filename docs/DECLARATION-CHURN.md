# Declaration churn in released MCP servers

**Snapshot taken 2026-09-23. Frozen, not refreshed.** Regenerate with
`uv run python scripts/collect_declarations.py --collect`, which overwrites
the snapshot and changes every number below; the date above is part of every
claim made here.

## The question

`docs/PLAN-DECLARATION-INTEGRITY.md` §3.1 asks how often real MCP servers
legitimately change a tool declaration. It decides whether pinning is
deployable: a control that fires on every routine upstream release is one an
operator switches off. Nobody had published the number, so every default in
`gating/declaration_policy.py` was a guess until this ran.

## Method

Each server's last 8 stable releases were
installed and launched over stdio, and their real `tools/list` responses
canonicalised by `gating/declarations.py`
(canonicaliser v1). Source was not parsed:
that would measure what a repository says rather than what a server sends.
A tool is *changed* when its combined per-field digest differs between two
consecutive releases; tools added or removed are counted separately and are
not part of the changed fraction.

## Churn, per server

| Server | Releases | Transitions | Tools compared | Changed | Rate |
|---|---|---|---|---|---|
| everything | 8 | 7 | 73 | 14 | 19.2% |
| fetch | 8 | 7 | 7 | 1 | 14.3% |
| filesystem | 6 | 5 | 70 | 42 | 60.0% |
| git | 8 | 7 | 84 | 12 | 14.3% |
| memory | 8 | 7 | 63 | 36 | 57.1% |
| sequential-thinking | 8 | 7 | 7 | 5 | 71.4% |
| time | 8 | 7 | 14 | 2 | 14.3% |
| **pooled** | | **47** | **318** | **112** | **35.2%** |

### The pooled rate is the wrong statistic

The distribution is **bimodal, with nothing in between**. Of 47 release transitions, **30 changed no declaration at all** and **17 changed every tool the server has**. The median transition changes 0% of declarations; the mean is 36.2% only because the second mode drags it there.

That shape is the finding. A release either leaves declarations alone or
rewrites all of them at once, which is the signature of an SDK-wide
metadata change rather than an author editing one tool. The consequence
for an operator is the opposite of the pooled figure's implication:
pinning is silent through roughly two thirds of upgrades, and when it
does fire it fires on everything — which is an easy alert to triage, not
a needle in a haystack.

Tools added across all transitions: 12. Removed: 10.

## Which field moves

| Field | Tools changed | Share of changes | Releases it moved in |
|---|---|---|---|
| `annotations` | 79 | 70.5% | 8/47 (17.0%) |
| `input_schema` | 41 | 36.6% | 9/47 (19.1%) |
| `output_schema` | 24 | 21.4% | 8/47 (17.0%) |
| `title` | 22 | 19.6% | 6/47 (12.8%) |
| `execution` | 22 | 19.6% | 6/47 (12.8%) |
| `description` | 9 | 8.0% | 9/47 (19.1%) |

Two columns because they answer different questions. *Tools changed* is
dominated by the all-at-once releases above; *releases it moved in* is
what an operator actually experiences.

### `description` moves surgically; everything else moves wholesale

Descriptions changed in **9 of 318** tool comparisons (2.8%), spread across 9 of 47 releases.

Read those two numbers together rather than separately. A description change
is *not* rare per release — it happens in about one upgrade in five, as often
as any other field. What is rare is its **blast radius**: when descriptions
move they move for roughly one tool, where the metadata fields move for every
tool at once. The churn in `annotations`, `output_schema` and `execution` is
an SDK version bump rewriting the whole listing; a description change is
somebody editing one tool's prose.

That distinction is the operationally useful one, because the fields are not
equally interesting. A tool-poisoning payload has to reach the model as text,
and `description` is the field that carries prose into context. So the signal
an operator wants — one tool's description changed — is precisely the signal
that is *not* buried by SDK churn: it arrived 9 times across 47 upgrades.

So the honest reading is that declaration pinning is deployable, and that a
policy able to name *fields* rather than only conditions would be quieter
still. `gating/declaration_policy.py` keys on conditions
(`new`/`mutated`/`shadowed`/...) and cannot express "alert on a description
change, ignore an annotations change". That is a concrete improvement this
measurement argues for and which is **not** implemented — recorded here
rather than quietly added, since the plan scoped this step to measuring.

This is also why the pin store keeps per-field digests rather than one blob:
a verdict that names the field is the difference between a reviewable alert
and a human diffing a 2KB schema by eye.

## Concealment prevalence

**0 of 380** declarations carry characters that a conforming renderer draws as nothing (0.0%).

Unpublished, zero-cost, and tied to a documented attack rather than invented
(plan §5.3, arXiv:2607.05744). The set is Unicode's
`Default_Ignorable_Code_Point`, the same one `detectors/normalise.py` strips.

## Cross-server name collisions

None. Across the 7 servers' latest releases, no tool name is declared by more than one server.

The base rate for the `shadowed` verdict. Note the sample: these are official
reference servers, chosen for having release histories to walk, not a random
draw from the ecosystem. A collision rate measured here says little about
what an operator running six third-party servers would see.

## Rule false positives on benign declarations

Descriptions: **4 of 380** fire at least one rule (1.1%). Input schemas: **0 of 380** (0.0%).

Rules that fired: `INJ-018` (4)

Every one of these is a false positive by construction: these are official
reference servers and nobody is attacking them.

**This is not the experiment plan §3.2 rules out.** That one injects the
adversarial corpus into descriptions and reports recall, which is
construct-invalid because tool descriptions are instruction-shaped by design
-- a poor AUROC there would be guaranteed by formatting rather than earned.
This measurement needs no adversarial labels and makes no threat assumption:
it reports how often a detector fires on text nobody is attacking. That is a
false-positive rate, and it is interpretable on its own.

For scale, description length across 380 declarations: median 60 characters, max 2783.

## What this means for the shipped defaults

The defaults in `gating/declaration_policy.py` were chosen before any of
this existed, on the reasoning that a control firing on every routine
release is one an operator switches off. The measurement either vindicates
that caution or shows it was unnecessary, and it should be read as saying:

* **`mutated: escalate` is the right default and stays.** It is silent through 30 of 47 upgrades, so it is not alert spam — but when it fires it can name every tool at once, which would be a poor `block`.
* **`concealed` could defensibly default to `block`.** Nothing in the corpus
  triggers it, so the expected false-positive cost is zero on this evidence.
  It stays at `escalate` anyway: 380 declarations from official servers is
  not enough to claim a zero rate for the ecosystem, and a control whose
  first false positive blocks a tool is one that gets switched off. The
  number is reported; the default is unchanged and this is why.
* **`shadowed` is untested by this data.** No collision occurred, so its
  false-positive behaviour is simply unmeasured rather than shown to be low.

No default was changed on the strength of this snapshot. Each is now a
choice with a number attached instead of a guess, which was the point.

## What this does and does not support

It supports a statement about **these** servers on **this** date. The sample
is official reference implementations, which are likelier to be stable than
the third-party servers an operator actually installs, so the churn figure
above should be read as a floor rather than a typical value.

It is not a detection result and no recall number appears here. Pinning
catches post-approval mutation by construction -- hashes detect hash changes
-- and printing that next to a measured AUROC is exactly the rigor slippage
plan §3.2 exists to prevent.

## Releases that could not be collected

2 of the attempted releases would not start in this environment and are excluded from every figure above: `filesystem@2025.8.18`, `filesystem@2025.8.21`.

Recorded rather than dropped: a version that will not run is not a version
with no churn, and silently excluding it would bias the rate downward.
