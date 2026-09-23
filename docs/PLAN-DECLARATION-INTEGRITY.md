# Plan: tool declaration integrity

Status: **agreed, upstream-checked, not started.** Written after a five-advisor
review; its corrections are folded in rather than appended, and the ideas it
killed are recorded in §6 so they are not re-proposed. The pre-flight upstream
check (§5) has been run and **changed the plan** — read §5 before §2.

---

## 1. The gap

`toolgate` gates two of the three attacker-controlled channels at the MCP
boundary:

| Channel | Direction | Gated today | Mechanism |
|---|---|---|---|
| Tool **results** | server → client | Yes | Detection — measured at ~20% recall, `docs/REPORT.md` |
| Tool **calls** | client → server | Yes | Capability rules — deterministic, `gating/tool_calls.py` |
| Tool **declarations** | server → client | **No** | — |

`gating/transport.py`'s own comment says `tools/list` is "out of scope", and
`agent.py` does:

```python
description=tool.description or f"{tool.name} (from the {server} MCP server)",
```

That takes server-controlled text and places it in the model's context as a
tool definition — at session start, before any call happens, persisting for the
whole session, unchecked. Every field of `mcp_types.Tool` is in the same
position: `name`, `title`, `description`, `input_schema`, `output_schema`,
`annotations`, `meta`.

This is the MCP tool-poisoning / rug-pull / shadowing threat class.

**Why it matters more than it looks.** A poisoned description is strictly
better placed than a poisoned tool result: it arrives earlier, it is framed as
trusted configuration rather than data, and it stays in context for the whole
session instead of one turn.

**Threat model, stated precisely.** The objection "a user could just read the
description" has two answers, and the second is the strong one.

Volume and rotation: nobody reads forty tool descriptions across six servers,
and nobody re-reads them after an update. Humans check once.

And more fundamentally, the user often *cannot* read it. Nothing in MCP
requires the rendered approval view and the bytes delivered to the model to
match, and Unicode TAG-block characters render as nothing while reaching the
model intact (§5.1). The payload can be present and invisible at the same time.

The cases this addresses are therefore:

1. **Rug-pull** — description approved at install, changed later.
2. **Mid-session mutation** — `notifications/tools/list_changed` exists
   (`ToolListChangedNotification`, verified in the SDK), so a server can change
   its declarations *during* a session, after any approval.
3. **Shadowing** — a second server declares a tool name a first server already
   owns. A human never notices that server B also declared `send_email`.
4. **Concealment** — a declaration carries non-rendering characters, so what
   the operator approved and what the model received are different strings.

It does **not** address a server that is malicious at first sight. That is
stated as a limitation, not engineered around.

---

## 2. What gets built

### 2.1 Canonicalisation — do this first

**This is the load-bearing decision and everything downstream depends on it.**
If canonicalisation is wrong, spurious mutations contaminate the churn
measurement and every number in section 3 is noise.

Rules:

- **Hash raw bytes, never normalised text** (see §5.2 — normalising
  concealment away before hashing would hide the attack from the pin).
- Hash a canonical JSON serialisation of an explicit field list:
  `name`, `title`, `description`, `input_schema`, `output_schema`,
  `annotations`. Sorted keys, no insignificant whitespace. NFC is applied
  only to the human-facing diff, never to the hashed bytes.
- **Exclude `meta`** — it carries transport and tracing fields that legitimately
  change per connection.
- Hash each field separately as well as together, so a diff can say *which*
  field moved. A single blob hash would report "something changed" and force a
  human to diff by eye, which is the failure mode this exists to prevent.
- Record the field list and the algorithm version in the pin file. A future
  change to either invalidates existing pins, and that must be detectable
  rather than silently reinterpreting old data.

Write the canonicaliser and its tests before anything else, including
adversarial cases: key reordering, unicode normalisation forms, whitespace-only
edits, and a description that differs by two words inside a long schema.

### 2.2 The pin store

- One file, `pins/<server>.json`, committed or gitignored at the operator's
  choice (default: gitignored, like every other runtime artifact here).
- Trust on first use: an unseen tool is recorded and allowed, and that is
  logged as `new` so the first sight is never silent.
- Records per-field hashes, first-seen timestamp, and the canonicaliser version.
- **No content.** Hashes only, consistent with SEC-3 — a description can carry
  anything, including data the operator would not want in a committed file.

### 2.3 Verification and enforcement

Four verdicts: `new`, `unchanged`, `mutated`, `shadowed` (a name already owned
by another server) — plus `concealed` as an orthogonal flag, since concealment
is a property of one declaration and so is detectable on first sight, which is
the case pinning alone cannot cover.

Enforcement mirrors `gating/tool_calls.py`:

- Policy-as-code block in the same YAML, per-server and per-tool.
- Actions: `allow`, `escalate` (log only), `block` (the declaration is withheld
  from the agent, so the poisoned text never reaches the model).
- Ships **off by default**, like capability gating did.
- Verified on **every** `tools/list` response, not only the first — otherwise
  `notifications/tools/list_changed` walks straight through.
- Blocking a declaration must not break the session: the tool is dropped from
  the list handed to the agent, and the drop is logged.

### 2.4 Audit

New `Outcome.TOOL_DECLARATION`. Row carries server, tool name, verdict, and
which fields moved. Never the field values.

---

## 3. What gets measured

### 3.1 The number that earns its place: benign churn

**Question:** how often do real MCP servers legitimately change a tool
declaration, and would pinning therefore drown an operator in alerts?

Nobody has published this. It decides whether pinning is deployable at all —
a control that fires constantly gets switched off, which is the same lesson
`config/policy.yaml` already records about expensive safe defaults.

**Method.** Collect tool declarations from public MCP servers across released
versions. Canonicalise. Report, per server and pooled:

- fraction of tools whose declaration changed between consecutive releases
- which field moved (name / description / schema / annotations)
- cross-server tool-name collisions
- what fraction of a typical description is instruction-shaped text

**Frozen, not live.** A scheduled scraper rots, and a stale base rate in a repo
whose credibility is measurement is worse than none. Take one dated snapshot,
commit it as evidence alongside `results/gauge/scores.csv`, and state the date
in every figure derived from it.

### 3.2 What will NOT be claimed

**Detection recall is not a result.** Pinning catches 100% of post-approval
mutation *by construction* — hashes detect hash changes. That is a tautology,
and printing it next to a real AUROC would be exactly the rigor slippage this
project exists to avoid. It is stated as "by construction" and given no number.

**The corpus is not re-run through descriptions naively.** The obvious
experiment — inject the existing 337 result-surface payloads into tool
descriptions and re-run the harness — is **construct-invalid**, and three
independent reviewers caught it. Tool descriptions are instruction-shaped by
design, so a ~0.5 AUROC there would be guaranteed by formatting rather than by
detector failure. It would look like a second measured surface and would
actually be an artifact.

If that experiment is ever run it needs payloads adapted to declaration shape,
and the adaptation must be described as a limitation in the same breath as the
result. Deferred, not quietly dropped.

**And if the prediction is wrong, that is the finding.** Everyone expects
classifiers to fail on declarations too. If one works, the thesis inverts and
that gets published. A prediction that cannot fail is not a measurement.

---

## 4. Sequence

Each step is independently valuable, so a stall leaves something working.

| Step | Deliverable | Notes |
|---|---|---|
| 0 | Extend `INVISIBLE_RE` to the TAG block and other non-rendering ranges; test against the eight published techniques | Fixes a live gap in the result path too; independently shippable |
| 1 | Canonicaliser + adversarial tests. Hash raw bytes; concealment is a separate verdict | Nothing else is trustworthy until this is |
| 2 | Pin store, TOFU, per-field hashes | Hashes only, no content |
| 3 | Verify on every `tools/list`; wire into the agent so a blocked declaration never reaches the model | Including `notifications/tools/list_changed` |
| 4 | Policy block, off by default; `Outcome.TOOL_DECLARATION` | Mirrors `tool_calls` |
| 5 | Churn snapshot + concealment prevalence, `docs/DECLARATION-CHURN.md` | Dated, frozen, committed |
| 6 | README: the third channel, and the coverage table | No tautological numbers |

Zero API cost throughout. No model calls; hashing and HTTP fetches of public
declarations only.

---

## 5. Upstream check — DONE, and it changed the plan

Run 2026-09-23, before any code.

**The protocol has no native defence.** Confirmed two ways: a spec-repo search,
and the CSA / NSA-DoD material that says outright that MCP "provides no native
defenses against tool poisoning, rug pull attacks, or cross-server tool
shadowing". The NSA/DoD joint advisory of 2026-06-02 lists version pinning as
mandatory — a control the protocol does not provide.

**The one proposal that tried died for process reasons, unmerged.**
[SEP-1766, "Digest-Pinned Tool Versioning and Interceptor-Based Validation"](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1766)
(opened 2025-11-05, closed 2026-06-24). The closing comment is procedural:
SEPs moved to pull requests, reopen as a PR if still relevant. It was never
adopted.

**And its own reviewers found the flaw that justifies doing this differently.**
SEP-1766 had the *server* publish a SHA-256 over its code archive. Two
reviewers independently objected:

- a single digest conflates three different things — the public tool contract,
  the server implementation artifact, and the deployment binding;
- more decisively: *"A client never sees the server's code archive, so an
  archive or implementation digest is really a server self-assertion."*

A server-published digest is worthless against rug-pull: a malicious server
publishes whatever digest it likes. **The only thing that works is what a
client can recompute itself — the public tool contract.** That is what §2.1
already specifies, so the plan survives the check and is better founded than
the proposal that preceded it.

### 5.1 What the check changed: concealment

The check surfaced
[*Unicode TAG-Block Concealment of Tool-Metadata Payloads in MCP*](https://arxiv.org/abs/2607.05744),
and it is directly load-bearing here.

Unicode's TAG block (U+E0000-U+E007F) renders as **nothing** in terminals, chat
UIs and IDEs, while reaching the model's tokenizer intact. The paper names the
protocol-level cause — *"nothing in the protocol requires the rendered approval
view and the bytes delivered to the model to match"* — and reports that
existing sanitizers **flagged none of its eight techniques**.

**This replaces the threat model in section 1.** The objection "a user could
just read the description" was answered with volume and rotation, which is
weak. The real answer is that the user *cannot* read it: the bytes a human is
shown and the bytes the model receives are not required to be the same, and a
payload can be present while rendering as zero visible characters.

**It also found a live defect in shipped code.** `detectors/normalise.py`'s
`INVISIBLE_RE` covers only `U+200B-200F`, `U+202A-202E` and `U+FEFF`. Verified
directly: a 25-character TAG-block payload appended to a benign description
produces **zero** transforms from `normalise()` and survives intact. That
normaliser runs on tool *results* today, so this is a gap in the current
detection path, not only a future one.

### 5.2 Consequences for canonicalisation (§2.1 revised)

- **Hash raw bytes, not normalised text.** Normalising concealment away before
  hashing would make a poisoned description hash identically to the clean one —
  the attack would become invisible to the pin as well as to the human. Exactly
  backwards.
- **Detect concealment separately**, as its own verdict alongside
  new/unchanged/mutated: does this declaration contain characters that render
  as nothing? That is a property of a single declaration, so it works on first
  sight — which is the one case pinning alone cannot cover.
- NFC normalisation stays, but only for the *human-facing diff*, never for the
  hash.

### 5.3 A second measurement, and it is not a tautology

**What fraction of real MCP tool declarations contain non-rendering
characters?** Zero cost, deterministic, unpublished, and tied to a documented
attack rather than invented. Reported alongside the churn base rate from §3.1.

And the honest self-test the paper invites: run the concealment techniques it
describes against this project's own normaliser and **publish what it catches
and what it misses**. The paper reports existing sanitizers catching 0 of 8.
If this one does better, that is a measured result; if it does not, that is
also a measured result and it goes in the README either way.

### 5.4 Still open

**Client caching.** Confirm where toolgate intercepts declarations relative to
any client-side caching, or a pin may verify something the agent never saw.
Unresolved; check during step 3.

## 6. Rejected, with reasons — do not re-propose

| Idea | Why not |
|---|---|
| **Cross-server taint / data-flow control** | Needs content lineage across calls, which contradicts SEC-1/NFR-3. M12 already died attempting cross-call correlation from hashes alone (`plan.md` 2.25). Unanimous kill. |
| **Secret / API-key detection** | Commodity — `gitleaks`, `trufflehog`, `detect-secrets` do it better. Off-thesis and invites the "gateway #51" read. Unanimous kill. |
| **Trust-on-first-use PKI with versioned pins, policy objects, cross-server identity** | Four of five reviewers named this the worst answer: a multi-month project for a solo maintainer, with no version where half of it ships. With no signing key or CA, "server identity" is just the config string. |
| **Live registry scraper on a schedule** | Unbounded maintenance; scrapers rot. Frozen dated snapshot instead. |
| **Naive corpus re-run through descriptions** | Construct-invalid, see 3.2. |

---

## 7. How this is described

> toolgate gates all three attacker-controlled channels at the MCP boundary.
> Tool results are inspected by detectors whose measured coverage is poor and
> published as such. Tool calls and tool declarations are constrained by
> deterministic rules, which need no classifier and therefore have no
> false-negative rate against the behaviour they name.

The honest framing of the third channel: **pinning cannot tell you a server is
malicious. It can tell you a server changed its mind after you trusted it.**
Those are different claims, and only the second one is being made.
