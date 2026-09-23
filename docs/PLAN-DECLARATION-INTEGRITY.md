# Plan: tool declaration integrity

Status: **complete, 2026-09-23.** All six steps are done, and so is the §5.3
self-test against the paper's eight techniques. Written after a five-advisor
review; its corrections are folded in rather than appended, and the ideas it
killed are recorded in §6 so they are not re-proposed. The pre-flight upstream
check (§5) has been run and **changed the plan** — read §5 before §2.

Three things in this document were corrected by implementation rather than by
planning, and each is marked where it appears: the paper's sanitizer numbers
(§5.1), the step-0 strip-versus-decode error (after §4), and §5.4's caching
question, whose answer moved declaration verification off the transport
boundary. The layer ships **off**: with no `tool_declarations` block in
`config/policy.yaml` no gate is built, nothing is pinned and nothing is logged.

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
  `annotations`, and — added on implementation — `execution` and `icons`.
  This list was written against an older SDK; under the pinned `mcp==2.1.1`,
  `mcp_types.Tool` models those two as well, and both are server-controlled
  (`icons[].src` is a server-supplied URL). Sorted keys, no insignificant
  whitespace. NFC is applied only to the human-facing diff, never to the hashed
  bytes.
- Object keys are sorted; **arrays are not reordered**. Array order is
  semantic in a JSON Schema, and T8 works by putting a dangerous value first in
  an `enum`. A canonicaliser that sorted arrays would call that `unchanged`.
- Known limitation: hashing the parsed `mcp_types.Tool` cannot see fields the
  SDK does not model, because pydantic drops them. The canonicaliser therefore
  takes a plain mapping so step 3 can feed it a raw `tools/list` frame instead;
  this interacts with the caching question already left open in §5.4.
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

  **Committing is the stronger choice and it is nearly free.** The pin file is
  not tamper-proof and cannot be made so by anything inside the repository
  (§6). Committing it moves that problem onto git: tampering becomes a
  reviewable diff, a deleted pin shows in `git status`, and a silent reset to
  trust-on-first-use has to survive code review rather than happening
  unobserved. Pins hold digests, field names and timestamps only, so committing
  one leaks nothing a server sent. The default stays gitignored because a pin
  file records what one machine happened to connect to, and a commit should not
  pick that up unasked — but an operator who wants declaration integrity under
  review should delete the `.gitignore` line.
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

  **Status after step 3, stated precisely.** `DeclarationGate.admit()` verifies
  every listing passed to it, so this holds for any number of listings. But the
  reference agent calls `session.list_tools()` exactly once, in
  `open_servers()`, and stores the result for the whole run — it never
  re-lists, and it does not subscribe to `notifications/tools/list_changed`.
  So in *this* client a mid-session mutation cannot reach the model at all,
  because the model is never re-shown the tool list. The rug-pull vector here
  is across sessions, not within one.

  That makes a notification handler dead code in this repository, which is why
  step 3 does not add one. It is **not** a claim that mid-session mutation is
  handled: a client that re-lists on notification (Claude Desktop, an IDE) has
  the live version of the threat, and its protection is that it routes each
  listing through `admit()`. Recorded here rather than left implied, because
  "verified on every `tools/list`" reads like a stronger claim than the one the
  reference agent can support.
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
| 0 | **Done 2026-09-23.** `INVISIBLE_RE` now covers Unicode's whole `Default_Ignorable_Code_Point` set; TAG-block runs are *decoded and appended*, not stripped | Closes T7 only, on the live result path. See the correction below |
| 1 | **Done 2026-09-23.** `gating/declarations.py` + adversarial tests. Hash raw bytes; concealment is a separate flag | Nothing else is trustworthy until this is |
| 2 | **Done 2026-09-23.** `gating/pins.py`: `pins/<server>.json`, TOFU, per-field hashes, verdicts `new`/`unchanged`/`mutated`/`stale_pin` | Hashes only, no content — asserted against the written bytes. A mutation never re-pins itself; a corrupt file raises rather than starting empty |
| 3 | **Done 2026-09-23.** `gating/declaration_gate.py` + `open_servers(declarations=...)`, off by default. Verifies the `ListToolsResult` the agent receives, returns the tuple that becomes `ToolParam`, adds the cross-server `shadowed_by` view | §5.4 resolved and it moved this step off the transport boundary — see below. `notifications/tools/list_changed` deferred with a reason |
| 4 | **Done 2026-09-23.** `gating/declaration_policy.py`, `tool_declarations` in `policy.yaml`, `Outcome.TOOL_DECLARATION`, CLI wiring | Keyed on *conditions* not verdicts, most-severe-wins. Defaults escalate, never block — benign churn is unmeasured until step 5. `on_pin_error` fails closed. `declaration_seen()` gives the cross-store corroboration |
| 5 | **Done 2026-09-23.** `scripts/collect_declarations.py`, `docs/DECLARATION-CHURN.md`, snapshot committed | 54 releases of 7 servers, really launched. Churn is **bimodal**: 30/47 transitions change nothing, 17/47 change everything. Concealment 0/380 |
| 6 | **Done 2026-09-23.** README third-channel section + three-channel coverage table | No tautological numbers: the table states "by construction" for declarations and gives no recall figure |

Zero API cost throughout. No model calls; hashing and HTTP fetches of public
declarations only.

### Correction to step 0, found during implementation

Step 0 was written as "extend `INVISIBLE_RE` to the TAG block". Implemented
literally, that would have made the attack *less* detectable, not more.

Stripping is the right transform for **separator** concealment, where invisible
characters split a visible keyword (`Ig<ZWSP>nore`): removing them reassembles
the keyword and the rule fires. T7 is **payload** concealment — the entire
instruction is written in TAG codepoints and the visible remainder is a short,
truthful label. Stripping that deletes the instruction and leaves
`"Formats code neatly."`, so the normalised text a detector sees is benign and
the pipeline reports a clean result with more confidence than before.

The transform has to be a **decode**: recover the ASCII, append it (never
replace, so offsets stay valid for FR-5), and only then strip the now-redundant
TAG characters. This mirrors the base64 handling already in that module.

Two further decisions made in implementation, both recorded because they are
places a later reader would otherwise assume the easy answer was taken:

- The stripping set is Unicode's `Default_Ignorable_Code_Point` property rather
  than a hand-listed set of ranges. The property's definition is "a conforming
  renderer displays nothing for this", which is exactly the threat. It also
  covers cases general category does not: U+3164 HANGUL FILLER is category
  `Lo` and renders as nothing.
- A decoded TAG run is truncated at the existing cap rather than rejected when
  it exceeds it, and unprintable characters are dropped from the decoded text
  rather than disqualifying the run. Both rejections would have been bypasses:
  appending a single CANCEL TAG (U+E007F, which decodes to DEL) would have
  exempted a payload from decoding entirely.

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
view and the bytes delivered to the model to match"* — and measures eight
techniques across five MCP metadata surfaces.

**Corrected 2026-09-23, on reading the paper itself rather than the check's
summary of it.** An earlier draft of this section said the paper's sanitizer
"flagged none of its eight techniques". That is wrong, and the real numbers
matter because they are the ones this project would be compared against.
Table 5 reports: all **8/8** reach the model's context; **4/8 evade** the
baseline string-matching sanitizer (T4, T8, T6, T7) while **4/8 are caught**
(T1, T2, T5, T3); and only **1/8** — T7, the TAG-block encoding — also evades
the human approval render, making it the single technique that defeats both
defence layers. The paper also checks the baseline against 25 benign tool
descriptions and flags 0, so its sanitizer is not a strawman that rejects
everything.

**Only one of the eight is a concealment technique.** This is the distinction
that shapes step 0. The set is T1 direct description injection and T2
cross-tool shadowing (plain ASCII); T7 TAG-block concealment (description);
T4 confused-deputy credential relay and T8 dangerous-default coercion
(`inputSchema`); T6 namespace collision (tool `name`); T5 error-channel
injection (`isError` result); T3 rug-pull (re-`tools/list`). Step 0 addresses
T7 and nothing else — T1/T2/T5 are plain-text and belong to the detectors whose
poor recall `docs/REPORT.md` already publishes, T4/T8 and T6 and T3 belong to
steps 1-4 of this plan.

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
and what it misses**. The comparison point is the corrected figure in §5.1 —
the paper's baseline sanitizer is evaded by 4 of 8, not 8 of 8 — and the
comparison is only fair for the techniques a normaliser can address at all.
Reporting "closed 1 of 8" against a baseline that closed 4 of 8 would be the
honest framing if that is what the measurement shows, and the surfaces the
other seven live on are covered by later steps rather than by this one.

**Done 2026-09-23, and that is what it showed.** `tests/test_paper_techniques.py`
runs a rebuilt payload per technique through the layers toolgate actually runs;
the README carries the table. On first sight toolgate flags **1 of 8** outright
(T7) and T6 only against another MCP server, against the baseline's 4 of 8 —
but on *different* techniques, so the two are complements rather than rivals.
After approval every declaration payload is flagged by construction, T4 and T8
included. **T5 is missed**: the shipped result-path detectors allow the rebuilt
payload with nothing firing, where the baseline catches it. Published in the
README against toolgate, as this section required.

### 5.4 Still open

**Client caching — RESOLVED 2026-09-23, and it changed where step 3 runs.**

Why it was treated as a blocker rather than a check to do in passing:
pin-file tampering needs local write access, and an attacker with that already
owns the control outright (§6, `SECURITY.md`). A verification gap between the
bytes toolgate hashes and the bytes the model receives needs **no local access
at all**, and it fails in both directions — toolgate verifying a declaration
the model never saw, or the model receiving one toolgate never verified. The
second is worse than no control, because it converts an unknown into a false
assurance.

Checked against the pinned `mcp==2.1.1`:

1. `ClientSession.list_tools()` calls `send_request` unconditionally. On the
   API this project uses, every listing *does* cross the transport, so a
   frame-level check would see them all. The naive worry was unfounded.
2. But `ClientSession._absorb_tool_listing()` mutates the result **after** the
   transport hands it over, and drops tools whose `x-mcp-header` annotations
   are invalid. A frame-level check therefore verifies a **superset** of what
   the agent receives.
3. And the higher-level `mcp.client.client.Client` keeps a response cache
   (SEP-2549) whose own source comment records that "a cache hit skips
   `session.list_tools`". On that API a frame-level check sees **nothing** while
   the model is handed a full tool list. This project does not use that API
   today, but nothing stops it from being adopted later.

So declaration verification is the one thing in this package that deliberately
does **not** gate at the transport boundary. It runs on the `ListToolsResult`
the agent actually receives, and the tuple it returns is the tuple that becomes
`ToolParam` — the guarantee is structural rather than a property of the call
graph staying the same shape. `test_gating_declaration_gate.py` asserts it
against the tool list the fake Anthropic client is handed, not against a
docstring.

Consequence worth recording: **a client that does not route its listing through
`DeclarationGate` is not protected**, whatever the transport gate is doing.
That is a narrower claim than "toolgate verifies declarations" and is the one
being made.

**Fail-open versus fail-closed.** `PinStore.load` raises `PinStoreCorrupt`
today. Whether step 3 lets that propagate (the session dies) or catches it (the
control is silently off) is a policy decision to make deliberately, not one
that should fall out of where a `try` block happens to land. It belongs with
the step 4 policy block, and until then the exception propagates.

## 6. Rejected, with reasons — do not re-propose

| Idea | Why not |
|---|---|
| **Cross-server taint / data-flow control** | Needs content lineage across calls, which contradicts SEC-1/NFR-3. M12 already died attempting cross-call correlation from hashes alone (`plan.md` 2.25). Unanimous kill. |
| **Secret / API-key detection** | Commodity — `gitleaks`, `trufflehog`, `detect-secrets` do it better. Off-thesis and invites the "gateway #51" read. Unanimous kill. |
| **Trust-on-first-use PKI with versioned pins, policy objects, cross-server identity** | Four of five reviewers named this the worst answer: a multi-month project for a solo maintainer, with no version where half of it ships. With no signing key or CA, "server identity" is just the config string. |
| **Live registry scraper on a schedule** | Unbounded maintenance; scrapers rot. Frozen dated snapshot instead. |
| **Naive corpus re-run through descriptions** | Construct-invalid, see 3.2. |
| **Signed or HMAC'd pin file** | Theatre against the only attacker it would face. Whoever can write `pins/` can also write `config/policy.yaml` to disable gating, edit `gating/pins.py` so verification always passes, or replace the package in `.venv/` — and can read any key stored on the same filesystem. It would add a guarantee-shaped artifact and no guarantee, which is the exact failure this project spent its audit removing. The same objection retires the smaller version of the §6 "TOFU PKI" row. Committing `pins/` and not running servers as your own user are what actually raise the bar; both are recorded in `SECURITY.md`. A key genuinely out of reach (hardware token, remote attestation) is the only non-theatre version, and that is the multi-month project already rejected above. |

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
