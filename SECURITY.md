# Security Policy

## What this project is, and what it therefore cannot promise

toolgate is a **research harness, an audit layer, and a capability gate** --
not a production security product. Its own published evaluation
([`docs/REPORT.md`](docs/REPORT.md)) measures its best detector at roughly 20%
recall on real indirect-injection payloads, and one of its two reused
classifiers at below-chance separation on this surface.

Read that as the operating assumption, not a disclaimer:

- **It does not stop prompt injection.** Four of five real payloads in the
  evaluation corpus pass through undetected.
- **An `allow` decision means "nothing matched", never "this is safe."**
- **An `escalate` decision does not intervene.** Escalate and Allow both forward
  the tool result byte-identical; the only artefact is a row in the decision
  log. Only Block and Redact change what the agent receives.
- **`block` is structurally unreachable in the shipped configuration.**
  `calibrated: false` in `config/policy.yaml` makes `PolicyEngine._ceiling()`
  downgrade every Block to Escalate. This is intentional and enforced in code.
- **No claim is made for non-English content, non-text payloads, or transports
  beyond local stdio and reachable HTTP+SSE.**

If you need something that reliably blocks attacks on the MCP tool-result
surface, this project's own evidence says no such thing exists yet, including
this one.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes, on a best-effort basis |
| Tagged releases | None yet |

There is no long-term-support branch and no backporting. Fixes land on `main`.

## Reporting a vulnerability

Report privately via [GitHub's private vulnerability
reporting](https://github.com/CodeByHashir/toolgate/security/advisories/new)
on this repository. Please do not open a public issue for anything that could
be exploited against a user of this code.

Useful reports include: the affected version or commit, what an attacker
achieves, a reproduction (a tool result, a config, a test), and any constraints
on exploitability.

## What to expect, honestly

**This project is maintained by one person and has a bus factor of one.** It
began as earlier research and continues as a personal research project. There
is no security team, no on-call rotation, and no paid support.

Concretely:

- **Acknowledgement:** usually within two weeks. Not guaranteed.
- **Fix timeline:** none committed. A serious, clearly exploitable issue in the
  gating path will be prioritised; a theoretical one may sit for a long time or
  be documented as a known limitation instead of fixed.
- **Advisories:** published for anything that materially misrepresents what the
  gate does — for example, a decision the audit log records as taken that was
  not actually applied.
- **Quiet periods:** work on this project is bursty. Silence means the
  maintainer is elsewhere, not that a report was judged unimportant. Feel free
  to ping a report that has gone unanswered for a month.

If this repository is ever abandoned, the intent is to say so in the README
rather than leave a security-adjacent project looking maintained. If you are
evaluating this for anything load-bearing, check the commit history first.

## Issues we consider out of scope

- Detector recall or false positives that the published evaluation already
  reports. Those are findings, not vulnerabilities — open an issue.
- Attacks requiring the operator to run with `--no-gate`, which prints a
  warning saying exactly what it disables.
- Anything requiring write access to `config/`, `pins/`, the model artifacts,
  or the corpus. Those are trusted inputs by design. See "The trust boundary
  runs at the process, not the tool" below for why a signed pin file would not
  change this.
- Resource exhaustion from deliberately oversized tool results beyond
  `gate.max_result_chars`, which exists to bound exactly that and is
  configurable.

## Issues we consider in scope

- A gating decision that the audit log records as applied but that was not
  applied to the forwarded frame.
- Tool-result content reaching the decision log, an error message, or any other
  artefact. The log stores a SHA-256 and numeric detector scores by design; a
  path that leaks the text itself is a real bug.
- Any way to make the gate execute, evaluate, or act on content inside a scanned
  frame (NFR-3 / SEC-1).
- A path that reaches `Decision.BLOCK` while `calibrated: false`, or that
  otherwise bypasses `PolicyEngine._ceiling()`.
- A crash in the gating path caused by a malformed tool result. Defined
  behaviour for malformed input is a requirement, not a nicety.
- A tool **declaration** that reaches the model without being verified against
  its pin, or a pin verdict recorded against bytes the model did not receive.
  Either direction is a verification bypass and does not need local access.
- A declaration pin reported as `unchanged` for a declaration whose bytes
  differ, including a difference expressible only in non-rendering characters.

## The trust boundary runs at the process, not the tool

Worth stating plainly, because two things in this repository are easy to read
as stronger than they are.

**SEC-4 confines the filesystem server's tools, not its process.** The reference
filesystem MCP server is restricted to `sandbox/` — that constrains which paths
its *tools* will operate on. It is not an OS-level sandbox. Every MCP server
here is launched as an ordinary subprocess with the same user and the same
filesystem rights as the operator. A malicious server can therefore write
anywhere you can, regardless of what its tool surface permits.

**So a signed or HMAC'd pin file would be theatre.** An attacker who can write
`pins/` can equally write `config/policy.yaml` to disable gating, edit
`src/llmshield_mcp/gating/pins.py` so verification always passes, or replace the
installed package in `.venv/`. Any key stored on the same filesystem is
available to the same attacker, so a signature over the pin file would add a
guarantee-shaped artifact and no guarantee. It is recorded as rejected, with
this reasoning, in `docs/PLAN-DECLARATION-INTEGRITY.md` §6.

What does raise the bar, in order of value per unit of effort:

1. **Commit `pins/`.** It is gitignored by default and the plan treats
   committing as a legitimate operator choice. Pins hold digests, field names
   and timestamps only, never content, so committing leaks nothing a server
   sent. It moves pin integrity onto git: tampering becomes a reviewable diff,
   a deletion shows up in `git status`, and a silent reset to trust-on-first-use
   has to survive code review instead of happening unobserved.
2. **Do not run MCP servers as yourself.** A separate user account or a
   container is what actually stops a malicious server process from touching
   `pins/`, `config/` or the source tree. This is the only item on this list
   that closes the hole rather than making it noisier.
3. **Corroborate across stores.** Declaration verdicts also land in the SQLite
   decision log, so "this tool is new" in the pin file can be contradicted by
   an audit row pinning it months earlier. An attacker then has to tamper two
   stores consistently rather than delete one file.

None of this makes pinning a defence against a compromised host. Pinning tells
you a server changed its mind after you trusted it. It does not defend the
machine it runs on.
