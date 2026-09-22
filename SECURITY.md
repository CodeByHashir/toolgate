# Security Policy

## What this project is, and what it therefore cannot promise

LLMShield-MCP is a **research harness and detection/audit layer**, not a
production security control. Its own published evaluation
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
reporting](https://github.com/CodeByHashir/llmshield-mcp/security/advisories/new)
on this repository. Please do not open a public issue for anything that could
be exploited against a user of this code.

Useful reports include: the affected version or commit, what an attacker
achieves, a reproduction (a tool result, a config, a test), and any constraints
on exploitability.

## What to expect, honestly

**This project is maintained by one person and has a bus factor of one.** It
began as dissertation work and continues as a personal research project. There
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
- Anything requiring write access to `config/`, the model artifacts, or the
  corpus. Those are trusted inputs by design.
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
