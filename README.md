# toolgate

[![CI](https://github.com/CodeByHashir/toolgate/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeByHashir/toolgate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](pyproject.toml)

**Capability gating for MCP agents, plus the measurements that motivate it.**

When an MCP-connected agent calls a tool, the result goes straight into the
model's context. That is a prompt-injection surface, but not the one most
defences were built for. Tool results are long and varied, and benign source
code is full of words like "ignore" and "system".

This repository does two things:

1. It measures whether prompt-injection detectors work on that surface. The
   test used three classifiers, 337 decontaminated payloads, three independent
   attack corpora and a full matched-FPR protocol. They do not work, including
   a production classifier with about 840k monthly downloads.
2. It ships the controls that survive that finding. If you can't reliably
   detect the attack, limit what a compromised agent is allowed to *do*, and
   check the configuration it is handed in the first place. The controls are
   sandbox confinement, egress allowlists, named destructive operations and
   integrity pinning of tool declarations. All are deterministic and none uses
   a classifier.

> **Status.** Built and run against real weights: interception, six detector
> adapters, a fusion/policy engine, a decontaminated 337-item corpus from three
> independent attack sources, matched-FPR calibration, leave-one-source-out,
> latency and dilution benchmarks, capability gating of outbound tool calls,
> integrity gating of inbound tool declarations, and `toolgate wrap`, a
> standalone stdio proxy that puts the capability rules in front of any MCP
> server a host starts. 1,435 tests: 1,411 run without the unpublished
> weights (a few only on Windows or only on POSIX), 24 more need them. The
> full evidence
> is in [`docs/REPORT.md`](docs/REPORT.md) and
> [`docs/DECLARATION-CHURN.md`](docs/DECLARATION-CHURN.md); a short version
> follows.
>
> `toolgate wrap` is v0.1, not yet published on PyPI: see
> [Use it: `toolgate wrap`](#use-it-toolgate-wrap). A session-level
> correlation layer was built, measured, found unable to detect the threat it
> targeted, and removed. The finding is kept in
> [`docs/DILUTION-BENCHMARK.md`](docs/DILUTION-BENCHMARK.md).

## Headline result

**No, and the reused models are not the cause.** Three classifiers were
measured on the same decontaminated 337-payload corpus, with the same
matched-FPR protocol and the same benign references:

| Detector | AUROC, realistic benign | Attacks missed at ~4% FPR |
|---|---|---|
| V0 — TF-IDF + logistic regression (reused) | **0.694** [0.648, 0.740] | 66.2% |
| V3 — DeBERTa-v3-base (reused) | 0.310 [0.262, 0.357] | 94.7% |
| `guard` — [ProtectAI v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2), purpose-built, ~840k downloads/mo | 0.524 [0.472, 0.577] | 93.8% |

The simplest model tested is the best one. The purpose-built production
detector is statistically indistinguishable from a coin flip: its 95%
confidence interval, [0.472, 0.577], contains 0.5. At its own calibrated
operating point it lets 19 in 20 real attacks through. Against benign text that
merely *looks* suspicious (source code containing "ignore", docs about system
prompts), both transformers fall *below* chance.

A small rule set derived from real attack data catches roughly one attack in
five, with zero false positives in 4,654 benign lines. That bounds its
false-positive rate below 0.082% (Wilson 95%), which is not the same claim as
"zero". The 19 rules carried over unmodified from the user-prompt surface catch
zero of 187.

None of it generalises. The same detector at the same threshold misses 39% to
100% of attacks, depending only on which of three independent real-world attack
collections is measured.

This ships as a detection and audit layer with measured, poor coverage. It is
Escalate-by-default, and Block is structurally disabled until a real
calibration backs it. It is not a guardrail that stops attacks.

The word "Escalate" oversells what happens here. Of the four decisions, only
two change what the agent receives: Block replaces the tool result, and Redact
masks the matched spans. Allow and Escalate both forward the frame
byte-identical, so an Escalate is a row in the decision log and nothing else.
It records that something looked wrong; it doesn't act on it. There is
deliberately no callback, exception or review-queue hook yet. An integration
contract would invite an embedding application to treat Allow as "checked and
clean", and on this surface Allow is roughly four out of five real attacks. See
[`docs/REPORT.md`](docs/REPORT.md) section 5 for the full evidence, figures and
what this does *not* claim.

## What to do about it: gate the capability, not the content

Every detector above asks "does this text look like an attack?" This project
measured that question as unanswerable on this surface. So the control moved to
a different one: "is the agent allowed to do this?"

```yaml
# config/policy.agent.yaml
tool_calls:
  rules:
    filesystem.read_text_file:
      paths: ["{sandbox}/**"]      # sandbox escape
    fetch.fetch:
      egress: ["example.com"]      # exfiltration
    github.delete_repo:
      action: block                # destructive
```

```
scenario          tool                        verdict   rule
------------------------------------------------------------------------------
legit read        filesystem.read_text_file   ALLOW
sandbox escape    filesystem.read_text_file   BLOCKED   ...read_text_file.paths
legit fetch       fetch.fetch                 ALLOW
exfiltration      fetch.fetch                 BLOCKED   fetch.fetch.egress
destructive       github.delete_repo          BLOCKED   github.delete_repo.action
```

Each check maps to an attacker objective that appears throughout the BIPIA and
InjecAgent payloads this project ingests: sandbox escape, exfiltration to an
attacker-controlled host, and destructive operations.

**Why this works when detection does not.** You don't have to recognise the
injection that talked an agent into reading `~/.ssh/id_rsa` to notice that the
agent is reading outside its sandbox. Recognising the persuasion is unsolved
semantics, which is the finding above. Recognising the capability is a string
comparison. For the behaviour a rule names, there is no false-negative rate
under any injection technique, language or dilution, because nothing is being
classified.

**What it does not do.** It bounds the blast radius of a successful injection
to whatever the policy still permits. An attacker who only needs a tool the
policy allows is unaffected. This narrows what a compromised agent can reach;
it does not stop the compromise. In the in-process path, blocking is enforced
by raising at the transport boundary; in `toolgate wrap`, the proxy answers
the call itself. Either way the request never reaches the server.

Capability gating ships off in the default profile, so adding it changed
nothing for anyone who has not opted in. `config/policy.agent.yaml` is a
working example scoped to the reference servers.

## Use it: `toolgate wrap`

`toolgate wrap` runs one stdio MCP server behind these rules. You put it in
front of the server's command in your host's config; the host talks to
toolgate, toolgate talks to the server.

```
host (Claude Code) <--stdio--> toolgate wrap --name fetch --config fetch.yaml -- <server command>
```

### Who v0.1 is for

Agents whose legitimate destinations you can list: your own API, a fixed set
of docs sites, GitHub. For those, an egress allowlist is a real bound. An
agent that must browse arbitrary sites does not fit an allowlist: you would
either break it or loosen the rule to `*`, and `*` protects nothing. That
case needs a different control (a session-level rule that tightens egress
once untrusted content has been read), which is planned, not built. Two
example policies for the workflows v0.1 fits:
[`examples/internal-api.yaml`](examples/internal-api.yaml) and
[`examples/docs-and-github.yaml`](examples/docs-and-github.yaml).

### The guarantee, with its scope

**A `tools/call` to a server wrapped by toolgate, whose URL argument names a
host outside that tool's egress allowlist, never reaches the server, whatever
prose led the model to make it.** The same holds for path arguments outside a
tool's `paths` globs and for tools configured `action: block`.

It holds because nothing is classified. The URL is parsed strictly and
compared with the list by host label and port. Anything two URL parsers could
read differently (a backslash, userinfo, whitespace, non-ASCII, numeric host
spellings) is refused rather than interpreted. Every client line is parsed
strictly too: duplicate keys, a byte-order mark, two objects on one line or a
batch are refused, never forwarded, so a lenient server cannot be handed a
tool call the proxy did not see. The refused call gets an error result naming
the rule (`Blocked by toolgate policy: rule fetch.fetch.egress`); the argument
is never echoed and never logged.

**What it does not cover**, measured or stated rather than assumed:

- **Servers you did not wrap, and tools with no `paths`/`egress` rule.** The
  startup line in the host's server log says how many tools the policy covers:
  `toolgate[fetch]: 1 of 1 tools constrained (default: block); audit: ...`.
- **Redirects the server follows itself, unless network mode is on.** Probed
  on 2026-10-03: `mcp-server-fetch` follows a 302 from an allowed host to any
  other host. The argument-level check sees only the URL it is given, so with
  `network: off` (the default) an allowed page that redirects leaks.
  [Network mode](#network-mode-cooperative) closes this for HTTP clients that
  honour proxy variables; the demo below shows both.
- **Exfiltration through an allowed host**, such as a gist or an issue comment
  on an allowlisted GitHub.
- **Traffic a server originates on its own**, and shell or exec tools whose
  network access is not an argument, except, with network mode on, HTTP
  traffic from a client that honours proxy variables.
- **PII redaction covers `tools/call` results only.** `resources/read`,
  `prompts/get` and notifications pass unredacted.
- **Paths are compared as text.** Symlinks are not resolved, so a symlink
  inside an allowed directory pointing outside it is not caught here
  (`server-filesystem` resolves real paths itself).
- **Tool descriptions are not pinned in the proxy yet.** Declaration pinning
  exists in the in-process path (below) but not in `wrap` v0.1.

**Ports are part of every entry.** `example.com` allows only port 80 for
`http` and 443 for `https` (an explicit `:443` counts the same). Write
`example.com:8080` for one other port or `example.com:*` for any.
`*.example.com` matches any host below `example.com`, not `example.com`
itself.

**Arguments the rule cannot classify fail closed.** For a tool with a `paths`
or `egress` rule, every argument in the tool's declared schema that could hold
a string must be named in `path_args`, `url_args` or `ignore_args` (defaults:
`path`, `paths`, `source`, `destination` and `url`, `uri`, `href`). A tool
with an unnamed one is withheld from the host's tool list and stderr says
which argument to add; an argument the schema does not declare is refused.

### Network mode (cooperative)

`network: enforce` in a policy file makes `wrap` run a small forward proxy on
127.0.0.1 for that server and point the server's `HTTP_PROXY`, `HTTPS_PROXY`
and `ALL_PROXY` at it. Every connection the server's HTTP client makes,
redirect hops included, is then checked against the same egress entries the
rules hold (their union for that server, since a connection does not say
which tool opened it), and refused with a 403 that names the cause.
`network: audit` checks and logs every connection but refuses none on policy
grounds. The default is `off`, which leaves the server's environment exactly
as it was.

```yaml
network: enforce
tool_calls:
  default: block
  rules:
    fetch.fetch:
      egress: ["docs.python.org"]
```

**It is cooperative, not containment.** It covers clients that read proxy
variables, checked per client family in
[`tests/test_proxy_clients.py`](tests/test_proxy_clients.py): httpx (which
`mcp-server-fetch` uses) and Node 24's built-in fetch (`wrap` sets
`NODE_USE_ENV_PROXY=1`) send every destination through the proxy, loopback
included. A client that ignores proxy variables connects directly and is not
covered; a test asserts that such a client still leaks. For containment use an
OS sandbox or a container.

What else it does, and what it costs:

- It decides on the target the client names (the CONNECT `host:port` or the
  absolute `http://` URL), never on the Host header, and connects to the
  checked IP address. A hostname entry may not resolve to loopback, private,
  link-local or cloud-metadata addresses (a rebinding name is refused); only a
  `localhost` entry may reach loopback, and only an IP-literal entry may reach
  the private address it names. An intranet host allowed by name is therefore
  refused in network mode; name it by IP instead.
- A name outside the allowlist is refused before it is looked up, so the DNS
  query cannot carry data out.
- The proxy requires a per-run token, given to the server in its proxy URL. It
  stops other users and unrelated processes from using the port; a process
  running as the same user can read the server's environment and is not
  stopped. The token is never logged.
- Each connection is an audit row (`outcome = 'network_egress'`, rule
  `<server>.network.egress`) with its destination and whether a call in flight
  named that host and port (`divergence`: `matched`, `unmatched`,
  `ungated_call`, `no_call`).
- `wrap` refuses to start if the environment already names an upstream proxy:
  chaining is not supported.
- **Launchers need their cache.** `uvx` and `npx` ask their package index
  before starting the server, through the proxy, and are refused. Start the
  server once without network mode (`uvx mcp-server-fetch==2026.8.18 --help`
  fills the cache), then use `uvx --offline ...` or `npx --offline ...` in the
  snippet, or a preinstalled server. If the server exits before saying
  anything, stderr says so.
- Latency: on the Windows dev machine, 1 KB p99 added rose from 1.39-1.47 ms
  with the mode off to 1.51-1.52 ms with `enforce` (two runs each,
  [`docs/PROXY-LATENCY.md`](docs/PROXY-LATENCY.md)).

### Quickstart (Claude Code)

The PyPI package is `toolgate-mcp` (the name `toolgate` on PyPI belongs to an
unrelated project); the command it installs is `toolgate`. v0.1 is not on PyPI
yet. Until `0.1.0a1` is published, install from git and replace
`toolgate-mcp==0.1.0a1` below with
`git+https://github.com/CodeByHashir/toolgate`.

1. Write a policy, e.g. `fetch.yaml`, starting from one of the examples:

   ```yaml
   tool_calls:
     default: block
     rules:
       fetch.fetch:
         egress: ["docs.python.org", "api.internal.example:8443"]
   ```

2. Put `toolgate wrap` in front of the server, pinned to a version, in
   `.mcp.json`:

   ```json
   {
     "mcpServers": {
       "fetch": {
         "command": "uvx",
         "args": [
           "--from", "toolgate-mcp==0.1.0a1", "toolgate",
           "wrap", "--name", "fetch",
           "--config", "/absolute/path/to/fetch.yaml",
           "--", "uvx", "mcp-server-fetch==2026.8.18"
         ]
       }
     }
   }
   ```

   Pin the version: unpinned, a broken release could stop every wrapped
   server the next time the host starts. Upgrade by changing the version in
   the snippet.

3. `--name` becomes the `<server>` in rule keys (`fetch.fetch` is server
   `fetch`, tool `fetch`). The config comes from `--config` or
   `$TOOLGATE_CONFIG`, never from the working directory. In a policy file,
   `sandbox:`, `state_dir:` and `audit_path:` accept `~` and `${NAME}`;
   relative values are resolved against the config file.

To remove toolgate, delete everything up to and including the `--` from the
args. The snippet is written for Claude Code, the host the demo targets, and
Claude Code has run through `toolgate wrap` end to end in the recorded demo
below (headless, with an MCP config file of this shape and the source-tree
toolgate rather than the PyPI package). Claude Desktop and Cursor snippets
will be added once each has been run, and are not listed until then.

**Exit codes**: `0` the host closed the session; `1` config missing or
invalid, server never started (the reason is on stderr); `2` the server
failed to start or exited first; `3` internal error, including ten audit-log
write failures in a row.

**See what was blocked.** Each wrapped server writes its own SQLite log; the
path is in the startup line. Rows hold rule ids, hashes and timings, never
arguments or results:

```bash
sqlite3 "<state_dir>/audit/fetch.sqlite" "SELECT timestamp, tool_name, note FROM decision_log WHERE fused_decision = 'block' ORDER BY id DESC LIMIT 20"
```

Each direction is processed one line at a time, in order. Measured on the
Windows dev machine with the egress rule, `rules_mcp` and `pii` enabled
([`docs/PROXY-LATENCY.md`](docs/PROXY-LATENCY.md)): the proxy adds 1.7 ms at
p99 to a call with a 1 KB result, and about 52 ms at p99 with a 100 KB result.
Almost all of the second figure is the two detectors scanning 100 KB; a
policy without redaction or injection detectors does not pay it. The
transformer detectors, if you opt in, add around 170 ms each.

### The demo: cross-server exfiltration, toolgate off and on

Two real servers: `filesystem` scoped to a demo project whose `.env` holds a
canary token, and `fetch`. A local page carries an indirect injection: read
`.env`, then fetch an attacker URL with its contents. A scripted client makes
exactly those calls; no model is involved, so this proves what the proxy
does, not what a model would do. Recorded on the Windows dev machine with the
pinned servers ([`tests/test_demo_fixtures.py`](tests/test_demo_fixtures.py),
[`tests/test_proxy_e2e.py`](tests/test_proxy_e2e.py)):

| Second call | toolgate off | toolgate on (`egress: ["localhost:<page port>"]`) |
|---|---|---|
| `http://127.0.0.1:<attacker>/?d=<.env>` | canary reaches the listener | refused, `fetch.fetch.egress`; listener receives nothing |
| `http://127.0.0.1:<attacker>\@localhost:<page>/?d=...` | canary reaches the listener | refused; listener receives nothing |
| `http://localhost:<attacker port>/?d=...` | canary reaches the listener | refused (port not allowed); listener receives nothing |
| allowed page that answers 302 to the attacker | canary reaches the listener | **canary still reaches the listener** with `network: off` (the default); refused by the proxy with `network: enforce`, listener receives nothing |

The reads and the allowed page fetch work the same with toolgate on, and
every line toolgate does not need to change is forwarded byte-for-byte: a
session through `@modelcontextprotocol/server-everything`, covering sampling,
elicitation, roots, resources, prompts, logging and progress, is compared as
raw bytes in both directions
([`tests/test_proxy_transparency.py`](tests/test_proxy_transparency.py)).
**A real agent, once each way** ([`docs/AGENT-DEMO.md`](docs/AGENT-DEMO.md)):
Claude Code with Sonnet 5.5, given only the two servers and the task
"summarise the page", recognised the injection and declined it in both the
toolgate-off and the toolgate-on run. So that recording does not show toolgate
stopping anything; the model never made the call. It does show a real host
session working through `toolgate wrap`. Two single runs, not a rate.

## The third channel: tool declarations

Capability rules cover what the agent does. They say nothing about the
configuration it is handed before it does anything.

When an agent connects to an MCP server it performs a `tools/list` handshake.
The returned name, description and JSON schema go straight into the model's
context as tool definitions. The server controls that text, it arrives framed
as trusted configuration rather than data, and it stays in context for the
whole session. That makes it a better-placed injection surface than a tool
result, and until recently this project didn't look at it.

```yaml
# config/policy.yaml — ships absent, so the layer is off
tool_declarations:
  default:
    mutated:   escalate   # the pinned bytes changed after you trusted them
    concealed: escalate   # non-rendering characters in a field
    shadowed:  escalate   # another server already declares this name
  on_pin_error: block     # unreadable pin store -> withhold that server
```

Declarations are hashed per field on first sight (`pins/<server>.json`, digests
only, never content) and re-checked on every listing. A change names the field
that moved. A declaration the policy refuses is dropped from the list handed to
the model, so the poisoned text never reaches it.

**The claim is narrower than it sounds.** Pinning cannot tell you a server is
malicious. A server that ships a poisoned description at install time is pinned
as faithfully as an honest one. It tells you a server changed after you trusted
it, and only that claim is made. Concealment is the one exception, because
non-rendering characters are a property of a single declaration, not of a
change.

### Is it deployable?

A control that fires on every routine upstream release is one an operator
switches off. Nobody had published how often real MCP servers change a
declaration, so the defaults above started as a guess. Now they are measured:
54 releases of 7 official servers, each installed and launched for real
([`docs/DECLARATION-CHURN.md`](docs/DECLARATION-CHURN.md), 2026-09-23).

| Measurement | Result |
|---|---|
| Release transitions that changed no declaration | 30 of 47 |
| Transitions that changed every tool at once | 17 of 47 |
| Anything in between | none |
| Tool comparisons where `description` changed | 9 of 318 (2.8%) |
| Declarations carrying non-rendering characters | 0 of 380 |
| Cross-server tool-name collisions | 0 |
| Benign descriptions firing the project's own injection rules | 4 of 380 (1.1%) |

The distribution is bimodal with nothing between the modes. A release either
leaves declarations alone or rewrites all of them, which looks like an SDK
metadata bump rather than an author editing a tool. So pinning stays silent
through roughly two thirds of upgrades, and when it does fire it fires on
everything, which is easy to triage. The pooled 35% "churn rate" is the wrong
statistic, and the document says so.

The last row is a false-positive rate, not a recall figure. These are official
reference servers and nobody is attacking them, so every hit is a false alarm.
All four came from `INJ-*`, the rule family this project already measured at
0/187 on real attacks.

No number here is a detection result. Pinning catches post-approval mutation by
construction, since hashes detect hash changes. Printing that next to a
measured AUROC would be the kind of rigor slippage the rest of this repository
exists to avoid.

### Against a published attack catalogue — including what it misses

[arXiv:2607.05744](https://arxiv.org/abs/2607.05744) implements eight
tool-metadata techniques and reports that a representative string-matching
sanitizer catches four of them. Here are the same eight run against toolgate's
shipped layers:

| | Technique | Surface | Paper's baseline sanitizer | toolgate, first sight | toolgate, if it arrives as a change |
|---|---|---|---|---|---|
| T1 | Direct description injection | description | caught | not flagged | flagged — `mutated: description` |
| T2 | Cross-tool shadowing | description | caught | not flagged | flagged — `mutated: description` |
| T3 | Rug-pull | re-`tools/list` | caught | — | flagged — `mutated: description` |
| T4 | Confused-deputy credential relay | schema parameter | missed | not flagged | flagged — `mutated: input_schema` |
| T5 | Error-channel injection | `isError` result | caught | **missed** | n/a — a result, not a declaration |
| T6 | Namespace collision | tool name | missed | flagged vs another MCP server; **invisible** vs a host built-in | same |
| T7 | TAG-block concealment | description | missed | **flagged** — `concealed` | flagged |
| T8 | Dangerous-default coercion | schema `default`/`enum` | missed | not flagged | flagged — `mutated: input_schema` |

On first sight toolgate flags 1 of 8 outright, and the paper's baseline catches
4 of 8. That comparison is not flattering, but the two catch different
techniques. The baseline catches the plain-text payloads toolgate passes on
first sight. Toolgate flags T7, which the paper shows is the only technique that
gets past both the sanitizer and a human reviewer. They complement each other.
T6 is flagged only when the colliding name belongs to another connected server,
because toolgate has no list of the host's built-in tools, which is what the
paper's T6 actually shadows.

After approval, every declaration payload is flagged by construction. That
includes T4 and T8, which carry no imperative for a keyword sanitizer to find.
Pinning does not care what a change says. No rate is attached to that, for the
reason given above.

T5 is a straight loss. It travels the tool-result path, where the shipped
detectors let the payload through with nothing firing, while the baseline
catches it. That fits the ~20% recall measured in `docs/REPORT.md`.

The table has three limits. The payloads are rebuilt from the paper's
descriptions rather than copied, one per technique, so each row is a spot check
and not a rate; a different phrasing of T5 could fire. Flagged is not withheld:
the shipped defaults escalate, which logs the verdict and forwards the
declaration, and withholding takes an explicit `block`. And the baseline column
is quoted from the paper's Table 5, not re-run. Every toolgate cell is an
assertion in [`tests/test_paper_techniques.py`](tests/test_paper_techniques.py).

## Coverage: all three channels at the MCP boundary

| Channel | Direction | Mechanism | Guarantee |
|---|---|---|---|
| Tool **results** | server → client | Detection (six detectors, fused) | None. ~20% recall, measured and published |
| Tool **calls** | client → server | Capability rules, in-process or via `toolgate wrap` | No false-negative rate against the behaviour a rule names |
| Tool **declarations** | server → client | Per-field integrity pinning | Detects post-approval change, by construction. Says nothing about first sight |

Two of the three need no classifier, which is the whole argument. Where
detection was measured and failed, the control moved to something
deterministic. Both deterministic layers ship off, so adding them changed
nothing for anyone who has not opted in.

## Why the 512-token window matters

The reused V3 transformer has a 512-token window. User prompts fit inside it.
Tool results routinely don't: a file read or web fetch is often 10 to 100 times
that. An injection planted past token 512 of a long file is invisible to a
truncating detector, not because the detector is weak but because it never sees
the text. This project implements both a truncating and a chunking scorer and
reports the gap between them as a first-class result.

## Install

Requires Python 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev --extra research
```

The `research` extra holds what reproducing the measurements needs: numpy,
scipy, scikit-learn, PyTorch, transformers, statsmodels, datasketch and the
Anthropic SDK. Every command from here on (`verify-models`, `corpus-ingest`,
`gauge-run`, `gauge-recut`, `run-agent` and the scripts under `scripts/`)
needs it; the `toolgate` subcommands say so if it is missing. Without it,
`uv sync --extra dev` installs the gating layer and the dev tools only, which
is how the slim CI job runs the gating tests. `toolgate wrap` needs nothing
beyond the base install, which is `mcp`, `pydantic`, `pyyaml`, `anyio` and
`platformdirs`; a test checks that importing it loads none of the research
stack.

## Detector artifacts

| | Model | Classes | Token limit | Available to you? |
|---|---|---|---|---|
| **V0** | TF-IDF (word 1–2 + char_wb 3–5) + logistic regression | 4 | none | No. Reused, unpublishable |
| **V3** | DeBERTa-v3-base sequence classifier | 4 | 512 | No. Reused, unpublishable |
| **`guard`** | [ProtectAI `deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | 2 | 512 | Yes. Apache-2.0, fetched from the Hub |

V0 and V3 are reused from prior work by the same author and are not retrained.
Both classify over `(benign, injection, jailbreak, harmful)`. They were trained
for the user-prompt surface, which is exactly what this project set out to test.
`guard` is a published binary `(SAFE, INJECTION)` classifier pinned by commit
SHA in `config/models.yaml`. It was added so that at least one measured
classifier is one a reader can rerun. See `docs/REPORT.md` section 4 for how it
scored. It is included for verifiability, not because it works.

The V0/V3 trained weights are not distributed with this repository and are not
publishable. `config/models.yaml` defaults to a repository-relative `models/`
directory, which is gitignored. Copy, symlink or junction your artifacts there,
or point `TOOLGATE_MODELS_ROOT` at wherever they live:

```bash
# Windows (no admin needed)
New-Item -ItemType Junction -Path .\models -Target C:\path\to\artifacts
```

```bash
# macOS / Linux
ln -s /path/to/artifacts ./models
```

See [docs/PINNING.md](docs/PINNING.md) for why the scikit-learn and transformers
versions are pinned exactly, and how the statistical claims stay reproducible
without the weights.

## Verify the reuse audit

```bash
uv run toolgate verify-models
```

Loads V0 and V3 on CPU, scores a small set of probe texts, and prints per-class
probabilities and latency. The final rows contrast the `truncate` and
`chunk_max` strategies on an over-length input, which shows the 512-token
problem most clearly.

Probe texts are a smoke test, not an evaluation. Don't draw conclusions from
them.

## Build the corpus

```bash
uv run toolgate corpus-ingest
```

Fetches three independent adversarial source families (BIPIA, InjecAgent and
LLMail-Inject, all MIT), pulls benign reference lines from this repository's own
content, and decontaminates every item against the ~19,000-row corpus V0/V3 were
actually trained on. The result is stored in `corpus/payload_corpus.sqlite`,
which is gitignored because it can be regenerated. It prints a drop-count
report: how many items per source were flagged as near-duplicates of training
data.

## Run the evaluation

```bash
uv run toolgate gauge-run                # calibrate V0/V3, matched-FPR ASR + AUROC
uv run python scripts/benchmark_rules.py   # rule recall vs BIPIA + InjecAgent
uv run python scripts/benchmark_latency.py # per-detector + fused latency
uv run python scripts/generate_report.py   # regenerate docs/figures/*.svg
uv run toolgate gauge-recut              # re-derive AUROC from scores.csv, no weights needed
```

`gauge-recut` is the falsification check for the headline. It needs no model
weights and no corpus, only the committed
[`results/gauge/scores.csv`](results/gauge/scores.csv). A DeLong AUROC below 0.5
has two possible explanations: the detector really is anti-correlated on this
surface, or the wrong scalar is being cut out of its four-class probability
vector. `scores.csv` stores all four class probabilities so anyone can test the
second, and `gauge-recut` re-derives the AUROC under every score mode from the
same stored inference.

It found a real problem. V3's published below-chance figure comes from the
`injection` cut V3 was originally scored with (0.325). Under `not_benign` the
same probabilities give 0.540, an interval straddling chance. So V3 is not
reliably anti-correlated; it just doesn't separate, and how bad it looks depends
on the cut. `docs/REPORT.md` section 4 carries the full table and the
correction. Run this before quoting any AUROC from that section.

`gauge-run` needs a corpus already produced by `corpus-ingest`, plus the real
reused weights (like `benchmark_latency.py`). `benchmark_rules.py` only
exercises the rule engine and needs neither. `gauge-run` never edits
`config/policy.yaml`. Reviewing its report and deciding whether to promote V0/V3
out of `inert` is a deliberate step for a human. See
[`docs/REPORT.md`](docs/REPORT.md) for the numbers these produced and
[`docs/LATENCY-BENCHMARK.md`](docs/LATENCY-BENCHMARK.md) for the full latency
breakdown.

## Test

```bash
uv run pytest              # contract tests, no weights needed
uv run pytest -m models    # reuse audit, requires the local artifacts
```

## Reproduce the declaration-churn snapshot

```bash
uv run python scripts/collect_declarations.py --collect   # installs and launches real servers
uv run python scripts/collect_declarations.py --report    # renders docs/DECLARATION-CHURN.md
```

`--collect` walks each server's release history on npm and PyPI, launches every
version over stdio and records what its real `tools/list` sends back. It needs
network, `npx` and `uvx`, and takes several minutes. It overwrites the committed
snapshot and therefore every figure in the document, which is why the snapshot
is dated and frozen rather than refreshed on a schedule.

The snapshot stores digests, tool names and pre-computed metrics, with no
description and no schema, so it neither leaks nor redistributes anything a
server sent.

## Record a tool-call chain

```bash
uv run toolgate run-agent --servers filesystem,fetch --out chains/baseline.json
```

Launches both reference MCP servers, drives them with a Claude tool-use loop,
and records every call and result to a JSON fixture. The evaluation then runs
offline against that recording, so API spend is a one-off and doesn't scale with
the corpus.

Gating is on by default and is independent of logging. `--db` persists the
decision log to SQLite; without it the log is in-memory and discarded, but the
gate still runs. `--no-gate` disables interception entirely and prints a warning
saying so, because `--out` then records raw, unredacted tool output to disk.

Four policy profiles ship. The three detector profiles cannot change any
decision. `PolicyEngine.decide()` never reads a detector that appears only under
`inert`, so they change what is scored, logged and paid for, never the
Allow/Redact/Block/Escalate outcome. A test asserts this.

`policy.agent.yaml` is the deliberate exception. It adds a request-side
capability control, which is the one thing here meant to change what happens.
Its detector roles are still identical to the default.

| Profile | Adds | Cost / result | Runnable after a plain clone? |
|---|---|---|---|
| `config/policy.yaml` (default) | rules + PII | 0.08 ms | Yes |
| `config/policy.agent.yaml` | capability gating of tool calls | 0.08 ms | Yes |
| `config/policy.guard.yaml` | `guard` | 170 ms | Yes (downloads ~700 MB once) |
| `config/policy.research.yaml` | `v0`, `v3`, `guard` | 345 ms | No, needs the unpublishable weights |

```bash
uv run toolgate run-agent --db logs/decisions.sqlite                       # default
uv run toolgate run-agent --policy config/policy.guard.yaml --db logs/d.sqlite
```

`policy.guard.yaml` exists because it is the only ML profile a stranger can run.
V0 and V3 need artifacts only the author has. Read `docs/REPORT.md` section 4
before using it: `guard` measured AUROC 0.524 on this surface, and it ships
`inert` for the same reason everything else does.

Chains that feed the evaluation use the default model. For cheap smoke runs:

```bash
uv run toolgate run-agent --model claude-haiku-4-5 --servers filesystem
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
`tests/test_chain_licensing.py` now stops another from being committed.
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) records that decision, the
fetched-corpus licences, and why the reused model weights aren't distributed.
