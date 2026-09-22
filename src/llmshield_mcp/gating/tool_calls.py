"""Capability gating for outbound `tools/call` requests.

Every other detector in this project inspects *content* and asks "does this look
like an attack?". `docs/REPORT.md` measures how well that works on the MCP
tool-result surface: the best detector reaches ~20% recall, the reused
transformer does not separate at all, and a purpose-built production classifier
is statistically indistinguishable from chance. Four attacks in five get
through.

This module asks a different question, and it is the direct engineering
consequence of that finding: **not "is this text malicious?" but "is the agent
allowed to do this?"**

The distinction matters because the second question needs no classifier. You do
not have to recognise the injection that talked an agent into reading
`~/.ssh/id_rsa` in order to notice that the agent is reading outside its
sandbox. Recognising the persuasion is unsolved semantics -- this project
measured that. Recognising the capability is a string comparison.

## What that buys, stated precisely

A capability rule has no false-negative rate *against the behaviour it names*:
if `filesystem.read_text_file` is confined to `./workspace/**`, a read of
`/etc/passwd` is refused whatever prose talked the model into attempting it,
through any injection technique, in any language, at any dilution. That is a
real guarantee and it is the reason this layer exists.

It is emphatically **not** a guarantee that the agent is safe. It bounds the
blast radius of a successful injection to whatever the policy still permits. An
attacker who only needs a tool the policy allows is unaffected. This layer
narrows what a compromised agent can reach; it does not stop the compromise.

## Three checks, chosen from the corpus rather than invented

Each maps to an attacker objective that actually appears in the BIPIA and
InjecAgent payloads this project already ingests:

* `action` -- flat verdict for a tool that should never run (destructive
  operations: delete a repository, drop a table, send mail).
* `paths` -- glob allowlist for path-like arguments (sandbox escape).
* `egress` -- host allowlist for URL-like arguments (exfiltration: the payload
  tells the agent to fetch an attacker-controlled URL with data in the query).

Deliberately not included: regex matching on argument *values*. That would
reintroduce content inspection through the back door, with the same false
positives, and this module's whole claim is that it does not do that.

## Defaults

`default: allow` ships, so adding this layer breaks nothing and a user opts in
per tool. That is a considered choice, not laziness: `config/policy.yaml`'s own
header records the lesson that a safe default which is expensive or disruptive
is a default people switch off. `default: block` turns the same config into an
allowlist and is one word away; `docs/REPORT.md` reports what each mode catches
rather than asserting which is correct.

## What reaches the audit log

The rule id and tool name, never argument values. A path or URL argument can
carry exactly the sensitive data the rest of this project refuses to store
(SEC-3, NFR-4), so a blocked call records *that* it was blocked and *which rule*
fired -- not the string that triggered it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

#: Argument names treated as filesystem paths. Drawn from the reference
#: servers' own schemas (`@modelcontextprotocol/server-filesystem`) rather than
#: guessed; an unknown server using a different name is simply not path-checked,
#: which is a visible gap rather than a silent mismatch.
PATH_ARGUMENT_NAMES: frozenset[str] = frozenset({"path", "paths", "source", "destination"})

#: Argument names treated as URLs, from `mcp-server-fetch`.
URL_ARGUMENT_NAMES: frozenset[str] = frozenset({"url", "uri"})


class ToolDecision(StrEnum):
    """What the capability layer says about one `tools/call`."""

    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


class ToolCallBlocked(RuntimeError):
    """Raised in place of sending a `tools/call` the policy refuses.

    Raising from the write stream rather than injecting a synthetic error
    response is deliberate. The MCP dispatcher registers its pending waiter
    before the write and pops it in a `finally` on every path
    (`mcp/shared/jsonrpc_dispatcher.py`), so an exception from `send()` cleans
    up correctly and surfaces to whoever called `session.call_tool()`. The
    alternative -- fabricating a JSON-RPC error and pushing it back through the
    read stream -- would need a pump task and a shared queue, which `plan.md`
    2.8 rejected for good reasons that still hold.

    It also reads more honestly: the call did not fail, it was refused.
    """

    def __init__(self, tool: str, rule: str, reason: str) -> None:
        self.tool = tool
        self.rule = rule
        self.reason = reason
        super().__init__(f"tool call {tool!r} blocked by {rule}: {reason}")


@dataclass(frozen=True, slots=True)
class ToolRule:
    """One tool's capability constraints."""

    #: Flat verdict, applied before the argument checks.
    action: ToolDecision = ToolDecision.ALLOW
    #: Glob allowlist for path-like arguments. None means "not path-checked".
    paths: tuple[str, ...] | None = None
    #: Host allowlist for URL-like arguments. None means "not egress-checked".
    egress: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class ToolCallPolicy:
    """The `tool_calls` block of a policy file."""

    #: Verdict for a tool no rule names. `block` makes this an allowlist.
    default: ToolDecision = ToolDecision.ALLOW
    #: Keyed `"<server>.<tool>"`, e.g. `"filesystem.read_text_file"`.
    rules: dict[str, ToolRule] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        """False when no rule names anything and the default allows.

        Lets the `Gate` skip the check entirely for the shipped configuration,
        so a project that never opts in pays nothing.
        """
        return bool(self.rules) or self.default is not ToolDecision.ALLOW


@dataclass(frozen=True, slots=True)
class ToolVerdict:
    decision: ToolDecision
    #: Which rule produced it, for the audit row. Never an argument value.
    rule: str
    reason: str

    @property
    def blocked(self) -> bool:
        return self.decision is ToolDecision.BLOCK


def _normalise_path(value: str) -> tuple[str, bool]:
    """Collapse separators and resolve `..` textually. Returns (path, escaped).

    Textual rather than `Path.resolve()` on purpose: resolving would follow
    symlinks and consult the filesystem, making the verdict depend on machine
    state and turning a policy check into I/O. `../` traversal is the attack
    being normalised away, and it is a string operation.

    `escaped` is True when a `..` had nowhere left to pop, i.e. the path tried
    to climb above its own root. That is reported separately rather than
    silently clamped: `../../etc/passwd` would otherwise normalise to
    `etc/passwd` and could then match a permissive glob, which is precisely the
    bypass this function exists to prevent.
    """
    cleaned = value.replace("\\", "/")
    parts: list[str] = []
    escaped = False
    for part in cleaned.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            else:
                escaped = True
            continue
        parts.append(part)
    prefix = "/" if cleaned.startswith("/") else ""
    return prefix + "/".join(parts), escaped


def _matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def _path_allowed(value: str, patterns: tuple[str, ...]) -> bool:
    """Match the NORMALISED path only.

    An earlier version also tried the raw string, which defeated the whole
    point: `fnmatch`'s `*` matches `/`, so `workspace/../../.ssh/id_rsa`
    matched `workspace/**` verbatim and a sandbox escape was allowed through.
    Caught by a smoke test before this shipped; the regression is pinned in
    `tests/test_tool_calls.py`.
    """
    normalised, escaped = _normalise_path(value)
    if escaped:
        return False
    return _matches_any(normalised, patterns)


def _host_allowed(value: str, patterns: tuple[str, ...]) -> bool:
    host = (urlparse(value).hostname or "").lower()
    if not host:
        # A URL argument we cannot parse a host from is not something to wave
        # through on an egress-restricted tool.
        return False
    return _matches_any(host, patterns)


def _string_values(arguments: Any, names: frozenset[str]) -> list[str]:
    """Collect string argument values whose key is in `names`.

    Handles a list value (`paths: [...]`) as well as a scalar, because the
    filesystem server's own schema uses both.
    """
    if not isinstance(arguments, dict):
        return []
    out: list[str] = []
    for key, value in arguments.items():
        if key not in names:
            continue
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(item for item in value if isinstance(item, str))
    return out


def evaluate_tool_call(
    policy: ToolCallPolicy, server: str, tool: str, arguments: Any
) -> ToolVerdict:
    """Decide whether one `tools/call` may proceed.

    Pure: no I/O, no clock, no state. The same call always gets the same
    verdict, which is what makes this layer's guarantee checkable by reading
    the policy file rather than by running a benchmark.
    """
    key = f"{server}.{tool}"
    rule = policy.rules.get(key)

    if rule is None:
        if policy.default is ToolDecision.ALLOW:
            return ToolVerdict(ToolDecision.ALLOW, rule="default", reason="no rule; default allow")
        return ToolVerdict(
            policy.default,
            rule="default",
            reason=f"no rule for {key!r} and default is {policy.default.value}",
        )

    if rule.action is not ToolDecision.ALLOW:
        return ToolVerdict(
            rule.action,
            rule=f"{key}.action",
            reason=f"tool is configured {rule.action.value}",
        )

    if rule.paths is not None:
        for value in _string_values(arguments, PATH_ARGUMENT_NAMES):
            if not _path_allowed(value, rule.paths):
                return ToolVerdict(
                    ToolDecision.BLOCK,
                    rule=f"{key}.paths",
                    # The offending value is deliberately absent: a path
                    # argument can carry exactly the sensitive data this
                    # project refuses to log (SEC-3).
                    reason="a path argument resolved outside the allowed globs",
                )

    if rule.egress is not None:
        for value in _string_values(arguments, URL_ARGUMENT_NAMES):
            if not _host_allowed(value, rule.egress):
                return ToolVerdict(
                    ToolDecision.BLOCK,
                    rule=f"{key}.egress",
                    reason="a URL argument targeted a host outside the allowed list",
                )

    return ToolVerdict(ToolDecision.ALLOW, rule=key, reason="all configured checks passed")


def load_tool_call_policy(raw: Any) -> ToolCallPolicy:
    """Parse and validate a policy file's `tool_calls` block.

    Strict, and at load time, for the same reason `load_policy_config` is: a
    typo in a capability rule is a silently weaker security posture, which is
    the worst way for a configuration error to present.
    """
    if raw is None:
        return ToolCallPolicy()
    if not isinstance(raw, dict):
        raise ValueError("tool_calls must be a mapping")

    default_raw = raw.get("default", "allow")
    try:
        default = ToolDecision(default_raw)
    except ValueError as exc:
        raise ValueError(
            f"tool_calls.default {default_raw!r} is not one of "
            f"{sorted(d.value for d in ToolDecision)}"
        ) from exc

    rules_raw = raw.get("rules") or {}
    if not isinstance(rules_raw, dict):
        raise ValueError("tool_calls.rules must be a mapping")

    rules: dict[str, ToolRule] = {}
    for key, entry in rules_raw.items():
        where = f"tool_calls.rules.{key}"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} must be a mapping")
        if "." not in str(key):
            raise ValueError(
                f"{where}: rule keys are '<server>.<tool>', e.g. 'filesystem.read_text_file'"
            )
        action_raw = entry.get("action", "allow")
        try:
            action = ToolDecision(action_raw)
        except ValueError as exc:
            raise ValueError(
                f"{where}.action {action_raw!r} is not one of "
                f"{sorted(d.value for d in ToolDecision)}"
            ) from exc

        def _globs(
            name: str, entry: dict[str, Any] = entry, where: str = where
        ) -> tuple[str, ...] | None:
            value = entry.get(name)
            if value is None:
                return None
            if isinstance(value, str) or not isinstance(value, list):
                raise ValueError(f"{where}.{name} must be a list of patterns")
            if not value:
                # An empty list reads as "allow nothing", which is almost
                # certainly a mistake rather than an intent; `action: block`
                # says that unambiguously.
                raise ValueError(
                    f"{where}.{name} is empty; use `action: block` to forbid the tool outright"
                )
            return tuple(str(v) for v in value)

        rules[str(key)] = ToolRule(action=action, paths=_globs("paths"), egress=_globs("egress"))

    return ToolCallPolicy(default=default, rules=rules)


__all__ = [
    "PATH_ARGUMENT_NAMES",
    "URL_ARGUMENT_NAMES",
    "ToolCallBlocked",
    "ToolCallPolicy",
    "ToolDecision",
    "ToolRule",
    "ToolVerdict",
    "evaluate_tool_call",
    "load_tool_call_policy",
]
