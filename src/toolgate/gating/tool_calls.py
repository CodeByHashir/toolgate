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
  Entries are `host`, `host:port` or `host:*`; a bare host means the scheme's
  default port only. A URL is read strictly (`parse_destination`) and anything
  two parsers could read differently is refused rather than interpreted.

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
import functools
import ipaddress
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from toolgate.config import SANDBOX_PLACEHOLDER

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
    read stream -- would need a pump task and a shared queue, which was rejected
    for good reasons that still hold.

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

    def with_sandbox(self, sandbox: Path) -> ToolCallPolicy:
        """Expand `{sandbox}` in every `paths` glob to the sandbox's real path.

        The filesystem server is rooted at an absolute directory and tells the
        model so, so real calls carry absolute paths. A relative glob such as
        `sandbox/**` never matches those, and refused every legitimate read in
        a live run. `{sandbox}/**` is the form that does. An unexpanded
        placeholder matches nothing, so a policy used without this call stays
        fail-closed.
        """
        root = _normalise_path(str(sandbox))[0]
        rules = {
            key: replace(
                rule,
                paths=tuple(p.replace(SANDBOX_PLACEHOLDER, root) for p in rule.paths),
            )
            if rule.paths is not None
            else rule
            for key, rule in self.rules.items()
        }
        return replace(self, rules=rules)


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


#: Ports a bare allowlist entry stands for. Only these two schemes are ever
#: allowed through an egress rule, so the table is also the scheme allowlist.
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

_SCHEME_AUTHORITY_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
#: A last label a WHATWG parser would read as the start of an IPv4 number
#: (decimal, or `0x` hex). See `_normalise_host`.
_NUMERIC_LABEL_RE = re.compile(r"(?:[0-9]+|0x[0-9a-f]*)\Z")
_PORT_RE = re.compile(r"[0-9]{1,5}\Z")


def _is_plain_ascii(value: str) -> bool:
    """True when every character is printable ASCII other than space and `\\`.

    That excludes, in one rule, every character the parser-differential
    bypasses in this module's history depend on: `\\` (which `urlparse` treats
    as ordinary but WHATWG clients treat as `/`), whitespace and control
    characters (which WHATWG clients strip or skip), and non-ASCII (which they
    IDNA-map, so the host connected to is not the host compared). An IDN must
    reach the allowlist as punycode.
    """
    return all("\x21" <= ch <= "\x7e" and ch != "\\" for ch in value)


def _normalise_host(text: str) -> str | None:
    """Return the canonical form of one host, or None when it is not one.

    Canonical means: lowercased, one trailing dot removed (`github.com.` is
    the same DNS name), IPv6 literals bracketed and compressed (`[::1]`), and
    IPv4 literals only in their canonical dotted-quad spelling.

    The IPv4 rule is the important one. A WHATWG parser reads any host whose
    last label is numeric as an IPv4 number, so `2130706433`, `127.1`,
    `0x7f.0.0.1` and `0177.0.0.1` all connect to 127.0.0.1. Rather than
    reimplement that parser and hope to agree with it, every such host is
    refused unless it is already the canonical dotted quad, so no spelling can
    alias an address the allowlist names differently.
    """
    if text.startswith("["):
        if not text.endswith("]") or "%" in text:
            # `%` is an IPv6 zone id: link-local, interface-specific, and not
            # something a policy can meaningfully name.
            return None
        try:
            return f"[{ipaddress.IPv6Address(text[1:-1]).compressed}]"
        except ValueError:
            return None

    host = text.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        return None
    labels = host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        return None
    if _NUMERIC_LABEL_RE.match(labels[-1]):
        try:
            canonical = str(ipaddress.IPv4Address(host))
        except ValueError:
            return None
        return host if canonical == host else None
    return host


def _is_ip_literal(host: str) -> bool:
    return host.startswith("[") or _NUMERIC_LABEL_RE.match(host.rsplit(".", 1)[-1]) is not None


def _split_authority(authority: str) -> tuple[str, str | None] | None:
    """Split `host[:port]`. Returns (host, port text or None), or None if malformed."""
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host, rest = authority[: close + 1], authority[close + 1 :]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            return None
        port = rest[1:]
    else:
        if authority.count(":") > 1:
            # An unbracketed IPv6 literal, or junk. Either way, not a host.
            return None
        host, sep, port = authority.partition(":")
        if not sep:
            return host, None
    if not port:
        # `host:` is a valid URL meaning the default port, and an equally
        # valid way to make two parsers disagree. Neither direction needs it.
        return None
    return host, port


def _parse_port(text: str) -> int | None:
    if not _PORT_RE.match(text):
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


@dataclass(frozen=True, slots=True)
class Destination:
    """Where an HTTP client would connect for one URL argument."""

    scheme: str
    host: str
    port: int


def parse_destination(value: Any) -> Destination | None:
    """Read one URL argument strictly. None means "refuse it".

    The guarantee this layer makes is about the host a real client connects
    to, so the parse is built to agree with a WHATWG client (Node's fetch,
    `httpx` in `mcp-server-fetch`) on every URL it accepts, and to refuse
    everything else rather than guess. `urllib.parse.urlparse` is not used:
    it disagrees with WHATWG clients on `\\`, which is exactly how
    `http://evil.com\\@github.com/x` passed a `github.com` allowlist while the
    fetch server, probed on 2026-10-03, connected to `evil.com`.

    Accepted: a string holding an absolute `http` or `https` URL, written
    `scheme://host[:port]` followed by `/`, `?`, `#` or the end, with no
    userinfo, no `\\`, nothing outside printable ASCII, a valid hostname or IP
    literal (`_normalise_host`), and a decimal port from 1 to 65535.

    Refused, among others: no scheme (`evil.test/x`), scheme-relative
    (`//evil.test`), the slash-repairing forms WHATWG accepts for special
    schemes (`http:evil.test`, `http:///evil.test`), other schemes (`file:`,
    `ftp:`, `data:`, `ws:`), empty strings, and non-string values.
    """
    if not isinstance(value, str) or not _is_plain_ascii(value):
        return None
    match = _SCHEME_AUTHORITY_RE.match(value)
    if match is None:
        return None
    scheme = match.group(1).lower()
    if scheme not in DEFAULT_PORTS:
        return None
    authority = match.group(2)
    if "@" in authority:
        # Userinfo is never needed to name a destination and is the classic
        # way to make a URL read as one host to a person and another to a
        # parser. Refused outright, whatever host follows it.
        return None
    split = _split_authority(authority)
    if split is None:
        return None
    host = _normalise_host(split[0])
    if host is None:
        return None
    port = DEFAULT_PORTS[scheme] if split[1] is None else _parse_port(split[1])
    if port is None:
        return None
    return Destination(scheme=scheme, host=host, port=port)


#: Sentinel for a `host:*` entry.
ANY_PORT: Final = -1


@dataclass(frozen=True, slots=True)
class EgressEntry:
    """One parsed allowlist entry.

    `host` is `"*"` (any host), `"*.<suffix>"` (any host with at least one
    label in front of `suffix`, matched on label boundaries) or one canonical
    host. `port` is None (the URL scheme's default port only), `ANY_PORT`, or
    one port number.
    """

    host: str
    port: int | None

    def matches(self, destination: Destination) -> bool:
        if self.port is None:
            if destination.port != DEFAULT_PORTS[destination.scheme]:
                return False
        elif self.port != ANY_PORT and self.port != destination.port:
            return False
        if self.host == "*":
            return True
        if self.host.startswith("*."):
            suffix = self.host[1:]  # keeps the leading dot: a label boundary
            return not _is_ip_literal(destination.host) and destination.host.endswith(suffix)
        return self.host == destination.host


def parse_egress_entry(entry: str) -> EgressEntry:
    """Parse one allowlist entry, or raise ValueError saying what is wrong.

    Forms: `host`, `host:port`, `host:*`, where `host` is a hostname, an IP
    literal (`127.0.0.1`, `[::1]`), `*.suffix`, or `*`. A bare host means the
    scheme's default port, so `example.com` allows `https://example.com` and
    `https://example.com:443` but not `https://example.com:8443` (design D6,
    D15). A `*` anywhere else is refused: these are host names compared by
    label, not glob patterns, because `fnmatch`'s `*` also matched `\\` and let
    `http://evil.com\\.github.com/x` through a `*.github.com` entry.
    """
    if not isinstance(entry, str) or not entry:
        raise ValueError("an egress entry must be a non-empty string")
    if not _is_plain_ascii(entry) or "/" in entry or "@" in entry:
        raise ValueError(
            f"egress entry {entry!r} must be a bare host such as 'example.com', "
            "'example.com:8080' or '*.example.com' (no scheme, path, userinfo, "
            "spaces or non-ASCII; write an IDN as punycode)"
        )
    split = _split_authority(entry)
    if split is None:
        raise ValueError(f"egress entry {entry!r} has a malformed host or port")
    host_text, port_text = split

    port: int | None
    if port_text is None:
        port = None
    elif port_text == "*":
        port = ANY_PORT
    else:
        port = _parse_port(port_text)
        if port is None:
            raise ValueError(f"egress entry {entry!r}: the port must be 1-65535 or '*'")

    if host_text == "*":
        return EgressEntry(host="*", port=port)
    if host_text.startswith("*."):
        suffix = _normalise_host(host_text[2:])
        if suffix is None or "*" in host_text[2:] or _is_ip_literal(suffix):
            raise ValueError(f"egress entry {entry!r}: '*.' must be followed by a hostname")
        return EgressEntry(host=f"*.{suffix}", port=port)
    if "*" in host_text:
        raise ValueError(
            f"egress entry {entry!r}: '*' is only allowed as the whole host or as "
            "a leading '*.' label"
        )
    host = _normalise_host(host_text)
    if host is None:
        raise ValueError(f"egress entry {entry!r} is not a valid hostname or IP literal")
    return EgressEntry(host=host, port=port)


@functools.lru_cache(maxsize=1024)
def _cached_entry(entry: str) -> EgressEntry | None:
    try:
        return parse_egress_entry(entry)
    except ValueError:
        return None


def _host_allowed(value: Any, entries: tuple[str, ...]) -> bool:
    """True when `value` is a URL whose destination an entry allows.

    Entries are validated when the policy loads; one that is malformed anyway
    (a `ToolRule` built by hand) matches nothing, so the failure is closed.
    """
    destination = parse_destination(value)
    if destination is None:
        # A URL argument we cannot read a destination from is not something
        # to wave through on an egress-restricted tool.
        return False
    for entry in entries:
        parsed = _cached_entry(entry)
        if parsed is not None and parsed.matches(destination):
            return True
    return False


def _url_values(arguments: Any, names: frozenset[str]) -> list[Any]:
    """Collect every value under a URL argument name, whatever its type.

    Unlike `_string_values`, non-strings are kept: a URL argument holding a
    number, an object or `null` is refused by `parse_destination` rather than
    skipped, because skipping it is how an unexpected shape would pass an
    egress rule unchecked (design R2-4).
    """
    if not isinstance(arguments, dict):
        return []
    out: list[Any] = []
    for key, value in arguments.items():
        if key not in names:
            continue
        if isinstance(value, list):
            out.extend(value)
        else:
            out.append(value)
    return out


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
        for value in _url_values(arguments, URL_ARGUMENT_NAMES):
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

        egress = _globs("egress")
        for entry in egress or ():
            try:
                parse_egress_entry(entry)
            except ValueError as exc:
                raise ValueError(f"{where}.egress: {exc}") from exc

        rules[str(key)] = ToolRule(action=action, paths=_globs("paths"), egress=egress)

    return ToolCallPolicy(default=default, rules=rules)


__all__ = [
    "ANY_PORT",
    "DEFAULT_PORTS",
    "PATH_ARGUMENT_NAMES",
    "URL_ARGUMENT_NAMES",
    "Destination",
    "EgressEntry",
    "ToolCallBlocked",
    "ToolCallPolicy",
    "ToolDecision",
    "ToolRule",
    "ToolVerdict",
    "evaluate_tool_call",
    "load_tool_call_policy",
    "parse_destination",
    "parse_egress_entry",
]
