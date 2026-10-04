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
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from toolgate.config import SANDBOX_PLACEHOLDER

#: Default argument names treated as filesystem paths, for a rule with `paths`
#: and no `path_args`. Drawn from the reference servers' own schemas
#: (`@modelcontextprotocol/server-filesystem`) rather than guessed. When the
#: caller supplies the tool's declared schema (`evaluate_tool_call(schema=...)`,
#: the proxy), a string-capable argument under any *other* name makes the tool
#: unclassified and refused, so a server using `file` or `target` fails closed
#: instead of going unchecked.
PATH_ARGUMENT_NAMES: frozenset[str] = frozenset({"path", "paths", "source", "destination"})

#: Default argument names treated as URLs, for a rule with `egress` and no
#: `url_args`. `url` is `mcp-server-fetch`'s.
URL_ARGUMENT_NAMES: frozenset[str] = frozenset({"url", "uri", "href"})

#: JSON Schema types that cannot carry a string. A property whose schema is
#: exactly one of these needs no classification; everything else might.
_NON_STRING_TYPES: frozenset[str] = frozenset({"integer", "number", "boolean", "null"})

#: Keywords that make a schema something other than "exactly one plain type".
#: Their presence means the value could be a string, so it is unclassified.
_COMPOSITE_KEYWORDS: frozenset[str] = frozenset(
    {"anyOf", "oneOf", "allOf", "not", "if", "then", "else", "$ref", "$dynamicRef", "enum", "const"}
)

#: Keys a rule may carry. Anything else is a typo, and a typo in a capability
#: rule is a silently weaker posture, so it is a load error.
_RULE_KEYS: frozenset[str] = frozenset(
    {"action", "paths", "egress", "path_args", "url_args", "ignore_args"}
)

#: Marks "the caller did not pass a schema at all" (the in-process path), as
#: distinct from `schema=None`, "the proxy has not seen this tool declared".
_NO_SCHEMA: Final = object()


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
    #: Argument names whose values are paths. None means `PATH_ARGUMENT_NAMES`.
    path_args: tuple[str, ...] | None = None
    #: Argument names whose values are URLs. None means `URL_ARGUMENT_NAMES`.
    url_args: tuple[str, ...] | None = None
    #: Argument names that may hold strings but are deliberately not checked,
    #: e.g. `content` on `write_file`. Writing a name here is the explicit,
    #: reviewable statement that the value cannot name a path or a host.
    ignore_args: tuple[str, ...] = ()

    @property
    def checks_arguments(self) -> bool:
        """True when the rule inspects argument values (it has paths or egress)."""
        return self.paths is not None or self.egress is not None

    @property
    def path_names(self) -> frozenset[str]:
        """Names checked against `paths`; empty when the rule has no `paths`."""
        if self.paths is None:
            return frozenset()
        return PATH_ARGUMENT_NAMES if self.path_args is None else frozenset(self.path_args)

    @property
    def url_names(self) -> frozenset[str]:
        """Names checked against `egress`; empty when the rule has no `egress`."""
        if self.egress is None:
            return frozenset()
        return URL_ARGUMENT_NAMES if self.url_args is None else frozenset(self.url_args)

    @property
    def classified_names(self) -> frozenset[str]:
        return self.path_names | self.url_names | frozenset(self.ignore_args)


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


class PlaceholderError(ValueError):
    """A `paths` glob or `sandbox:` value that cannot be expanded.

    A ValueError so existing config-error handling catches it; its own type so
    `wrap` can say precisely why it refused to start (exit 1, child never
    started, design D3).
    """


_PLACEHOLDER_RE = re.compile(r"\$\{([^}]*)\}|\$\{|\$|\{sandbox\}|\{[^}]*\}|\{|\}")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_GLOB_CHARS = frozenset("*?[]")


def _expand_text(
    text: str,
    *,
    sandbox: Path | None,
    environ: Mapping[str, str],
    home: Path,
    allow_sandbox: bool = True,
) -> str:
    """Expand `~`, `${NAME}` and `{sandbox}` in one string, or raise.

    Each substituted value is normalised the way `with_sandbox` normalises
    the sandbox root (separators to `/`, `.`/`..` resolved textually), so a
    Windows path from the environment matches the paths a server sends.

    Refused, each with a message naming the problem:

    * `{sandbox}` with no `sandbox:` key, and any other `{...}` or a stray
      brace: a typo such as `{sandboxx}` must not become a glob that matches
      nothing and blocks every call with no explanation;
    * `${NAME}` unset, or set to the empty string: `${PROJECT}/**` with an
      empty PROJECT would become `/**`, which allows everything;
    * a variable whose value contains glob characters, for the same reason;
    * bare `$NAME`, an invalid name, an unterminated `${`;
    * `~user`, which would need a password-database lookup to mean anything.
    """
    if text.startswith("~"):
        if text == "~" or text[1] in "/\\":
            text = _normalise_path(str(home))[0] + text[1:]
        else:
            raise PlaceholderError("only `~` and `~/` are supported at the start of a path")

    out: list[str] = []
    position = 0
    for match in _PLACEHOLDER_RE.finditer(text):
        out.append(text[position : match.start()])
        position = match.end()
        token = match.group(0)
        if token == "{sandbox}":
            if not allow_sandbox:
                raise PlaceholderError("a `sandbox:` value cannot itself use {sandbox}")
            if sandbox is None:
                raise PlaceholderError(
                    "uses {sandbox} but the config has no `sandbox:` key to expand it from"
                )
            out.append(_normalise_path(str(sandbox))[0])
        elif token.startswith("${") and token.endswith("}"):
            name = match.group(1)
            if not _ENV_NAME_RE.match(name):
                raise PlaceholderError(f"${{{name}}} is not a valid variable name")
            value = environ.get(name)
            if value is None:
                raise PlaceholderError(f"${{{name}}} is not set in the environment")
            if not value:
                raise PlaceholderError(f"${{{name}}} is empty")
            if _GLOB_CHARS & set(value):
                raise PlaceholderError(
                    f"${{{name}}} expands to a value containing glob characters (*?[])"
                )
            normalised, escaped = _normalise_path(value)
            if escaped or not normalised:
                raise PlaceholderError(f"${{{name}}} does not expand to a usable path")
            out.append(normalised)
        elif token == "${":
            raise PlaceholderError("unterminated `${`")
        elif token == "$":
            raise PlaceholderError("a bare `$` is not expanded; write ${NAME}")
        else:
            raise PlaceholderError(
                f"unknown placeholder {token!r}; only {{sandbox}}, `~` and ${{NAME}} expand"
            )
    out.append(text[position:])
    return "".join(out)


def expand_placeholders(
    policy: ToolCallPolicy,
    *,
    sandbox: Path | None,
    environ: Mapping[str, str],
    home: Path,
) -> ToolCallPolicy:
    """Expand `{sandbox}`, `~` and `${NAME}` in every `paths` glob, once.

    Used by `toolgate wrap` at config load (design D3). Unlike `with_sandbox`,
    which leaves an unknown placeholder in place to match nothing, this raises
    `PlaceholderError` for anything it cannot expand, and `wrap` exits 1
    before the child starts: a policy that silently blocks every call looks
    like a broken tool, and one that silently allows everything is worse.

    Only `paths` globs expand. Egress entries never contain placeholders (the
    entry parser refuses them), and argument values are never expanded at
    call time: an agent writing `~/x` gets `~/x` compared literally.
    """
    rules: dict[str, ToolRule] = {}
    for key, rule in policy.rules.items():
        if rule.paths is None:
            rules[key] = rule
            continue
        expanded: list[str] = []
        for glob in rule.paths:
            try:
                expanded.append(_expand_text(glob, sandbox=sandbox, environ=environ, home=home))
            except PlaceholderError as exc:
                raise PlaceholderError(f"tool_calls.rules.{key}.paths: {exc}") from exc
        rules[key] = replace(rule, paths=tuple(expanded))
    return replace(policy, rules=rules)


def resolve_sandbox(
    raw: str,
    *,
    base_dir: Path,
    environ: Mapping[str, str],
    home: Path,
    key: str = "sandbox",
) -> Path:
    """Turn a policy file's `sandbox:` value (or another path key) into an absolute path.

    `~` and `${NAME}` expand as in globs. A relative result is taken relative
    to `base_dir`, the directory holding the config file, never the working
    directory: hosts start servers from directories the user does not choose.
    The directory is not required to exist; globs only compare strings.
    `key` only names the setting in error messages: `wrap` resolves
    `state_dir` and `audit_path` the same way.
    """
    try:
        text = _expand_text(raw, sandbox=None, environ=environ, home=home, allow_sandbox=False)
    except PlaceholderError as exc:
        raise PlaceholderError(f"{key}: {exc}") from exc
    path = Path(text)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


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


def _named_values(arguments: Any, names: frozenset[str]) -> list[Any]:
    """Every value under a key in `names`, found at any depth.

    Objects and arrays are walked recursively, so `{"opts": {"path": ...}}`
    and `{"jobs": [{"url": ...}]}` are checked like a top-level argument (an
    earlier version looked at top-level keys only, design R1-8). A value under
    a matching key is returned as-is, not walked further; a list under it is
    flattened one level, because `paths: [...]` is how the filesystem server
    passes several paths.

    Non-strings are returned too, so the caller can refuse them. Skipping a
    value whose type was not expected is how an odd shape would pass a check
    unexamined (design R2-4).
    """
    out: list[Any] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in names:
                    if isinstance(value, list):
                        out.extend(value)
                    else:
                        out.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(arguments)
    return out


def _is_exact_non_string(schema: Any) -> bool:
    kind = schema.get("type") if isinstance(schema, dict) else None
    return (
        isinstance(schema, dict)
        and isinstance(kind, str)
        and kind in _NON_STRING_TYPES
        and not (_COMPOSITE_KEYWORDS & schema.keys())
    )


def unclassified_arguments(rule: ToolRule, schema: Any) -> tuple[str, ...]:
    """Name every declared argument this rule cannot vouch for.

    The proxy calls this on each `tools/list` response for every tool whose
    rule has `paths` or `egress`. A non-empty result means the tool is
    withheld from the host and calls to it are refused, because the policy
    cannot say whether one of its arguments names a path or a host.

    The rule (design "Schema shapes", which supersedes the earlier "string
    properties" wording, R3-8): a property is safe without classification only
    if its schema is exactly `integer`, `number`, `boolean` or `null`. Every
    other property must be listed in `path_args`, `url_args` or `ignore_args`
    -- `string`, no `type`, a type array, `anyOf`/`oneOf`/`allOf`, `$ref`,
    `enum`/`const`, and objects or arrays that cannot be walked. A closed
    object (`additionalProperties: false`) is walked property by property; an
    array is walked through its `items`. Listing a name classifies the whole
    value under it, whatever its shape.

    Returned names are dotted paths (`options.target`, `items[].note`) for the
    stderr hint; `"*"` means the schema itself could not be read. They come
    from the server's declaration, never from a call's argument values.
    """
    if not rule.checks_arguments:
        return ()
    names = rule.classified_names
    found: list[str] = []

    def visit(name: str, prop: Any) -> None:
        leaf = name.rsplit(".", 1)[-1].removesuffix("[]")
        if leaf in names or _is_exact_non_string(prop):
            return
        if isinstance(prop, dict) and not (_COMPOSITE_KEYWORDS & prop.keys()):
            if prop.get("type") == "object" and prop.get("additionalProperties") is False:
                properties = prop.get("properties", {})
                if isinstance(properties, dict):
                    for child, child_schema in properties.items():
                        visit(f"{name}.{child}", child_schema)
                    return
            if prop.get("type") == "array" and isinstance(prop.get("items"), dict):
                visit(f"{name}[]", prop["items"])
                return
        # `x[]` reads as "the elements of x"; for the hint, name the array.
        found.append(name.removesuffix("[]"))

    if not isinstance(schema, dict):
        return ("*",)
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return ("*",)
    for name, prop in properties.items():
        visit(str(name), prop)
    return tuple(found)


def _undeclared_argument(arguments: dict[str, Any], schema: dict[str, Any]) -> bool:
    """True when the call carries a key its schema does not declare.

    Checked at the top level and inside every closed object the schema
    describes, following `properties` and array `items`. A key the schema does
    not name has no classification, so it cannot be vouched for (design
    "Arguments not in the schema"). Top-level keys are refused whatever the
    root's `additionalProperties` says: an open root would otherwise be a
    door for any argument name the policy never saw.
    """

    def check(value: Any, prop: Any, *, root: bool = False) -> bool:
        if not isinstance(prop, dict):
            return False
        if isinstance(value, dict) and (root or prop.get("additionalProperties") is False):
            properties = prop.get("properties")
            declared = properties if isinstance(properties, dict) else {}
            for key, child in value.items():
                if key not in declared or check(child, declared[key]):
                    return True
        elif isinstance(value, list) and isinstance(prop.get("items"), dict):
            return any(check(item, prop["items"]) for item in value)
        return False

    return check(arguments, schema, root=True)


def evaluate_tool_call(
    policy: ToolCallPolicy,
    server: str,
    tool: str,
    arguments: Any,
    *,
    schema: Any = _NO_SCHEMA,
) -> ToolVerdict:
    """Decide whether one `tools/call` may proceed.

    Pure: no I/O, no clock, no state. The same call always gets the same
    verdict, which is what makes this layer's guarantee checkable by reading
    the policy file rather than by running a benchmark.

    `schema` is the tool's declared `inputSchema`, passed by the proxy, which
    sees `tools/list`. With it, a rule that checks paths or URLs also fails
    closed on what it cannot classify (rule id `<server>.<tool>.args`):
    `schema=None` means the tool has not been declared yet; a schema with an
    unclassified argument, a call with an argument the schema does not
    declare, and arguments that are not an object are all refused. Leaving
    `schema` out is the in-process path's contract, unchanged: values are
    checked, names are not.
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

    if schema is not _NO_SCHEMA and rule.checks_arguments:
        args_rule = f"{key}.args"
        if schema is None:
            return ToolVerdict(
                ToolDecision.BLOCK, rule=args_rule, reason="no tool declaration seen yet"
            )
        if not isinstance(arguments, dict):
            return ToolVerdict(
                ToolDecision.BLOCK, rule=args_rule, reason="tool arguments are not an object"
            )
        if unclassified_arguments(rule, schema):
            return ToolVerdict(
                ToolDecision.BLOCK,
                rule=args_rule,
                reason="the tool declares arguments the policy does not classify",
            )
        if _undeclared_argument(arguments, schema):
            return ToolVerdict(
                ToolDecision.BLOCK,
                rule=args_rule,
                reason="an argument is not declared in the tool's inputSchema",
            )

    if rule.paths is not None:
        for value in _named_values(arguments, rule.path_names):
            if not isinstance(value, str) or not _path_allowed(value, rule.paths):
                return ToolVerdict(
                    ToolDecision.BLOCK,
                    rule=f"{key}.paths",
                    # The offending value is deliberately absent: a path
                    # argument can carry exactly the sensitive data this
                    # project refuses to log (SEC-3).
                    reason="a path argument resolved outside the allowed globs",
                )

    if rule.egress is not None:
        for value in _named_values(arguments, rule.url_names):
            if not _host_allowed(value, rule.egress):
                return ToolVerdict(
                    ToolDecision.BLOCK,
                    rule=f"{key}.egress",
                    reason="a URL argument targeted a host outside the allowed list",
                )

    return ToolVerdict(ToolDecision.ALLOW, rule=key, reason="all configured checks passed")


def _names(
    entry: dict[str, Any],
    name: str,
    where: str,
    *,
    requires: tuple[str, ...] | None,
    check: str,
    allow_empty: bool = False,
) -> tuple[str, ...] | None:
    """Read one of `path_args` / `url_args` / `ignore_args` from a rule."""
    value = entry.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ValueError(f"{where}.{name} must be a list of argument names")
    if requires is None:
        # Naming arguments for a check the rule does not make would classify
        # them without checking them: a quiet hole, so a load error.
        raise ValueError(f"{where}.{name} is set without {check}, so nothing would check it")
    if not value and not allow_empty:
        raise ValueError(f"{where}.{name} is empty; omit it to use the default names")
    return tuple(value)


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
        unknown = sorted(str(k) for k in entry if k not in _RULE_KEYS)
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {unknown}; expected {sorted(_RULE_KEYS)}")
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

        paths = _globs("paths")
        egress = _globs("egress")
        for item in egress or ():
            try:
                parse_egress_entry(item)
            except ValueError as exc:
                raise ValueError(f"{where}.egress: {exc}") from exc

        path_args = _names(entry, "path_args", where, requires=paths, check="`paths`")
        url_args = _names(entry, "url_args", where, requires=egress, check="`egress`")
        ignore_args = _names(
            entry,
            "ignore_args",
            where,
            requires=paths or egress,
            check="`paths` or `egress`",
            allow_empty=True,
        )
        seen: dict[str, str] = {}
        for field_name, names in (
            ("path_args", path_args),
            ("url_args", url_args),
            ("ignore_args", ignore_args),
        ):
            for name in names or ():
                if name in seen:
                    raise ValueError(
                        f"{where}: argument {name!r} is listed in more than one of "
                        f"{seen[name]} and {field_name}"
                    )
                seen[name] = field_name

        rules[str(key)] = ToolRule(
            action=action,
            paths=paths,
            egress=egress,
            path_args=path_args,
            url_args=url_args,
            ignore_args=ignore_args or (),
        )

    return ToolCallPolicy(default=default, rules=rules)


__all__ = [
    "ANY_PORT",
    "DEFAULT_PORTS",
    "PATH_ARGUMENT_NAMES",
    "URL_ARGUMENT_NAMES",
    "Destination",
    "EgressEntry",
    "PlaceholderError",
    "ToolCallBlocked",
    "ToolCallPolicy",
    "ToolDecision",
    "ToolRule",
    "ToolVerdict",
    "evaluate_tool_call",
    "expand_placeholders",
    "load_tool_call_policy",
    "parse_destination",
    "parse_egress_entry",
    "resolve_sandbox",
    "unclassified_arguments",
]
