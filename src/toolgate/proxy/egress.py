"""Decisions behind network mode: what a connection names, and whether it may go.

`toolgate wrap` decides on the URL in a `tools/call`. The wrapped server's
HTTP client then follows redirects on its own, so in the demo an allowed page
answering 302 to the attacker leaked the canary with toolgate on. Network mode
(policy key `network: audit | enforce`) closes that for cooperative clients:
`wrap` runs a forward proxy on 127.0.0.1 and points the child's proxy
variables at it, and every connection the server makes, redirect hops
included, is checked against the same egress entries the rules already hold.

This module holds the pure decisions; `netproxy` does the sockets. Each
decision reuses the parser the argument-level gate uses (`tool_calls`), so a
host means the same thing at both layers:

* A CONNECT authority (`host:port`) and an absolute-form proxy request URL are
  read with `_split_authority`, `_normalise_host` and `parse_destination`. The
  Host header is never consulted.
* `EgressEntry.matches` keys a bare entry on the URL scheme's default port.
  CONNECT has no scheme, so a CONNECT to port 80 is read as `http` and any
  other port as `https`: a bare entry then allows CONNECT to 443 and 80, the
  same two ports it allows in URLs. Node's env-proxy support sends a plain
  `http://` URL as `CONNECT host:80` (probed with Node 24.14.1), which is why
  80 must count.
* The allowlist is the union of the server's rules' `egress` entries. The
  proxy cannot reliably tell which tool opened a connection when calls overlap.
* A hostname entry is matched by name, so a name an attacker controls could
  resolve to loopback or to cloud metadata. Every resolved address is checked
  against `REFUSED_NETWORKS`, a list owned here rather than
  `ipaddress.is_global` (whose registry changes between CPython releases).
  Only a `localhost` entry may reach loopback, and only an IP-literal entry may
  reach the address it names.

Network mode is cooperative: it covers clients that honour proxy variables and
do not exempt the destination. httpx (mcp-server-fetch) and Node 24's built-in
fetch with `NODE_USE_ENV_PROXY=1` both send loopback destinations through the
proxy (tests/test_proxy_clients.py). Clients that ignore the variables are not
covered at all.
"""

from __future__ import annotations

import enum
import ipaddress
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from toolgate.gating.tool_calls import (
    Destination,
    EgressEntry,
    ToolCallPolicy,
    _is_plain_ascii,
    _normalise_host,
    _parse_port,
    _split_authority,
    parse_destination,
    parse_egress_entry,
)

__all__ = [
    "REFUSED_NETWORKS",
    "AuditThrottle",
    "Divergence",
    "NetworkMode",
    "address_refusal",
    "classify_divergence",
    "connect_destination",
    "egress_union",
    "matching_entries",
    "network_child_env",
    "parent_proxy_variables",
    "parse_network_mode",
    "proxy_url_destination",
    "range_refusal_body",
    "union_refusal_body",
]


class NetworkMode(enum.Enum):
    """The `network` policy key.

    `audit` runs the proxy and records every connection but refuses none on
    policy grounds; `enforce` refuses. Safety and protocol checks (the proxy
    token, malformed requests, resource limits) apply in both, so audit mode is
    never an open relay.
    """

    OFF = "off"
    AUDIT = "audit"
    ENFORCE = "enforce"


def parse_network_mode(value: Any) -> NetworkMode:
    """Read the `network` key. Absent means off; anything unknown is an error.

    YAML 1.1 reads an unquoted `off` as the boolean false, so `network: off`
    arrives as False and is accepted as off. True (`on`, `yes`) is refused:
    it names no mode.
    """
    if value is None or value is False:
        return NetworkMode.OFF
    if isinstance(value, str):
        for mode in NetworkMode:
            if mode.value == value:
                return mode
    raise ValueError(f"network must be one of off, audit, enforce (got {value!r})")


def egress_union(policy: ToolCallPolicy, server: str) -> tuple[EgressEntry, ...]:
    """Every `egress` entry of every rule for `server`, deduplicated, in order.

    Rules without `egress` contribute nothing. An empty union is valid: with
    `enforce` it refuses every connection, which is right for a server that
    should not use the network at all.
    """
    prefix = f"{server}."
    seen: dict[EgressEntry, None] = {}
    for key, rule in policy.rules.items():
        if key.startswith(prefix) and rule.egress is not None:
            for text in rule.egress:
                seen.setdefault(parse_egress_entry(text), None)
    return tuple(seen)


def connect_destination(authority: str) -> Destination | None:
    """The destination a CONNECT request names, or None to refuse it (400).

    The authority must be `host:port` with an explicit port, in the same strict
    forms the URL parser accepts: no userinfo, no unbracketed IPv6, no zone id,
    no non-canonical IPv4 spellings.
    """
    if not _is_plain_ascii(authority) or "@" in authority:
        return None
    split = _split_authority(authority)
    if split is None or split[1] is None:
        return None
    host = _normalise_host(split[0])
    port = _parse_port(split[1])
    if host is None or port is None:
        return None
    return Destination(scheme="http" if port == 80 else "https", host=host, port=port)


def proxy_url_destination(target: str) -> Destination | None:
    """The destination of a plain-HTTP proxy request, or None to refuse it (400).

    Only absolute-form `http://` targets: origin-form (`/x`, which would leave
    the Host header to choose) and `https://` (which must use CONNECT) are
    refused.
    """
    destination = parse_destination(target)
    if destination is None or destination.scheme != "http":
        return None
    return destination


def matching_entries(
    entries: Sequence[EgressEntry], destination: Destination
) -> tuple[EgressEntry, ...]:
    """The entries that allow `destination`; empty means "not in the union"."""
    return tuple(entry for entry in entries if entry.matches(destination))


#: Addresses a hostname entry may not reach. Order matters only for the name a
#: refusal reports: the narrowest network is listed first.
REFUSED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(text)
    for text in (
        # IPv4
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, including cloud metadata 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including 255.255.255.255
        # IPv6
        "::/128",
        "::1/128",
        "::/96",  # IPv4-compatible (deprecated): ::7f00:1 embeds 127.0.0.1
        "100::/64",  # discard
        "64:ff9b::/96",  # NAT64: can embed any IPv4 address
        "64:ff9b:1::/48",  # local-use NAT64
        "2001::/32",  # Teredo
        "2001:2::/48",  # benchmarking
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4: embeds an IPv4 address
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # site-local (deprecated)
        "ff00::/8",  # multicast
    )
)


def _literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def address_refusal(address: str, entries: Sequence[EgressEntry]) -> str | None:
    """The refused network `address` falls in, or None when it may be used.

    `entries` are the entries that matched the destination's name. An
    IPv4-mapped IPv6 address is checked as the IPv4 address it carries. A
    `localhost` entry exempts loopback addresses; an IP-literal entry exempts
    exactly the address it names. A wildcard or hostname entry exempts nothing.
    """
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    refused = next((net for net in REFUSED_NETWORKS if ip in net), None)
    if refused is None:
        return None
    for entry in entries:
        if entry.host == "localhost" and ip.is_loopback:
            return None
        if _literal_address(entry.host) == ip:
            return None
    return str(refused)


def _authority(destination: Destination) -> str:
    return f"{destination.host}:{destination.port}"


def union_refusal_body(destination: Destination, server: str) -> str:
    """The 403 body when no entry of the server's union allows the destination."""
    return f"toolgate: {_authority(destination)} is not in the egress union of server {server}"


def range_refusal_body(destination: Destination, address: str) -> str:
    """The 403 body when the destination resolves only to refused addresses."""
    return f"toolgate: {_authority(destination)} resolves to {address} in a refused range"


class Divergence(enum.Enum):
    """How a connection relates to the `tools/call`s in flight when it opened.

    `matched`: some in-flight call's URL argument names this host and port.
    `unmatched`: calls with URL arguments are in flight and none names it (a
    redirect hop, robots.txt on another host, or something else).
    `ungated_call`: only calls with no known destination are in flight.
    `no_call`: nothing is in flight (startup, background traffic).
    """

    MATCHED = "matched"
    UNMATCHED = "unmatched"
    UNGATED_CALL = "ungated_call"
    NO_CALL = "no_call"


def classify_divergence(
    destination: Destination, in_flight: Iterable[frozenset[tuple[str, int]]]
) -> Divergence:
    """Compare host and port only: a CONNECT to :443 matches an https argument."""
    target = (destination.host, destination.port)
    calls = list(in_flight)
    if not calls:
        return Divergence.NO_CALL
    if any(target in call for call in calls):
        return Divergence.MATCHED
    if any(calls):
        return Divergence.UNMATCHED
    return Divergence.UNGATED_CALL


_PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
_REMOVED_NAMES = frozenset({*_PROXY_NAMES, "NO_PROXY"})


def network_child_env(
    environ: Mapping[str, str], proxy_url: str, *, windows: bool
) -> dict[str, str]:
    """The child's environment in network mode, built from `environ`.

    Every proxy and no-proxy variable is removed whatever its case, so an
    inherited `NO_PROXY=localhost` cannot exempt the demo's loopback attacker.
    The three proxy variables are then set: both spellings on POSIX, where
    names are case-sensitive and clients read either; one uppercase spelling on
    Windows, where names are case-insensitive. `NODE_USE_ENV_PROXY=1` makes
    Node's built-in fetch read them. `environ` is not modified.
    """
    env = {name: value for name, value in environ.items() if name.upper() not in _REMOVED_NAMES}
    for name in _PROXY_NAMES:
        env[name] = proxy_url
        if not windows:
            env[name.lower()] = proxy_url
    env["NODE_USE_ENV_PROXY"] = "1"
    return env


def parent_proxy_variables(environ: Mapping[str, str]) -> list[str]:
    """Proxy variables already set (non-empty) in `environ`, in any case.

    Network mode does not chain to an upstream proxy, so `wrap` refuses to
    start when one is configured rather than silently cut the server off.
    """
    return [name for name, value in environ.items() if name.upper() in _PROXY_NAMES and value]


class AuditThrottle:
    """At most one audit row per key per `window` seconds.

    A key is `(host:port, decision, divergence)`: divergence is part of it so
    the per-value counts stay complete. Suppressed repeats are counted, and the
    count is returned by the next admitted `admit` for that key (to be written
    on its row) or by `drain` at shutdown.
    """

    def __init__(self, window: float = 10.0, clock: Callable[[], float] = time.monotonic) -> None:
        self._window = window
        self._clock = clock
        self._last: dict[tuple[str, ...], float] = {}
        self._suppressed: dict[tuple[str, ...], int] = {}

    def admit(self, key: tuple[str, ...]) -> int | None:
        """The suppressed count to record on this row, or None to skip the row."""
        now = self._clock()
        last = self._last.get(key)
        if last is not None and now - last < self._window:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return None
        self._last[key] = now
        return self._suppressed.pop(key, 0)

    def drain(self) -> dict[tuple[str, ...], int]:
        """Counts suppressed since each key's last row; clears them."""
        counts, self._suppressed = self._suppressed, {}
        return counts
