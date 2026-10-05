"""Tests for the decisions behind network mode (design: network egress mode).

Network mode puts a forward proxy between the wrapped server and the network,
so a redirect the server's HTTP client follows on its own is checked like the
URL in the `tools/call` was. These tests cover the pure decisions only: which
destination a CONNECT authority or a proxy request URL names, whether the
server's egress union allows it, whether the address it resolves to is one a
hostname entry may reach, how a connection relates to the calls in flight,
the child's environment, and the audit-row throttle. The socket side is tested
separately.
"""

from __future__ import annotations

import ipaddress

import pytest

from toolgate.gating.tool_calls import Destination, load_tool_call_policy, parse_egress_entry
from toolgate.proxy.egress import (
    REFUSED_NETWORKS,
    AuditThrottle,
    Divergence,
    NetworkMode,
    address_refusal,
    classify_divergence,
    connect_destination,
    egress_union,
    matching_entries,
    network_child_env,
    parent_proxy_variables,
    parse_network_mode,
    proxy_url_destination,
    range_refusal_body,
    union_refusal_body,
)


def _entries(*texts: str) -> tuple:
    return tuple(parse_egress_entry(text) for text in texts)


# --- mode -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "mode"),
    [
        (None, NetworkMode.OFF),
        ("off", NetworkMode.OFF),
        (False, NetworkMode.OFF),  # YAML 1.1 reads an unquoted `off` as false
        ("audit", NetworkMode.AUDIT),
        ("enforce", NetworkMode.ENFORCE),
    ],
)
def test_network_mode_values(value: object, mode: NetworkMode) -> None:
    assert parse_network_mode(value) is mode


@pytest.mark.parametrize("value", ["on", "ENFORCE", "", True, 1, ["enforce"]])
def test_network_mode_rejects_anything_else(value: object) -> None:
    with pytest.raises(ValueError, match="network"):
        parse_network_mode(value)


# --- union ----------------------------------------------------------------


def test_union_collects_the_servers_egress_entries_only() -> None:
    policy = load_tool_call_policy(
        {
            "default": "allow",
            "rules": {
                "fetch.fetch": {"egress": ["docs.example.com", "*.cdn.test"]},
                "fetch.fetch_raw": {"egress": ["docs.example.com", "api.test:8443"]},
                "fetch.local": {"paths": ["workspace/**"]},
                "fetch.danger": {"action": "block"},
                "other.fetch": {"egress": ["elsewhere.test"]},
            },
        }
    )
    assert egress_union(policy, "fetch") == _entries(
        "docs.example.com", "*.cdn.test", "api.test:8443"
    )


def test_union_is_empty_for_a_server_without_egress_rules() -> None:
    policy = load_tool_call_policy(
        {"default": "block", "rules": {"filesystem.read": {"paths": ["w/**"]}}}
    )
    assert egress_union(policy, "filesystem") == ()


# --- CONNECT targets --------------------------------------------------------


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("example.com:443", Destination("https", "example.com", 443)),
        ("Example.COM.:443", Destination("https", "example.com", 443)),
        # Node's env-proxy sends plain http:// URLs as CONNECT host:80 (probed).
        ("example.com:80", Destination("http", "example.com", 80)),
        ("example.com:8443", Destination("https", "example.com", 8443)),
        ("[::1]:443", Destination("https", "[::1]", 443)),
        ("127.0.0.1:9000", Destination("https", "127.0.0.1", 9000)),
    ],
)
def test_connect_destination(authority: str, expected: Destination) -> None:
    assert connect_destination(authority) == expected


@pytest.mark.parametrize(
    "authority",
    [
        "example.com",  # CONNECT needs a port
        "example.com:",
        "example.com:0",
        "example.com:99999",
        "::1:443",  # unbracketed IPv6
        "[fe80::1%eth0]:443",  # zone id
        "user@example.com:443",
        "exa mple.com:443",
        "example.com\\@evil.test:443",
        "2130706433:443",  # non-canonical IPv4 spelling
        "",
    ],
)
def test_connect_destination_refuses_malformed_targets(authority: str) -> None:
    assert connect_destination(authority) is None


def test_a_bare_entry_allows_connect_to_443_and_80_only() -> None:
    entries = _entries("example.com")
    for port in (443, 80):
        destination = connect_destination(f"example.com:{port}")
        assert destination is not None
        assert matching_entries(entries, destination), port
    other = connect_destination("example.com:8443")
    assert other is not None
    assert not matching_entries(entries, other)
    assert matching_entries(_entries("example.com:8443"), other)


# --- proxy request URLs (absolute-form) -----------------------------------


def test_proxy_url_destination_accepts_http_absolute_form() -> None:
    assert proxy_url_destination("http://localhost:8000/redirect?d=1") == Destination(
        "http", "localhost", 8000
    )


@pytest.mark.parametrize(
    "target",
    [
        "/redirect",  # origin-form
        "https://example.com/x",  # https must use CONNECT
        "ftp://example.com/x",
        "http://user@example.com/x",
        "http://evil.test\\@example.com/x",
        "*",
        "example.com:80",
    ],
)
def test_proxy_url_destination_refuses_everything_else(target: str) -> None:
    assert proxy_url_destination(target) is None


# --- matching --------------------------------------------------------------


def test_matching_entries_uses_the_existing_entry_semantics() -> None:
    entries = _entries("*.trusted.test", "localhost:8000")
    assert matching_entries(entries, Destination("https", "api.trusted.test", 443))
    assert not matching_entries(entries, Destination("https", "trusted.test", 443))
    assert matching_entries(entries, Destination("http", "localhost", 8000))
    assert not matching_entries(entries, Destination("http", "localhost", 9000))


# --- address check -----------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.1",
        "10.1.2.3",
        "100.64.0.1",
        "127.0.0.1",
        "127.9.9.9",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::7f00:1",  # IPv4-compatible, embeds 127.0.0.1 (R3-4)
        "::ffff:127.0.0.1",  # IPv4-mapped: unmapped first
        "::ffff:169.254.169.254",
        "100::1",
        "fc00::1",
        "fd12::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "2001:db8::1",
        "2001:2::1",
        "64:ff9b::7f00:1",  # NAT64
        "64:ff9b:1::1",
        "2002:7f00:1::1",  # 6to4
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    ],
)
def test_hostname_entries_never_reach_refused_ranges(address: str) -> None:
    assert address_refusal(address, _entries("*.example.com", "*")) is not None


@pytest.mark.parametrize("address", ["93.184.215.14", "8.8.8.8", "2606:4700::1111"])
def test_public_addresses_pass(address: str) -> None:
    assert address_refusal(address, _entries("example.com")) is None


def test_refusal_names_the_range() -> None:
    assert address_refusal("169.254.169.254", _entries("metadata.example")) == "169.254.0.0/16"


def test_localhost_entry_may_reach_loopback_only() -> None:
    entries = _entries("localhost:8000")
    assert address_refusal("127.0.0.1", entries) is None
    assert address_refusal("::1", entries) is None
    assert address_refusal("10.0.0.1", entries) is not None
    assert address_refusal("169.254.169.254", entries) is not None


def test_ip_literal_entry_may_reach_exactly_that_address() -> None:
    entries = _entries("10.0.0.5:8080", "[fd00::5]")
    assert address_refusal("10.0.0.5", entries) is None
    assert address_refusal("fd00::5", entries) is None
    assert address_refusal("10.0.0.6", entries) is not None


def test_a_rebinding_name_resolving_to_loopback_is_refused() -> None:
    # The entry is a hostname, not `localhost`: its resolving to 127.0.0.1 is
    # exactly the rebinding case.
    assert address_refusal("127.0.0.1", _entries("attacker-rebind.example")) == "127.0.0.0/8"


def test_refused_networks_are_parsed_networks() -> None:
    for network in REFUSED_NETWORKS:
        assert isinstance(network, ipaddress.IPv4Network | ipaddress.IPv6Network)


# --- refusal bodies (R3-2) ---------------------------------------------------


def test_union_refusal_body_names_the_server() -> None:
    body = union_refusal_body(Destination("http", "localhost", 9999), "fetch")
    assert body == "toolgate: localhost:9999 is not in the egress union of server fetch"


def test_range_refusal_body_names_the_address() -> None:
    body = range_refusal_body(Destination("https", "evil.test", 443), "127.0.0.1")
    assert body == "toolgate: evil.test:443 resolves to 127.0.0.1 in a refused range"


# --- divergence ---------------------------------------------------------------


def test_divergence_values() -> None:
    page = frozenset({("localhost", 8000)})
    target = Destination("http", "localhost", 8000)
    attacker = Destination("http", "localhost", 9000)
    assert classify_divergence(target, [page]) is Divergence.MATCHED
    assert classify_divergence(attacker, [page]) is Divergence.UNMATCHED
    assert classify_divergence(attacker, [frozenset()]) is Divergence.UNGATED_CALL
    assert classify_divergence(attacker, [frozenset(), page]) is Divergence.UNMATCHED
    assert classify_divergence(attacker, []) is Divergence.NO_CALL


def test_divergence_compares_host_and_port_not_scheme() -> None:
    # A CONNECT to :443 matches an https URL argument on the same host.
    url = frozenset({("example.com", 443)})
    assert classify_divergence(Destination("https", "example.com", 443), [url]) is (
        Divergence.MATCHED
    )


# --- child environment --------------------------------------------------------

PROXY = "http://tg:token@127.0.0.1:5000"


def test_posix_env_sets_both_spellings_and_removes_no_proxy() -> None:
    parent = {"PATH": "/bin", "NO_PROXY": "localhost", "no_proxy": "127.0.0.1", "HOME": "/h"}
    env = network_child_env(parent, PROXY, windows=False)
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        assert env[name] == PROXY
        assert env[name.lower()] == PROXY
    assert env["NODE_USE_ENV_PROXY"] == "1"
    assert not {name for name in env if name.upper() == "NO_PROXY"}
    assert env["PATH"] == "/bin" and env["HOME"] == "/h"


def test_windows_env_removes_every_case_variant_and_sets_one_spelling() -> None:
    parent = {"Path": "C:\\x", "No_Proxy": "localhost", "no_proxy": "*", "http_proxy": "old"}
    env = network_child_env(parent, PROXY, windows=True)
    proxy_names = sorted(
        name for name in env if name.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
    )
    assert proxy_names == ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"]
    assert all(env[name] == PROXY for name in proxy_names)
    assert not {name for name in env if name.upper() == "NO_PROXY"}
    assert env["Path"] == "C:\\x"


def test_env_builder_does_not_modify_the_parent() -> None:
    parent = {"NO_PROXY": "localhost"}
    network_child_env(parent, PROXY, windows=False)
    assert parent == {"NO_PROXY": "localhost"}


def test_parent_proxy_variables_are_detected_in_any_case() -> None:
    parent = {"Https_Proxy": "http://corp:3128", "ALL_PROXY": "", "NO_PROXY": "x", "PATH": "/"}
    assert parent_proxy_variables(parent) == ["Https_Proxy"]
    assert parent_proxy_variables({"PATH": "/"}) == []


# --- audit throttle -------------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_throttle_admits_one_row_per_key_per_window_and_counts_the_rest() -> None:
    clock = _Clock()
    throttle = AuditThrottle(window=10.0, clock=clock)
    key = ("localhost:9000", "refused", "unmatched")
    assert throttle.admit(key) == 0
    assert throttle.admit(key) is None
    assert throttle.admit(key) is None
    clock.now = 10.5
    assert throttle.admit(key) == 2  # written on the next row for the key
    assert throttle.drain() == {}


def test_throttle_keys_include_divergence() -> None:
    # Mixed divergence inside one window: each value gets its own row, so the
    # per-value counts stay complete (spec review R2-1).
    throttle = AuditThrottle(window=10.0, clock=_Clock())
    assert throttle.admit(("h:80", "allowed", "matched")) == 0
    assert throttle.admit(("h:80", "allowed", "no_call")) == 0
    assert throttle.admit(("h:80", "allowed", "matched")) is None
    assert throttle.drain() == {("h:80", "allowed", "matched"): 1}
    assert throttle.drain() == {}
