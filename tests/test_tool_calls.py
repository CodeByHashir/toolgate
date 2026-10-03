"""Tests for capability gating of outbound `tools/call` requests.

This layer's claim is narrow and strong: against the behaviour a rule names, it
has no false-negative rate, because it does not classify anything. These tests
are written to hold it to exactly that claim -- every bypass a path or URL
argument could attempt, and nothing about whether text "looks" malicious.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from toolgate.gating.tool_calls import (
    ToolCallBlocked,
    ToolCallPolicy,
    ToolDecision,
    ToolRule,
    evaluate_tool_call,
    load_tool_call_policy,
)

POLICY = load_tool_call_policy(
    {
        "default": "allow",
        "rules": {
            "filesystem.read_text_file": {"paths": ["workspace/**"]},
            "filesystem.write_file": {"paths": ["workspace/out/**"]},
            "fetch.fetch": {"egress": ["docs.example.com", "*.trusted.test"]},
            "github.delete_repo": {"action": "block"},
            "mail.send": {"action": "escalate"},
        },
    }
)


def _verdict(server: str, tool: str, **arguments: Any) -> Any:
    return evaluate_tool_call(POLICY, server, tool, arguments)


class TestPathConfinement:
    @pytest.mark.parametrize(
        "path",
        [
            "workspace/notes.md",
            "workspace/sub/deep/file.txt",
            "./workspace/notes.md",
            "workspace/a/../b.txt",
            "workspace\\sub\\a.txt",
        ],
    )
    def test_paths_inside_the_sandbox_are_allowed(self, path: str) -> None:
        assert _verdict("filesystem", "read_text_file", path=path).decision is ToolDecision.ALLOW

    @pytest.mark.parametrize(
        "path",
        [
            "/etc/passwd",
            "../../etc/passwd",
            "workspace/../../.ssh/id_rsa",
            "workspace/../secrets.env",
            "..",
            "other/file.txt",
            "workspace/../../workspace/escaped.txt",
        ],
    )
    def test_traversal_and_absolute_paths_are_blocked(self, path: str) -> None:
        """The regression that a smoke test caught before this shipped.

        An earlier `_path_allowed` also matched the RAW string, and `fnmatch`'s
        `*` matches `/`, so `workspace/../../.ssh/id_rsa` matched `workspace/**`
        verbatim and the sandbox escape was allowed. Only the normalised path is
        matched now, and a `..` that climbs above its own root fails outright.
        """
        verdict = _verdict("filesystem", "read_text_file", path=path)
        assert verdict.decision is ToolDecision.BLOCK, path
        assert verdict.rule == "filesystem.read_text_file.paths"

    def test_a_list_valued_path_argument_is_checked_elementwise(self) -> None:
        allowed = _verdict("filesystem", "read_text_file", paths=["workspace/a", "workspace/b"])
        assert allowed.decision is ToolDecision.ALLOW

        smuggled = _verdict("filesystem", "read_text_file", paths=["workspace/a", "/etc/shadow"])
        assert smuggled.decision is ToolDecision.BLOCK

    def test_each_tool_gets_its_own_confinement(self) -> None:
        """write_file is narrower than read_text_file; the rules must not bleed."""
        assert _verdict("filesystem", "write_file", path="workspace/out/x").decision is (
            ToolDecision.ALLOW
        )
        assert _verdict("filesystem", "write_file", path="workspace/notes.md").decision is (
            ToolDecision.BLOCK
        )

    def test_a_tool_with_no_path_rule_is_not_path_checked(self) -> None:
        assert _verdict("filesystem", "list_directory", path="/anywhere").decision is (
            ToolDecision.ALLOW
        )


class TestEgressConfinement:
    @pytest.mark.parametrize(
        "url",
        ["https://docs.example.com/guide", "https://api.trusted.test/x", "http://docs.example.com"],
    )
    def test_allowed_hosts_pass(self, url: str) -> None:
        assert _verdict("fetch", "fetch", url=url).decision is ToolDecision.ALLOW

    @pytest.mark.parametrize(
        "url",
        [
            "https://attacker.test/collect?data=secret",
            "https://docs.example.com.attacker.test/x",
            "https://evil.test/?u=https://docs.example.com",
            "not-a-url",
            "",
            "file:///etc/passwd",
        ],
    )
    def test_exfiltration_targets_are_blocked(self, url: str) -> None:
        verdict = _verdict("fetch", "fetch", url=url)
        assert verdict.decision is ToolDecision.BLOCK, url
        assert verdict.rule == "fetch.fetch.egress"

    def test_a_host_that_merely_contains_an_allowed_name_is_not_allowed(self) -> None:
        """`docs.example.com.attacker.test` must not satisfy `docs.example.com`."""
        assert _verdict(
            "fetch", "fetch", url="https://docs.example.com.attacker.test"
        ).decision is (ToolDecision.BLOCK)


class TestFlatActions:
    def test_a_blocked_tool_is_blocked_whatever_the_arguments(self) -> None:
        for arguments in ({}, {"repo": "x"}, {"path": "workspace/safe"}):
            verdict = evaluate_tool_call(POLICY, "github", "delete_repo", arguments)
            assert verdict.decision is ToolDecision.BLOCK
            assert verdict.rule == "github.delete_repo.action"

    def test_escalate_is_reported_but_is_not_a_block(self) -> None:
        verdict = _verdict("mail", "send", to="a@b.test")
        assert verdict.decision is ToolDecision.ESCALATE
        assert not verdict.blocked


class TestDefaults:
    def test_default_allow_lets_unnamed_tools_through(self) -> None:
        assert _verdict("anything", "at_all", x=1).decision is ToolDecision.ALLOW

    def test_default_block_turns_the_config_into_an_allowlist(self) -> None:
        allowlist = load_tool_call_policy(
            {"default": "block", "rules": {"filesystem.read_text_file": {}}}
        )
        assert (
            evaluate_tool_call(allowlist, "filesystem", "read_text_file", {}).decision
            is ToolDecision.ALLOW
        )
        assert (
            evaluate_tool_call(allowlist, "github", "delete_repo", {}).decision
            is ToolDecision.BLOCK
        )

    def test_an_empty_policy_is_inert(self) -> None:
        empty = ToolCallPolicy()
        assert not empty.enabled
        assert evaluate_tool_call(empty, "any", "tool", {}).decision is ToolDecision.ALLOW

    def test_default_block_alone_counts_as_enabled(self) -> None:
        assert load_tool_call_policy({"default": "block"}).enabled


class TestNoArgumentValuesLeak:
    def test_the_verdict_reason_never_quotes_the_offending_value(self) -> None:
        """SEC-3: a path or URL argument can carry exactly what must not be logged."""
        secret_path = "/home/user/.aws/credentials"
        secret_url = "https://evil.test/?token=sk-live-abcdef123456"

        path_verdict = _verdict("filesystem", "read_text_file", path=secret_path)
        url_verdict = _verdict("fetch", "fetch", url=secret_url)

        for verdict, secret in ((path_verdict, secret_path), (url_verdict, secret_url)):
            assert secret not in verdict.reason
            assert secret not in verdict.rule
            assert "credentials" not in verdict.reason
            assert "sk-live" not in verdict.reason


class TestConfigValidation:
    def test_absent_block_is_an_inert_policy(self) -> None:
        assert not load_tool_call_policy(None).enabled

    def test_a_non_mapping_block_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be a mapping"):
            load_tool_call_policy(["nope"])

    def test_an_unknown_default_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="tool_calls.default"):
            load_tool_call_policy({"default": "maybe"})

    def test_an_unknown_action_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="action"):
            load_tool_call_policy({"rules": {"a.b": {"action": "sometimes"}}})

    def test_a_rule_key_without_a_server_prefix_is_rejected(self) -> None:
        """`read_text_file` is ambiguous across servers; `filesystem.read_text_file` is not."""
        with pytest.raises(ValueError, match="server.*tool"):
            load_tool_call_policy({"rules": {"read_text_file": {"paths": ["x/**"]}}})

    def test_an_empty_glob_list_is_rejected_as_probably_a_mistake(self) -> None:
        with pytest.raises(ValueError, match="use `action: block`"):
            load_tool_call_policy({"rules": {"a.b": {"paths": []}}})

    def test_a_string_instead_of_a_glob_list_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be a list"):
            load_tool_call_policy({"rules": {"a.b": {"paths": "workspace/**"}}})


class TestBlockedException:
    def test_it_carries_what_an_operator_needs_and_nothing_more(self) -> None:
        error = ToolCallBlocked(tool="filesystem.read_text_file", rule="x.paths", reason="outside")

        assert error.tool == "filesystem.read_text_file"
        assert error.rule == "x.paths"
        assert "blocked by x.paths" in str(error)


def test_rule_dataclass_defaults_are_permissive() -> None:
    """A rule that names nothing must not accidentally forbid everything."""
    rule = ToolRule()
    assert rule.action is ToolDecision.ALLOW
    assert rule.paths is None
    assert rule.egress is None


def test_shipped_default_policy_does_not_enable_capability_gating(tmp_path: Path) -> None:
    """Adding this layer must not change behaviour for anyone who has not opted in."""
    from toolgate.gating.policy import load_policy_config

    assert not load_policy_config().tool_calls.enabled


class TestSandboxPlaceholder:
    """`{sandbox}` globs, resolved against the filesystem server's real root.

    The server reports its absolute root to the model, so a live agent sends
    absolute paths. Before `with_sandbox` existed the shipped agent profile
    only had `sandbox/**`, and a Haiku smoke run had every legitimate read
    refused.
    """

    ROOTS = (Path("/srv/repo/sandbox"), Path(r"D:\repo\sandbox"))

    @staticmethod
    def _policy(root: Path) -> ToolCallPolicy:
        return load_tool_call_policy(
            {"rules": {"filesystem.read_text_file": {"paths": ["{sandbox}", "{sandbox}/**"]}}}
        ).with_sandbox(root)

    @pytest.mark.parametrize("root", ROOTS)
    def test_absolute_paths_inside_the_sandbox_are_allowed(self, root: Path) -> None:
        policy = self._policy(root)
        base = str(root)
        for path in (base, f"{base}/README.md", base + r"\notes\meeting-notes.md"):
            verdict = evaluate_tool_call(policy, "filesystem", "read_text_file", {"path": path})
            assert verdict.decision is ToolDecision.ALLOW, path

    @pytest.mark.parametrize("root", ROOTS)
    def test_escapes_from_an_absolute_sandbox_are_blocked(self, root: Path) -> None:
        policy = self._policy(root)
        base = str(root)
        for path in (
            f"{base}/../secrets.env",
            f"{base}-evil/README.md",
            f"{base}/a/../../../etc/passwd",
            "/etc/passwd",
            "README.md",
        ):
            verdict = evaluate_tool_call(policy, "filesystem", "read_text_file", {"path": path})
            assert verdict.decision is ToolDecision.BLOCK, path

    def test_an_unexpanded_placeholder_matches_nothing(self) -> None:
        policy = load_tool_call_policy(
            {"rules": {"filesystem.read_text_file": {"paths": ["{sandbox}/**"]}}}
        )
        verdict = evaluate_tool_call(
            policy, "filesystem", "read_text_file", {"path": "/srv/repo/sandbox/README.md"}
        )
        assert verdict.decision is ToolDecision.BLOCK

    def test_rules_without_paths_are_left_alone(self) -> None:
        policy = load_tool_call_policy(
            {
                "rules": {
                    "github.delete_repo": {"action": "block"},
                    "fetch.fetch": {"egress": ["a.test"]},
                }
            }
        )
        assert policy.with_sandbox(Path("/srv/repo/sandbox")) == policy

    def test_shipped_agent_profile_allows_an_absolute_sandbox_read(self) -> None:
        from toolgate.gating.policy import load_policy_config
        from toolgate.servers import load_servers_config

        sandbox = load_servers_config().sandbox
        policy = load_policy_config(
            Path(__file__).resolve().parent.parent / "config" / "policy.agent.yaml"
        ).tool_calls.with_sandbox(sandbox)

        inside = evaluate_tool_call(
            policy, "filesystem", "read_text_file", {"path": str(sandbox / "README.md")}
        )
        outside = evaluate_tool_call(
            policy, "filesystem", "read_text_file", {"path": str(sandbox.parent / "README.md")}
        )
        assert inside.decision is ToolDecision.ALLOW
        assert outside.decision is ToolDecision.BLOCK


# --- T1: hardened, port-aware egress (design D6, D15, R3-18) ---------------------
#
# Everything above this line is the pre-T1 suite and is kept unchanged (REG-1):
# the port-aware change must pass it as written. The classes below pin the new
# behaviour. Every URL here is a *value an agent could send*; the question each
# row asks is "which host would a real HTTP client connect to, and is that host
# on the list?", not "does the string look suspicious?".


def _egress(url: Any, *entries: str) -> ToolDecision:
    policy = load_tool_call_policy({"rules": {"fetch.fetch": {"egress": list(entries)}}})
    return evaluate_tool_call(policy, "fetch", "fetch", {"url": url}).decision


class TestEgressParserDifferentials:
    """URLs that Python's `urlparse` and a WHATWG client read differently.

    The two reproduced bypasses come first. `mcp-server-fetch` was probed on
    2026-10-03 (docs/designs/standalone-gateway.md, Open Question 1): for both
    it connected to the attacker host, while `urlparse` reported the allowed
    one. Rejecting the whole class beats chasing each parser's reading.
    """

    def test_backslash_userinfo_bypass_is_refused(self) -> None:
        assert _egress("http://evil.com\\@github.com/x", "github.com") is ToolDecision.BLOCK

    def test_backslash_label_bypass_is_refused(self) -> None:
        assert _egress("http://evil.com\\.github.com/x", "*.github.com") is ToolDecision.BLOCK

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com\\x",  # backslash anywhere
            "http://github.com/a\\b",
            "http://user@github.com/",  # userinfo, even with an allowed host after it
            "http://user:pass@github.com/",
            "http://evil.com@github.com/",
            "http://github.com@evil.com/",
            "http://git hub.com/",  # whitespace
            "http://github.com/\tx",
            "http://github.com/\nx",
            "http://github.com/\x00",
            " http://github.com/",
            "http://github.com/\x7f",
            "http://githüb.com/",  # non-ASCII (IDN must arrive as punycode)
            "http://github.com/café",
            "http://github%2ecom/",  # percent-encoded host
            "http://github.com:/",  # empty port
            "http://github.com:0/",
            "http://github.com:65536/",
            "http://github.com:+443/",
            "http:github.com/",  # special-scheme forms a WHATWG parser repairs
            "http:/github.com/",
            "http:///github.com/",
            "//github.com/x",  # scheme-relative
            "http://-github.com/",
            "http://github_.com/",
            "http://github..com/",
        ],
    )
    def test_ambiguous_or_malformed_urls_are_refused(self, url: str) -> None:
        assert _egress(url, "github.com", "*.github.com", "github.com:*") is ToolDecision.BLOCK

    def test_label_wildcards_match_on_label_boundaries_only(self) -> None:
        assert _egress("https://api.github.com/", "*.github.com") is ToolDecision.ALLOW
        assert _egress("https://a.b.github.com/", "*.github.com") is ToolDecision.ALLOW
        assert _egress("https://github.com/", "*.github.com") is ToolDecision.BLOCK
        assert _egress("https://evilgithub.com/", "*.github.com") is ToolDecision.BLOCK
        assert _egress("https://github.com.evil.test/", "*.github.com") is ToolDecision.BLOCK


class TestEgressHostNormalisation:
    def test_host_case_is_ignored_on_both_sides(self) -> None:
        assert _egress("HTTPS://GitHub.COM/x", "github.com") is ToolDecision.ALLOW
        assert _egress("https://github.com/x", "GitHub.com") is ToolDecision.ALLOW

    def test_one_trailing_dot_names_the_same_host(self) -> None:
        assert _egress("https://github.com./x", "github.com") is ToolDecision.ALLOW
        assert _egress("https://evil.test./x", "github.com") is ToolDecision.BLOCK

    def test_punycode_is_an_ordinary_ascii_host(self) -> None:
        assert _egress("https://xn--gthub-zsa.com/", "xn--gthub-zsa.com") is ToolDecision.ALLOW
        assert _egress("https://xn--gthub-zsa.com/", "github.com") is ToolDecision.BLOCK

    @pytest.mark.parametrize(
        ("url", "entry", "expected"),
        [
            ("http://127.0.0.1/", "127.0.0.1", ToolDecision.ALLOW),
            ("http://127.0.0.2/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://[::1]/", "[::1]", ToolDecision.ALLOW),
            ("http://[0:0:0:0:0:0:0:1]/", "[::1]", ToolDecision.ALLOW),
            ("http://[::1]/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://localhost/", "127.0.0.1", ToolDecision.BLOCK),  # names, not resolution
            # Numeric forms a WHATWG parser reads as 127.0.0.1; only the
            # canonical dotted quad is accepted, so none of these can alias.
            ("http://2130706433/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://127.1/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://0x7f.0.0.1/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://0177.0.0.1/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://127.000.000.001/", "127.0.0.1", ToolDecision.BLOCK),
            ("http://example.123/", "*", ToolDecision.BLOCK),
            ("http://[fe80::1%25eth0]/", "*", ToolDecision.BLOCK),  # zone id
        ],
    )
    def test_ip_literals(self, url: str, entry: str, expected: ToolDecision) -> None:
        assert _egress(url, entry) is expected


class TestEgressPorts:
    """D6 + D15: a bare host means the scheme's default port, and only that."""

    @pytest.mark.parametrize(
        ("url", "entry", "expected"),
        [
            # D15 contract: same destination, same verdict.
            ("https://docs.example.com/x", "docs.example.com", ToolDecision.ALLOW),
            ("https://docs.example.com:443/x", "docs.example.com", ToolDecision.ALLOW),
            ("http://docs.example.com:80/x", "docs.example.com", ToolDecision.ALLOW),
            # The intended difference: a bare host refuses other ports.
            ("https://docs.example.com:8443/x", "docs.example.com", ToolDecision.BLOCK),
            ("http://docs.example.com:443/x", "docs.example.com", ToolDecision.BLOCK),
            ("https://docs.example.com:80/x", "docs.example.com", ToolDecision.BLOCK),
            # host:port is exact.
            ("http://localhost:8000/", "localhost:8000", ToolDecision.ALLOW),
            ("http://localhost:8001/", "localhost:8000", ToolDecision.BLOCK),
            ("http://localhost/", "localhost:8000", ToolDecision.BLOCK),
            ("https://h.test:443/", "h.test:443", ToolDecision.ALLOW),
            ("https://h.test/", "h.test:443", ToolDecision.ALLOW),
            # host:* is any port.
            ("http://localhost:1/", "localhost:*", ToolDecision.ALLOW),
            ("http://localhost/", "localhost:*", ToolDecision.ALLOW),
            ("http://localhost:65535/", "localhost:*", ToolDecision.ALLOW),
            # Ports combine with wildcards and IP literals.
            ("https://api.github.com:8443/", "*.github.com:8443", ToolDecision.ALLOW),
            ("https://api.github.com/", "*.github.com:8443", ToolDecision.BLOCK),
            ("http://[::1]:9000/", "[::1]:9000", ToolDecision.ALLOW),
            ("http://[::1]:9001/", "[::1]:9000", ToolDecision.BLOCK),
            ("http://127.0.0.1:5000/", "127.0.0.1:*", ToolDecision.ALLOW),
        ],
    )
    def test_port_rules(self, url: str, entry: str, expected: ToolDecision) -> None:
        assert _egress(url, entry) is expected

    def test_the_demo_attacker_port_is_refused_on_the_page_host(self) -> None:
        """R3-13: the launch demo's separation must rest on the port, not the name."""
        assert _egress("http://localhost:8123/page", "localhost:8123") is ToolDecision.ALLOW
        assert _egress("http://localhost:9999/?d=x", "localhost:8123") is ToolDecision.BLOCK


class TestEgressUrlValues:
    """R3-18: anything but an absolute http(s) URL on the list is refused."""

    @pytest.mark.parametrize(
        "value",
        [
            "github.com/x",  # no scheme
            "/x",  # relative
            "x",
            "",
            "file:///etc/passwd",
            "ftp://github.com/",
            "data:text/plain,hi",
            "javascript:alert(1)",
            "ws://github.com/",
            "mailto:a@github.com",
            None,
            42,
            {"href": "https://github.com/"},
        ],
    )
    def test_non_url_values_are_refused(self, value: Any) -> None:
        assert _egress(value, "github.com", "*") is ToolDecision.BLOCK

    def test_list_values_are_checked_elementwise_and_must_all_be_strings(self) -> None:
        assert _egress(["https://github.com/a", "https://github.com/b"], "github.com") is (
            ToolDecision.ALLOW
        )
        assert _egress(["https://github.com/a", "https://evil.test/"], "github.com") is (
            ToolDecision.BLOCK
        )
        assert _egress(["https://github.com/a", 7], "github.com") is ToolDecision.BLOCK

    def test_star_allows_any_well_formed_host_but_not_malformed_urls(self) -> None:
        assert _egress("https://anything.example/", "*") is ToolDecision.ALLOW
        assert _egress("http://evil.com\\@github.com/", "*") is ToolDecision.BLOCK


class TestEgressEntryValidation:
    """A malformed allowlist entry is a config error at load, never a silent mismatch."""

    @pytest.mark.parametrize(
        "entry",
        [
            "https://github.com",
            "github.com/",
            "git*.com",
            "*github.com",
            "api.*.com",
            "**.github.com",
            "github.com:http",
            "github.com:0",
            "github.com:70000",
            "github.com:",
            "user@github.com",
            "github.com\\",
            "",
            " github.com",
            "::1",
            "[::1",
            "githüb.com",
        ],
    )
    def test_bad_entries_are_rejected(self, entry: str) -> None:
        with pytest.raises(ValueError, match="egress"):
            load_tool_call_policy({"rules": {"fetch.fetch": {"egress": [entry]}}})

    @pytest.mark.parametrize(
        "entry",
        [
            "github.com",
            "*.github.com",
            "github.com:8080",
            "github.com:*",
            "*",
            "*:*",
            "127.0.0.1",
            "127.0.0.1:9",
            "[::1]",
            "[::1]:*",
            "localhost",
            "GitHub.com.",
        ],
    )
    def test_good_entries_load(self, entry: str) -> None:
        load_tool_call_policy({"rules": {"fetch.fetch": {"egress": [entry]}}})

    def test_shipped_agent_policy_still_loads_and_allows_default_ports(self) -> None:
        """REG-1: config/policy.agent.yaml's bare-host entries keep working."""
        from toolgate.gating.policy import load_policy_config

        policy = load_policy_config(
            Path(__file__).resolve().parent.parent / "config" / "policy.agent.yaml"
        ).tool_calls
        for url in ("https://example.com/", "http://www.example.com/x", "https://example.org"):
            assert evaluate_tool_call(policy, "fetch", "fetch", {"url": url}).decision is (
                ToolDecision.ALLOW
            ), url
        assert (
            evaluate_tool_call(
                policy, "fetch", "fetch", {"url": "https://example.com:8443/"}
            ).decision
            is ToolDecision.BLOCK
        )


# --- T2: fail-closed argument classification (design "Calls the proxy cannot
# classify", R3-8, R3-17) ---------------------------------------------------------
#
# The proxy passes the tool's declared `inputSchema` as `schema=`. A rule that
# checks paths or URLs then refuses to guess: every property that could hold a
# string has to be named in `path_args`, `url_args` or `ignore_args`, and an
# argument the schema does not declare is refused. Callers that pass no
# `schema` (the in-process research path) keep the pre-T2 behaviour.


def _s(**properties: Any) -> dict[str, Any]:
    """A closed object schema with the given properties."""
    return {"type": "object", "properties": properties, "additionalProperties": False}


STR = {"type": "string"}
INT = {"type": "integer"}

FETCH_SCHEMA = {  # mcp-server-fetch==2026.8.18, as probed on 2026-10-03
    "type": "object",
    "properties": {
        "url": {"type": "string", "format": "uri", "minLength": 1},
        "max_length": {"type": "integer", "default": 5000},
        "start_index": {"type": "integer", "default": 0, "minimum": 0},
        "raw": {"type": "boolean", "default": False},
    },
    "required": ["url"],
}

WRITE_FILE_SCHEMA = _s(path=STR, content=STR)


def _rule_policy(**rule: Any) -> ToolCallPolicy:
    return load_tool_call_policy({"rules": {"srv.tool": rule}})


def _unclassified(schema: Any, **rule: Any) -> tuple[str, ...]:
    from toolgate.gating.tool_calls import unclassified_arguments

    return unclassified_arguments(_rule_policy(**rule).rules["srv.tool"], schema)


class TestSchemaClassification:
    """One row per schema shape (R3-17)."""

    EGRESS = {"egress": ["example.com"]}

    @pytest.mark.parametrize(
        "prop",
        [
            {"type": "integer"},
            {"type": "number", "minimum": 0},
            {"type": "boolean", "default": False},
            {"type": "null"},
        ],
    )
    def test_exact_non_string_scalars_need_no_classification(self, prop: Any) -> None:
        assert _unclassified(_s(x=prop), **self.EGRESS) == ()

    @pytest.mark.parametrize(
        ("label", "prop"),
        [
            ("string", {"type": "string"}),
            ("untyped", {}),
            ("untyped with description", {"description": "anything"}),
            ("type array with string", {"type": ["string", "null"]}),
            ("type array without string", {"type": ["integer", "null"]}),
            ("anyOf", {"anyOf": [{"type": "integer"}, {"type": "string"}]}),
            ("anyOf of scalars", {"anyOf": [{"type": "integer"}, {"type": "boolean"}]}),
            ("oneOf", {"oneOf": [{"type": "integer"}]}),
            ("allOf", {"allOf": [{"type": "integer"}]}),
            ("integer with anyOf beside it", {"type": "integer", "anyOf": [{"type": "string"}]}),
            ("$ref", {"$ref": "#/$defs/Target"}),
            ("enum", {"enum": ["a", "b"]}),
            ("const", {"const": "a"}),
            ("open object", {"type": "object", "properties": {"n": INT}}),
            (
                "object with additionalProperties true",
                {"type": "object", "additionalProperties": True},
            ),
            ("array without items", {"type": "array"}),
            ("array of strings", {"type": "array", "items": STR}),
            ("non-dict schema", True),
        ],
    )
    def test_everything_else_counts_as_a_possible_string(self, label: str, prop: Any) -> None:
        assert _unclassified(_s(x=prop), **self.EGRESS) == ("x",), label

    def test_listing_a_name_classifies_it_whatever_its_shape(self) -> None:
        schema = _s(x={"anyOf": [STR, INT]}, y=STR, z={"$ref": "#/x"})
        assert (
            _unclassified(schema, egress=["example.com"], url_args=["x"], ignore_args=["y", "z"])
            == ()
        )

    def test_closed_objects_are_walked(self) -> None:
        schema = _s(options=_s(depth=INT, target=STR, url=STR))
        assert _unclassified(schema, **self.EGRESS) == ("options.target",)

    def test_arrays_are_walked_through_their_items(self) -> None:
        schema = _s(items={"type": "array", "items": _s(n=INT, note=STR)})
        assert _unclassified(schema, **self.EGRESS) == ("items[].note",)
        assert _unclassified(_s(ns={"type": "array", "items": INT}), **self.EGRESS) == ()

    def test_default_names_cover_the_reference_servers(self) -> None:
        assert _unclassified(FETCH_SCHEMA, egress=["example.com"]) == ()
        assert (
            _unclassified(_s(path=STR, paths={"type": "array", "items": STR}), paths=["w/**"]) == ()
        )
        assert _unclassified(_s(href=STR, uri=STR), **self.EGRESS) == ()

    def test_names_count_only_for_the_checks_the_rule_makes(self) -> None:
        """An egress-only rule does not treat `path` as checked, so it must be listed."""
        assert _unclassified(_s(url=STR, path=STR), egress=["example.com"]) == ("path",)
        assert _unclassified(_s(url=STR, path=STR), paths=["w/**"]) == ("url",)

    def test_explicit_args_replace_the_defaults(self) -> None:
        assert _unclassified(_s(path=STR, file=STR), paths=["w/**"], path_args=["file"]) == (
            "path",
        )

    def test_a_write_file_tool_with_content_needs_ignore_args(self) -> None:
        assert _unclassified(WRITE_FILE_SCHEMA, paths=["w/**"]) == ("content",)
        assert _unclassified(WRITE_FILE_SCHEMA, paths=["w/**"], ignore_args=["content"]) == ()

    @pytest.mark.parametrize("schema", [None, "x", [], {"type": "object", "properties": "no"}])
    def test_an_unreadable_schema_is_unclassified_as_a_whole(self, schema: Any) -> None:
        assert _unclassified(schema, **self.EGRESS) == ("*",)

    def test_a_rule_without_paths_or_egress_needs_no_classification(self) -> None:
        assert _unclassified(_s(x=STR), action="allow") == ()


class TestCallsWithASchema:
    FETCH = load_tool_call_policy({"rules": {"fetch.fetch": {"egress": ["docs.example.com"]}}})
    FS = load_tool_call_policy(
        {
            "rules": {
                "fs.write_file": {
                    "paths": ["workspace/**"],
                    "path_args": ["path"],
                    "ignore_args": ["content"],
                },
                "fs.nested": {"paths": ["workspace/**"]},
            }
        }
    )

    def test_an_allowed_fetch_passes(self) -> None:
        verdict = evaluate_tool_call(
            self.FETCH,
            "fetch",
            "fetch",
            {"url": "https://docs.example.com/x", "raw": True},
            schema=FETCH_SCHEMA,
        )
        assert verdict.decision is ToolDecision.ALLOW

    def test_a_call_before_any_declaration_is_refused(self) -> None:
        verdict = evaluate_tool_call(
            self.FETCH, "fetch", "fetch", {"url": "https://docs.example.com/x"}, schema=None
        )
        assert verdict.decision is ToolDecision.BLOCK
        assert verdict.rule == "fetch.fetch.args"
        assert "no tool declaration seen yet" in verdict.reason

    def test_a_tool_without_a_rule_needs_no_declaration(self) -> None:
        assert evaluate_tool_call(self.FETCH, "fetch", "other", {"q": 1}, schema=None).decision is (
            ToolDecision.ALLOW
        )

    def test_an_argument_the_schema_does_not_declare_is_refused(self) -> None:
        verdict = evaluate_tool_call(
            self.FETCH,
            "fetch",
            "fetch",
            {"url": "https://docs.example.com/x", "target": "https://evil.test/"},
            schema=FETCH_SCHEMA,
        )
        assert verdict.decision is ToolDecision.BLOCK
        assert verdict.rule == "fetch.fetch.args"

    def test_an_undeclared_key_inside_a_closed_object_is_refused(self) -> None:
        schema = _s(opts=_s(path=STR))
        ok = evaluate_tool_call(
            self.FS, "fs", "nested", {"opts": {"path": "workspace/a"}}, schema=schema
        )
        bad = evaluate_tool_call(
            self.FS,
            "fs",
            "nested",
            {"opts": {"path": "workspace/a", "file": "/etc/x"}},
            schema=schema,
        )
        assert ok.decision is ToolDecision.ALLOW
        assert bad.decision is ToolDecision.BLOCK
        assert bad.rule == "fs.nested.args"

    def test_an_unclassified_tool_is_refused_even_with_safe_values(self) -> None:
        verdict = evaluate_tool_call(
            self.FS,
            "fs",
            "nested",
            {"path": "workspace/a", "note": "hi"},
            schema=_s(path=STR, note=STR),
        )
        assert verdict.decision is ToolDecision.BLOCK
        assert verdict.rule == "fs.nested.args"

    @pytest.mark.parametrize("arguments", [None, [], "x", 3])
    def test_non_object_arguments_are_refused(self, arguments: Any) -> None:
        verdict = evaluate_tool_call(self.FETCH, "fetch", "fetch", arguments, schema=FETCH_SCHEMA)
        assert verdict.decision is ToolDecision.BLOCK
        assert verdict.rule == "fetch.fetch.args"

    def test_ignored_arguments_are_not_inspected(self) -> None:
        verdict = evaluate_tool_call(
            self.FS,
            "fs",
            "write_file",
            {"path": "workspace/out.txt", "content": "/etc/passwd"},
            schema=WRITE_FILE_SCHEMA,
        )
        assert verdict.decision is ToolDecision.ALLOW

    def test_paths_are_still_confined(self) -> None:
        verdict = evaluate_tool_call(
            self.FS,
            "fs",
            "write_file",
            {"path": "/etc/cron.d/x", "content": ""},
            schema=WRITE_FILE_SCHEMA,
        )
        assert verdict.decision is ToolDecision.BLOCK
        assert verdict.rule == "fs.write_file.paths"

    def test_flat_actions_come_before_classification(self) -> None:
        policy = load_tool_call_policy({"rules": {"gh.delete": {"action": "block"}}})
        assert (
            evaluate_tool_call(policy, "gh", "delete", {}, schema=None).rule == "gh.delete.action"
        )


class TestRecursiveValueWalk:
    """Values under a classified name are found at any depth (design R1-8)."""

    POLICY = load_tool_call_policy(
        {"rules": {"srv.tool": {"paths": ["workspace/**"], "egress": ["docs.example.com"]}}}
    )

    @pytest.mark.parametrize(
        ("arguments", "expected", "check"),
        [
            ({"opts": {"path": "workspace/a"}}, ToolDecision.ALLOW, ""),
            ({"opts": {"path": "/etc/passwd"}}, ToolDecision.BLOCK, "paths"),
            ({"jobs": [{"path": "workspace/a"}, {"path": "../x"}]}, ToolDecision.BLOCK, "paths"),
            ({"a": {"b": [{"url": "https://evil.test/"}]}}, ToolDecision.BLOCK, "egress"),
            ({"a": {"b": [{"url": "https://docs.example.com/"}]}}, ToolDecision.ALLOW, ""),
            ({"path": 7}, ToolDecision.BLOCK, "paths"),  # a non-string path is refused
            ({"paths": ["workspace/a", None]}, ToolDecision.BLOCK, "paths"),
            ({"path": {"nested": "workspace/a"}}, ToolDecision.BLOCK, "paths"),
        ],
    )
    def test_nested_values(self, arguments: Any, expected: ToolDecision, check: str) -> None:
        verdict = evaluate_tool_call(self.POLICY, "srv", "tool", arguments)
        assert verdict.decision is expected, arguments
        if check:
            assert verdict.rule == f"srv.tool.{check}"


class TestArgumentNameConfig:
    @pytest.mark.parametrize(
        ("rule", "message"),
        [
            ({"paths": ["w/**"], "path_args": "path"}, "path_args must be a list"),
            ({"paths": ["w/**"], "path_args": [1]}, "path_args must be a list"),
            ({"egress": ["a.test"], "path_args": ["file"]}, "path_args.*without `paths`"),
            ({"paths": ["w/**"], "url_args": ["u"]}, "url_args.*without `egress`"),
            ({"ignore_args": ["x"]}, "ignore_args.*without `paths` or `egress`"),
            (
                {"paths": ["w/**"], "egress": ["a.test"], "path_args": ["x"], "url_args": ["x"]},
                "more than one",
            ),
            ({"paths": ["w/**"], "path_args": ["x"], "ignore_args": ["x"]}, "more than one"),
            ({"paths": ["w/**"], "path_args": []}, "path_args is empty"),
            ({"paths": ["w/**"], "pathargs": ["x"]}, "unknown key"),
        ],
    )
    def test_misconfiguration_is_a_load_error(self, rule: dict[str, Any], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            load_tool_call_policy({"rules": {"srv.tool": rule}})

    def test_an_empty_ignore_list_is_fine(self) -> None:
        load_tool_call_policy({"rules": {"srv.tool": {"paths": ["w/**"], "ignore_args": []}}})
