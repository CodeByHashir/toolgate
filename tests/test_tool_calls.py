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

from llmshield_mcp.gating.tool_calls import (
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
    from llmshield_mcp.gating.policy import load_policy_config

    assert not load_policy_config().tool_calls.enabled
