"""Relative path arguments are resolved against the server's working directory.

The filesystem false-refusal study (docs/FS-UTILITY-STUDY.md) found that
every refusal it measured was a relative path (`notes/meeting.md`, `.`): the
server resolves one against its working directory, which `wrap` shares with
it, while the `paths` check matched the text against absolute globs and
refused. These tests pin the fix: a relative path is joined to the working
directory before matching, and only a value that is unambiguously relative
on every platform is treated as one. Anything else (`~`, a drive, a URI, a
leading separator) is matched as written, which keeps it fail-closed.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from tests.test_proxy_pump import policy_config
from toolgate.gating.policy import PolicyConfig
from toolgate.gating.tool_calls import (
    ToolCallPolicy,
    ToolDecision,
    ToolVerdict,
    evaluate_tool_call,
    load_tool_call_policy,
)
from toolgate.proxy.pump import ProxyCore, ProxySettings
from toolgate.proxy.wrap import working_dir_warning

POSIX = load_tool_call_policy(
    {"default": "block", "rules": {"fs.read": {"paths": ["/ws", "/ws/**"]}}}
)
WINDOWS = load_tool_call_policy(
    {"default": "block", "rules": {"fs.read": {"paths": ["C:/Users/me/ws", "C:/Users/me/ws/**"]}}}
)


def verdict(
    path: str, working_dir: str | None = "/ws", policy: ToolCallPolicy = POSIX
) -> ToolVerdict:
    return evaluate_tool_call(policy, "fs", "read", {"path": path}, working_dir=working_dir)


class TestResolution:
    @pytest.mark.parametrize(
        "path",
        ["notes/meeting.md", "notes\\meeting.md", ".", "./data/sales.csv", "", "a/../b",
         "../ws/x", "reports"],
    )  # fmt: skip
    def test_a_relative_path_inside_the_working_directory_is_allowed(self, path: str) -> None:
        assert verdict(path).decision is ToolDecision.ALLOW

    @pytest.mark.parametrize("path", ["..", "../other/x", "a/../../x", "../../../../etc/passwd"])
    def test_a_relative_path_that_climbs_out_is_refused(self, path: str) -> None:
        result = verdict(path)
        assert result.decision is ToolDecision.BLOCK
        assert result.rule == "fs.read.paths"

    def test_without_a_working_directory_relative_paths_stay_refused(self) -> None:
        """The in-process path passes none; its behaviour is unchanged."""
        assert verdict("notes/meeting.md", working_dir=None).decision is ToolDecision.BLOCK

    def test_absolute_paths_are_matched_as_before(self) -> None:
        assert verdict("/ws/notes/a.md").decision is ToolDecision.ALLOW
        assert verdict("/etc/passwd").decision is ToolDecision.BLOCK
        assert verdict("/ws/../etc/passwd").decision is ToolDecision.BLOCK

    def test_a_working_directory_outside_the_globs_refuses_relative_paths(self) -> None:
        assert verdict("notes/a.md", working_dir="/elsewhere").decision is ToolDecision.BLOCK

    def test_windows_working_directory_and_separators(self) -> None:
        for path in ("data\\sales.csv", "data/sales.csv", "."):
            result = verdict(path, working_dir="C:\\Users\\me\\ws", policy=WINDOWS)
            assert result.decision is ToolDecision.ALLOW, path
        result = verdict("..\\secret.txt", working_dir="C:\\Users\\me\\ws", policy=WINDOWS)
        assert result.decision is ToolDecision.BLOCK


class TestNotRelative:
    """Values a server may read as something other than a relative path."""

    @pytest.mark.parametrize(
        "path",
        [
            "~",  # servers expand the home directory
            "~/notes/a.md",
            "C:notes.md",  # drive-relative on Windows
            "C:/other/x",
            "file:///ws/x",  # a URI, not a path
            "x:y",
            "\\\\server\\share\\x",  # UNC
            "\\x",  # root of the current drive on Windows
        ],
    )
    def test_is_matched_as_written_and_refused(self, path: str) -> None:
        assert verdict(path).decision is ToolDecision.BLOCK


class TestRefusalText:
    def test_a_path_refusal_names_the_fix_without_the_value(self) -> None:
        result = verdict("../../secret-token-dir/x")
        assert result.decision is ToolDecision.BLOCK
        assert "secret-token" not in result.reason and "secret-token" not in result.hint
        assert "absolute path" in result.hint

    def test_a_relative_refusal_says_it_was_relative(self) -> None:
        assert "relative" in verdict("../other/x").reason
        assert "relative" not in verdict("/etc/passwd").reason

    def test_the_proxy_reply_carries_the_hint_for_path_rules(self) -> None:
        settings = ProxySettings(
            name="fs",
            policy=_policy_config(),
            working_dir="/ws",
        )
        proxy = ProxyCore(settings)
        _declare(proxy)
        allowed = proxy.client_line(_call(1, "notes/a.md"))
        assert allowed.to_server, "a relative path inside the working directory is forwarded"
        refused = proxy.client_line(_call(2, "../x"))
        assert refused.to_server == []
        text = _reply_text(refused.to_client[0])
        assert text.startswith("Blocked by toolgate policy: rule fs.read.paths")
        assert "absolute path" in text


class TestStartupWarning:
    def test_no_warning_when_the_working_directory_is_the_sandbox_or_inside_it(
        self, tmp_path: Path
    ) -> None:
        assert working_dir_warning(tmp_path, tmp_path) is None
        (tmp_path / "sub").mkdir()
        assert working_dir_warning(tmp_path, tmp_path / "sub") is None

    def test_no_warning_without_a_sandbox(self, tmp_path: Path) -> None:
        assert working_dir_warning(None, tmp_path) is None

    def test_a_warning_names_both_directories(self, tmp_path: Path) -> None:
        sandbox, cwd = tmp_path / "project", tmp_path / "elsewhere"
        message = working_dir_warning(sandbox, cwd)
        assert message is not None
        assert str(sandbox) in message and str(cwd) in message
        assert "relative" in message


# --- helpers -------------------------------------------------------------------------

READ_SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}


def _policy_config() -> PolicyConfig:
    return policy_config({"default": "block", "rules": {"fs.read": {"paths": ["/ws", "/ws/**"]}}})


def _line(message: object) -> bytes:
    return json.dumps(message).encode() + b"\n"


def _declare(proxy: ProxyCore) -> None:
    proxy.client_line(_line({"jsonrpc": "2.0", "id": "L", "method": "tools/list"}))
    proxy.server_line(
        _line({"jsonrpc": "2.0", "id": "L",
               "result": {"tools": [{"name": "read", "inputSchema": READ_SCHEMA}]}})
    )  # fmt: skip


def _call(request_id: int, path: str) -> bytes:
    return _line(
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
         "params": {"name": "read", "arguments": {"path": path}}}
    )  # fmt: skip


def _reply_text(raw: bytes) -> str:
    return str(json.loads(raw)["result"]["content"][0]["text"])


@pytest.mark.live_servers
@pytest.mark.skipif(shutil.which("npx") is None, reason="npx is needed for the real server")
def test_a_relative_path_reaches_the_real_filesystem_server(tmp_path: Path) -> None:
    """End to end: `wrap` in the workspace, the pinned server-filesystem behind it.

    The calls the study saw refused (`notes/meeting.md`, `.`) now reach the
    server and succeed; a relative path climbing out is still refused, with
    the hint, before the server sees it.
    """
    from tests.fixtures.demo import FILESYSTEM_COMMAND
    from tests.fixtures.demo.mcp_client import StdioMcpClient, is_tool_error, result_text
    from toolgate.fs_utility_study import MEETING, make_workspace, policy_for, server_command

    workspace = tmp_path / "ws"
    make_workspace(workspace)
    config = tmp_path / "filesystem.yaml"
    config.write_text(
        policy_for(workspace) + f'state_dir: "{(tmp_path / "state").as_posix()}"\n',
        encoding="utf-8",
    )
    server = server_command(FILESYSTEM_COMMAND, workspace)
    command = [sys.executable, "-m", "toolgate", "wrap", "--name", "filesystem",
               "--config", str(config), "--", *server]  # fmt: skip
    with StdioMcpClient(command, cwd=workspace, timeout=300) as client:
        client.initialize()
        client.list_tools()
        read = client.call_tool("read_text_file", {"path": "notes/meeting.md"})
        assert not is_tool_error(read), result_text(read)
        assert MEETING.strip().splitlines()[0] in result_text(read)
        listing = client.call_tool("list_directory", {"path": "."})
        assert not is_tool_error(listing), result_text(listing)
        assert "notes" in result_text(listing)
        refused = client.call_tool("read_text_file", {"path": "../filesystem.yaml"})
        assert is_tool_error(refused)
        assert result_text(refused).startswith(
            "Blocked by toolgate policy: rule filesystem.read_text_file.paths"
        )
        assert "absolute path" in result_text(refused)
