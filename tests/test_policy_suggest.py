"""Tests for `toolgate policy suggest` (v0.2 Track E, DX item E1).

`policy suggest` starts the server, reads its real `tools/list`, and prints a
policy draft: `default: block`, and per tool a rule whose string-capable
arguments are sorted into `url_args`, `path_args` and `ignore_args` by name
and schema `format`, every guess marked `# review`. Two properties are held
here: the draft always loads, and for every declared tool it classifies every
argument (`unclassified_arguments(...) == ()`), so the proxy never withholds a
tool the draft names. The placeholders it writes (`example.invalid`, a
`/replace/with/...` glob) allow nothing until the user edits them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from toolgate.gating.tool_calls import load_tool_call_policy, unclassified_arguments
from toolgate.suggest import (
    PLACEHOLDER_HOST,
    PLACEHOLDER_PATHS,
    SuggestError,
    classify_tool,
    draft_policy,
    list_tools,
)

FAKE_SERVER = Path(__file__).resolve().parent / "fixtures" / "fake_mcp_server.py"


def _check_draft(name: str, tools: list[dict[str, Any]], text: str) -> dict[str, Any]:
    raw = yaml.safe_load(text)
    policy = load_tool_call_policy(raw["tool_calls"])
    assert policy.default.value == "block"
    for tool in tools:
        rule = policy.rules.get(f"{name}.{tool['name']}")
        assert rule is not None, tool["name"]
        assert unclassified_arguments(rule, tool.get("inputSchema")) == (), tool["name"]
    return raw


# --- classification ------------------------------------------------------------


def test_url_path_and_other_arguments_are_sorted() -> None:
    schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "callback": {"type": "string", "format": "uri"},
            "webhook_endpoint": {"type": "string"},
            "path": {"type": "string"},
            "source": {"type": "string"},
            "output_file": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}},
            "content": {"type": "string"},
            "max_length": {"type": "integer"},
            "raw": {"type": "boolean"},
        },
    }
    classified = classify_tool(schema)
    assert classified.url_args == ("url", "callback", "webhook_endpoint")
    assert classified.path_args == ("path", "source", "output_file", "paths")
    assert classified.ignore_args == ("content",)
    assert classified.readable


def test_nested_and_composite_arguments_are_classified_whole() -> None:
    schema = {
        "type": "object",
        "properties": {
            "edits": {"type": "array", "items": {"type": "object"}},
            "mode": {"enum": ["a", "b"]},
            "options": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
    }
    classified = classify_tool(schema)
    assert classified.ignore_args == ("edits", "mode", "options")


def test_an_unreadable_schema_is_not_readable() -> None:
    assert not classify_tool(None).readable
    assert not classify_tool({"properties": ["x"]}).readable


# --- the draft -------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "fetch",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "max_length": {"type": "integer"}},
        },
    },
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        },
    },
    {"name": "ping", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "weird", "inputSchema": "not a schema"},
]


def test_draft_loads_classifies_everything_and_marks_review() -> None:
    text = draft_policy("srv", TOOLS)
    raw = _check_draft("srv", TOOLS, text)
    rules = raw["tool_calls"]["rules"]
    assert rules["srv.fetch"] == {"egress": [PLACEHOLDER_HOST], "url_args": ["url"]}
    assert rules["srv.write_file"] == {
        "paths": [PLACEHOLDER_PATHS],
        "path_args": ["path"],
        "ignore_args": ["content"],
    }
    assert rules["srv.ping"] == {}
    assert rules["srv.weird"] == {"action": "block"}
    lines = text.splitlines()
    for key in ("srv.fetch:", "srv.write_file:", "srv.ping:", "srv.weird:"):
        (line,) = [entry for entry in lines if entry.strip().startswith(key)]
        assert "# review" in line, line
    assert "default: block" in text


def test_placeholders_allow_nothing_real() -> None:
    from toolgate.gating.tool_calls import ToolDecision, evaluate_tool_call

    policy = load_tool_call_policy(yaml.safe_load(draft_policy("srv", TOOLS))["tool_calls"])
    url = evaluate_tool_call(policy, "srv", "fetch", {"url": "https://docs.python.org/"})
    path = evaluate_tool_call(policy, "srv", "write_file", {"path": "/home/u/x", "content": ""})
    assert url.decision is ToolDecision.BLOCK and path.decision is ToolDecision.BLOCK


def test_a_server_without_tools_still_gets_a_valid_draft() -> None:
    raw = yaml.safe_load(draft_policy("srv", []))
    assert load_tool_call_policy(raw["tool_calls"]).rules == {}


# --- talking to a real process -------------------------------------------------------


def test_list_tools_from_the_fake_server() -> None:
    tools = list_tools([sys.executable, str(FAKE_SERVER)], timeout=30)
    assert [tool["name"] for tool in tools] == ["fetch", "echo"]


def test_a_server_that_exits_is_an_error_naming_its_stderr() -> None:
    command = [sys.executable, "-c", "import sys; sys.stderr.write('boom\\n'); sys.exit(4)"]
    with pytest.raises(SuggestError, match="boom"):
        list_tools(command, timeout=30)


def test_cli_prints_the_draft_to_stdout_only(tmp_path: Path) -> None:
    env = dict(os.environ)
    completed = subprocess.run(
        [sys.executable, "-m", "toolgate", "policy", "suggest", "--name", "fake",
         "--", sys.executable, str(FAKE_SERVER)],
        capture_output=True, text=True, timeout=120, env=env, cwd=tmp_path,
    )  # fmt: skip
    assert completed.returncode == 0, completed.stderr
    tools = list_tools([sys.executable, str(FAKE_SERVER)], timeout=30)
    _check_draft("fake", tools, completed.stdout)
    assert list(tmp_path.iterdir()) == []  # writes no file


def test_cli_exits_nonzero_when_the_server_fails(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "toolgate", "policy", "suggest", "--name", "x",
         "--", sys.executable, "-c", "raise SystemExit(3)"],
        capture_output=True, text=True, timeout=120, cwd=tmp_path,
    )  # fmt: skip
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "not drafted" in completed.stderr


# --- the pinned reference servers (accepted DX obligation) ----------------------------


@pytest.mark.live_servers
@pytest.mark.skipif(
    shutil.which("npx") is None or shutil.which("uvx") is None,
    reason="npx and uvx are needed to start the pinned reference servers",
)
@pytest.mark.parametrize("server", ["filesystem", "fetch"])
def test_reference_server_drafts_classify_every_argument(server: str, tmp_path: Path) -> None:
    from tests.fixtures.demo import FETCH_COMMAND, FILESYSTEM_COMMAND

    command = (
        [*FILESYSTEM_COMMAND, str(tmp_path)] if server == "filesystem" else list(FETCH_COMMAND)
    )
    tools = list_tools(command, timeout=300)
    assert tools
    _check_draft(server, tools, draft_policy(server, tools))
