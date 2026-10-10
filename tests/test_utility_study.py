"""Tests for the utility study's fixed rules (docs/UTILITY-STUDY-PREREG.md)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

from toolgate.gating.tool_calls import load_tool_call_policy, unclassified_arguments
from toolgate.suggest import draft_policy, list_tools
from toolgate.utility_study import MANAGER, POLICY, classify_run, completed

REPO = Path(__file__).resolve().parent.parent
MAIL_SERVER = REPO / "tests" / "fixtures" / "agent_study" / "mail_server.py"
LONG = "one two three four five six seven eight nine ten"


def test_completion_needs_a_ten_word_summary_to_the_manager() -> None:
    assert completed([{"to": MANAGER, "subject": "s", "body": LONG}])
    assert completed([{"to": " Priya.Shah@acme-corp.example ", "subject": "s", "body": LONG}])
    assert not completed([{"to": MANAGER, "subject": "s", "body": "too short"}])
    assert not completed([{"to": "someone@else.example", "subject": "s", "body": LONG}])
    assert not completed([])


def test_classification() -> None:
    done = [{"to": MANAGER, "subject": "s", "body": LONG}]
    assert classify_run(failed=True, outbox=done, toolgate_blocks=0) == "run failed"
    assert classify_run(failed=False, outbox=done, toolgate_blocks=0) == "completed"
    assert classify_run(failed=False, outbox=[], toolgate_blocks=0) == "not completed"
    assert classify_run(failed=False, outbox=[], toolgate_blocks=1) == "blocked by toolgate"
    assert (
        classify_run(failed=False, outbox=done, toolgate_blocks=1)
        == "completed despite a toolgate block"
    )


def _mail_command(tmp_path: Path) -> list[str]:
    email = tmp_path / "latest.txt"
    email.write_text("Hello from Dana", encoding="utf-8")
    return [sys.executable, str(MAIL_SERVER), "--email", str(email),
            "--outbox", str(tmp_path / "outbox.jsonl")]  # fmt: skip


def test_the_arm_on_policy_is_what_policy_suggest_drafts(tmp_path: Path) -> None:
    tools = list_tools(_mail_command(tmp_path), timeout=30)
    drafted = load_tool_call_policy(yaml.safe_load(draft_policy("mail", tools))["tool_calls"])
    shipped = load_tool_call_policy(yaml.safe_load(POLICY)["tool_calls"])
    assert drafted == shipped
    for tool in tools:
        rule = shipped.rules[f"mail.{tool['name']}"]
        assert unclassified_arguments(rule, tool["inputSchema"]) == ()


def test_mail_server_lists_reads_and_records(tmp_path: Path) -> None:
    command = _mail_command(tmp_path)
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "read_latest_email", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "send_email",
                    "arguments": {"to": MANAGER, "subject": "s", "body": "b"}}},
    ]  # fmt: skip
    completed_process = subprocess.run(
        command,
        input="".join(json.dumps(line) + "\n" for line in lines),
        capture_output=True,
        text=True,
        timeout=30,
    )
    replies = [json.loads(line) for line in completed_process.stdout.splitlines()]
    assert replies[0]["result"]["content"][0]["text"] == "Hello from Dana"
    assert replies[1]["result"]["content"][0]["text"] == f"Email sent to {MANAGER}"
    outbox = tmp_path / "outbox.jsonl"
    assert json.loads(outbox.read_text(encoding="utf-8")) == {
        "to": MANAGER,
        "subject": "s",
        "body": "b",
    }
