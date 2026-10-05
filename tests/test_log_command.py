"""Tests for `toolgate log` (v0.2 Track E, DX item E2).

The README's way to see what was blocked used the `sqlite3` command-line
tool, which stock Windows does not have. `toolgate log` reads the same audit
file with Python's sqlite3, read-only, and prints the newest rows first. The
rows hold rule ids, hashes, timings and notes, never argument values or
results, so printing them prints nothing a call carried.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from toolgate.gating.audit import Decision, DecisionLog, DecisionRecord, Outcome
from toolgate.log_command import read_rows


def _audit(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    log = DecisionLog(path)
    rows = [
        (Decision.ALLOW, Outcome.RESULT, "fetch", "forwarded"),
        (Decision.BLOCK, Outcome.TOOL_CALL, "fetch", "rule fake.fetch.egress: host not allowed"),
        (Decision.ESCALATE, Outcome.TOOL_CALL, "mail", "rule fake.mail: escalate"),
        (Decision.BLOCK, Outcome.NETWORK_EGRESS, None, "rule fake.network.egress: refused"),
    ]
    for decision, outcome, tool, note in rows:
        log.append(
            DecisionRecord(
                correlation_id="c",
                mcp_server_id="fake",
                raw_result_hash="",
                fused_decision=decision,
                latency_ms=0.0,
                outcome=outcome,
                tool_name=tool,
                note=note,
            ).with_timestamp()
        )
    log.close()
    return path


def test_read_rows_newest_first(tmp_path: Path) -> None:
    audit = _audit(tmp_path / "a.sqlite")
    rows = read_rows(audit, blocked=False, limit=10)
    assert [row.note for row in rows] == [
        "rule fake.network.egress: refused",
        "rule fake.mail: escalate",
        "rule fake.fetch.egress: host not allowed",
        "forwarded",
    ]


def test_read_rows_blocked_only_and_limit(tmp_path: Path) -> None:
    audit = _audit(tmp_path / "a.sqlite")
    rows = read_rows(audit, blocked=True, limit=10)
    assert [row.decision for row in rows] == ["block", "block"]
    assert len(read_rows(audit, blocked=False, limit=1)) == 1


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "toolgate", "log", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
    )


def test_cli_reads_the_audit_named_by_the_config(tmp_path: Path) -> None:
    _audit(tmp_path / "state" / "audit" / "fake.sqlite")
    config = tmp_path / "fake.yaml"
    config.write_text('state_dir: "state"\ntool_calls:\n  default: allow\n', encoding="utf-8")
    completed = _run("--name", "fake", "--config", str(config), "--blocked", cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert len(lines) == 3  # header + 2 blocked rows
    assert "network_egress" in lines[1] and "fake.network.egress" in lines[1]
    assert "tool_call" in lines[2] and "fetch" in lines[2]


def test_cli_with_an_explicit_audit_path(tmp_path: Path) -> None:
    audit = _audit(tmp_path / "x.sqlite")
    completed = _run("--audit", str(audit), "--limit", "2", cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert len(completed.stdout.splitlines()) == 3


def test_cli_missing_audit_file_is_an_error(tmp_path: Path) -> None:
    completed = _run("--audit", str(tmp_path / "none.sqlite"), cwd=tmp_path)
    assert completed.returncode == 1
    assert "no audit log" in completed.stderr
    assert not (tmp_path / "none.sqlite").exists()  # read-only: never creates it
