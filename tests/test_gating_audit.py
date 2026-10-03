"""Tests for the decision log store."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from toolgate.gating.audit import (
    AuditFailure,
    AuditWriter,
    Decision,
    DecisionLog,
    DecisionRecord,
    Outcome,
    decision_log,
    default_audit_path,
)


def _record(**overrides: object) -> DecisionRecord:
    fields: dict[str, object] = {
        "correlation_id": "cid",
        "mcp_server_id": "filesystem",
        "raw_result_hash": "0" * 64,
        "fused_decision": Decision.ALLOW,
        "latency_ms": 0.4,
    }
    fields.update(overrides)
    return DecisionRecord(**fields)  # type: ignore[arg-type]


def test_append_and_read_back(tmp_path: Path) -> None:
    log = DecisionLog(tmp_path / "d.sqlite")
    log.append(_record(tool_name="read_text_file"))

    rows = log.rows()
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "read_text_file"
    assert rows[0]["fused_decision"] == "allow"


def test_timestamp_is_filled_in_when_absent(tmp_path: Path) -> None:
    log = DecisionLog(tmp_path / "d.sqlite")
    log.append(_record())

    assert log.rows()[0]["timestamp"].startswith("20")


def test_explicit_timestamp_is_preserved(tmp_path: Path) -> None:
    log = DecisionLog(tmp_path / "d.sqlite")
    log.append(_record(timestamp="2026-01-01T00:00:00+00:00"))

    assert log.rows()[0]["timestamp"] == "2026-01-01T00:00:00+00:00"


def test_detector_scores_and_block_types_round_trip_as_json(tmp_path: Path) -> None:
    log = DecisionLog(tmp_path / "d.sqlite")
    log.append(_record(detector_scores={"v0": 0.5}, block_types=("text", "image")))

    row = log.rows()[0]
    assert row["detector_scores"] == '{"v0": 0.5}'
    assert row["block_types"] == '["text", "image"]'


def test_log_is_append_only_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "d.sqlite"
    with decision_log(path) as log:
        log.append(_record())
    with decision_log(path) as log:
        log.append(_record())
        assert log.count() == 2


def test_every_outcome_and_decision_value_is_storable(tmp_path: Path) -> None:
    # The vocabulary is fixed in M2 so later milestones do not change the schema.
    log = DecisionLog(tmp_path / "d.sqlite")
    for decision in Decision:
        for outcome in Outcome:
            log.append(_record(fused_decision=decision, outcome=outcome))

    assert log.count() == len(Decision) * len(Outcome)


def test_gate_latency_and_server_roundtrip_are_separate_columns(tmp_path: Path) -> None:
    # Conflating them would make NFR-1 unmeasurable: server time would swamp
    # the gate overhead the requirement is actually about.
    log = DecisionLog(tmp_path / "d.sqlite")
    log.append(_record(latency_ms=0.2, roundtrip_ms=512.0))

    row = log.rows()[0]
    assert row["latency_ms"] == 0.2
    assert row["roundtrip_ms"] == 512.0


class TestInMemoryLog:
    """`DecisionLog(None)` is what lets gating run without persisting anything.

    Before it existed the CLI could not offer that: interception was switched
    on by supplying a `--db` path, so "gate but do not write an audit file"
    was unreachable and the default was "neither".
    """

    def test_none_path_writes_nothing_to_disk(self, tmp_path: Path) -> None:
        before = set(tmp_path.iterdir())
        log = DecisionLog(None)
        log.append(_record())

        assert log.count() == 1
        assert set(tmp_path.iterdir()) == before

    def test_persistent_flag_distinguishes_the_two(self, tmp_path: Path) -> None:
        assert DecisionLog(None).persistent is False
        assert DecisionLog(tmp_path / "d.sqlite").persistent is True

    def test_in_memory_rows_are_readable_before_close(self) -> None:
        log = DecisionLog(None)
        log.append(_record(tool_name="read_text_file"))

        assert log.rows()[0]["tool_name"] == "read_text_file"

    def test_context_manager_accepts_none(self) -> None:
        with decision_log(None) as log:
            log.append(_record())
            assert log.count() == 1


def test_the_log_exposes_no_mutation_api() -> None:
    """Append-only is a property of the class, not just a convention.

    M12's session accumulator added an `update_note` UPDATE; both were removed.
    This test fails if a future change reintroduces a way to alter a written
    row, which would break the audit guarantee quietly.
    """
    mutators = [
        name
        for name in dir(DecisionLog)
        if not name.startswith("_")
        and any(verb in name for verb in ("update", "delete", "remove", "set_", "edit"))
    ]
    assert mutators == []


# --- T7: per-server audit files, WAL, and the failure rule (design D9, D10, D17) ---


def test_file_backed_logs_use_wal_and_normal_sync(tmp_path: Path) -> None:
    """D17: no fsync per commit, so the audit write stays off the tool call's path."""
    log = DecisionLog(tmp_path / "d.sqlite")
    try:
        mode = log._connection.execute("PRAGMA journal_mode").fetchone()[0]
        sync = log._connection.execute("PRAGMA synchronous").fetchone()[0]
        timeout = log._connection.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        log.close()
    assert mode == "wal"
    assert sync == 1  # NORMAL
    assert timeout == 2000


def test_in_memory_logs_are_unaffected() -> None:
    with decision_log(None) as log:
        log.append(_record())
        assert log.count() == 1


def test_default_audit_path_is_one_file_per_server(tmp_path: Path) -> None:
    """D9: separate files remove cross-process lock contention by default."""
    assert default_audit_path(tmp_path, "fetch") == tmp_path / "audit" / "fetch.sqlite"
    assert default_audit_path(tmp_path, "fetch") != default_audit_path(tmp_path, "filesystem")


_WRITER = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from toolgate.gating.audit import Decision, DecisionLog, DecisionRecord
    log = DecisionLog(Path(sys.argv[1]))
    name = sys.argv[2]
    for i in range(int(sys.argv[3])):
        log.append(DecisionRecord(correlation_id=f"{name}-{i}", mcp_server_id=name,
                                  raw_result_hash="", fused_decision=Decision.ALLOW,
                                  latency_ms=0.0))
    log.close()
    """
)


def test_two_processes_can_write_one_shared_path(tmp_path: Path) -> None:
    """D9: a shared path is allowed; WAL plus a bounded busy timeout lets both write."""
    path = tmp_path / "shared.sqlite"
    rows = 200
    writers = [
        subprocess.Popen([sys.executable, "-c", _WRITER, str(path), name, str(rows)])
        for name in ("fetch", "filesystem")
    ]
    assert [w.wait(timeout=120) for w in writers] == [0, 0]
    log = DecisionLog(path)
    try:
        assert log.count() == 2 * rows
        servers = {row["mcp_server_id"] for row in log.rows()}
    finally:
        log.close()
    assert servers == {"fetch", "filesystem"}


class _BrokenLog:
    """A DecisionLog stand-in whose writes fail until told otherwise."""

    def __init__(self) -> None:
        self.failing = True
        self.written: list[DecisionRecord] = []

    def append(self, record: DecisionRecord) -> None:
        if self.failing:
            raise sqlite3.OperationalError("database is locked")
        self.written.append(record)


class TestAuditWriter:
    """D10: a failed write never changes a decision; persistent failure is loud."""

    def test_a_failure_is_reported_and_counted_not_raised(self) -> None:
        messages: list[str] = []
        writer = AuditWriter(_BrokenLog(), report=messages.append)  # type: ignore[arg-type]
        assert writer.append(_record()) is False
        assert writer.consecutive_failures == 1
        assert len(messages) == 1 and "database is locked" in messages[0]

    def test_success_resets_the_counter(self) -> None:
        log = _BrokenLog()
        writer = AuditWriter(log, report=lambda _m: None)  # type: ignore[arg-type]
        for _ in range(9):
            writer.append(_record())
        log.failing = False
        assert writer.append(_record()) is True
        assert writer.consecutive_failures == 0
        log.failing = True
        for _ in range(9):
            writer.append(_record())  # nine more: still under the limit

    def test_the_tenth_consecutive_failure_raises(self) -> None:
        writer = AuditWriter(_BrokenLog(), report=lambda _m: None)  # type: ignore[arg-type]
        for _ in range(9):
            assert writer.append(_record()) is False
        with pytest.raises(AuditFailure, match="10 consecutive"):
            writer.append(_record())

    def test_the_limit_is_configurable(self) -> None:
        writer = AuditWriter(_BrokenLog(), report=lambda _m: None, max_consecutive_failures=2)  # type: ignore[arg-type]
        writer.append(_record())
        with pytest.raises(AuditFailure):
            writer.append(_record())

    def test_the_report_never_contains_record_content(self) -> None:
        messages: list[str] = []
        writer = AuditWriter(_BrokenLog(), report=messages.append)  # type: ignore[arg-type]
        writer.append(_record(note="rule fetch.fetch.egress", tool_name="secret_tool_xyz"))
        assert "secret_tool_xyz" not in messages[0]
