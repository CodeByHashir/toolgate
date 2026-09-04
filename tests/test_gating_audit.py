"""Tests for the decision log store."""

from __future__ import annotations

from pathlib import Path

from llmshield_mcp.gating.audit import (
    Decision,
    DecisionLog,
    DecisionRecord,
    Outcome,
    decision_log,
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
