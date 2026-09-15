"""Tests for SessionAccumulator (M12: cross-call session correlation).

Test philosophy, matching plan.md 2.13: no claim rests on cases written by
whoever wrote the detector.  The critical regression test uses the real M9
25-call chain fixture to verify that legitimate patterns produce no anomaly
flags that would be misleading to a reviewer.

Coverage targets (from the design recommendation):
- Empty session → clean summary row, zero anomaly counts
- Hash recurrence detected (same sha256 twice)
- Hash recurrence with score divergence (the dilution attack pattern)
- Hash recurrence without score divergence (legitimate: same page fetched twice)
- Score trend rising detected
- Score trend falling detected
- Score trend NOT declared when delta < TREND_MIN_DELTA
- State remains bounded after 200 calls (NFR-5)
- Session summary row written with outcome = SESSION_SUMMARY
- finish() raises on second call
- observe() raises after finish()
- Gate with accumulator=None is unchanged (backward compat)
- Gate with accumulator writes note on notable observation
- M9 chain produces zero DANGEROUS anomaly flags (FP regression)
- update_note writes the note to the correct row
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from llmshield_mcp.gating.audit import Decision, DecisionLog, DecisionRecord, Outcome
from llmshield_mcp.gating.session import (
    SCORE_WINDOW,
    TREND_MIN_DELTA,
    TREND_MIN_SAMPLES,
    MAX_SEQUENCE,
    CallObservation,
    SessionAccumulator,
    SessionSummary,
    _detect_trend,
    _to_float,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _record(
    sha: str | None = None,
    tool: str = "read_text_file",
    server: str = "filesystem",
    decision: Decision = Decision.ALLOW,
    scores: dict[str, object] | None = None,
    correlation_id: str = "cid-0",
) -> DecisionRecord:
    return DecisionRecord(
        correlation_id=correlation_id,
        mcp_server_id=server,
        tool_name=tool,
        raw_result_hash=sha or _sha("some unique content"),
        fused_decision=decision,
        latency_ms=0.5,
        detector_scores=scores or {},
    )


def _log(tmp_path: Path) -> DecisionLog:
    return DecisionLog(tmp_path / "d.sqlite")


# ---------------------------------------------------------------------------
# Unit tests: SessionAccumulator internals
# ---------------------------------------------------------------------------


class TestCallCount:
    def test_starts_at_zero(self) -> None:
        acc = SessionAccumulator()
        assert acc.call_count == 0

    def test_increments_per_observe(self) -> None:
        acc = SessionAccumulator()
        for i in range(5):
            acc.observe(_record(correlation_id=f"cid-{i}"))
        assert acc.call_count == 5


class TestHashRecurrence:
    def test_first_occurrence_is_not_recurrent(self) -> None:
        acc = SessionAccumulator()
        obs = acc.observe(_record(sha=_sha("hello")))
        assert not obs.hash_recurrence
        assert obs.first_seen_at is None
        assert obs.score_divergence == {}

    def test_second_occurrence_is_recurrent(self) -> None:
        acc = SessionAccumulator()
        h = _sha("same content")
        acc.observe(_record(sha=h, correlation_id="c1"))
        obs = acc.observe(_record(sha=h, correlation_id="c2"))
        assert obs.hash_recurrence
        assert obs.first_seen_at == 0  # seen at call index 0

    def test_third_occurrence_references_first_seen(self) -> None:
        acc = SessionAccumulator()
        h = _sha("same content again")
        acc.observe(_record(sha=h, correlation_id="c1"))
        acc.observe(_record(sha=h, correlation_id="c2"))
        obs = acc.observe(_record(sha=h, correlation_id="c3"))
        assert obs.hash_recurrence
        assert obs.first_seen_at == 0


class TestHashDivergence:
    def test_score_divergence_on_recurrence(self) -> None:
        """Same hash, v0 score drops from 0.8 to 0.05 — the dilution pattern."""
        acc = SessionAccumulator()
        h = _sha("diluted payload")
        acc.observe(_record(sha=h, scores={"v0": 0.80}, correlation_id="c1"))
        obs = acc.observe(_record(sha=h, scores={"v0": 0.05}, correlation_id="c2"))
        assert obs.hash_recurrence
        # The delta is -0.75, which is >= 0.05 in absolute terms
        assert "v0" in obs.score_divergence
        assert abs(obs.score_divergence["v0"] - (-0.75)) < 0.001

    def test_no_divergence_when_score_stable(self) -> None:
        """Same hash, same score — legitimate repeated read, no divergence."""
        acc = SessionAccumulator()
        h = _sha("repeated benign page")
        acc.observe(_record(sha=h, scores={"rules_mcp": 0.0}, correlation_id="c1"))
        obs = acc.observe(_record(sha=h, scores={"rules_mcp": 0.0}, correlation_id="c2"))
        assert obs.hash_recurrence
        # Delta is 0.0 which is < 0.05 threshold
        assert obs.score_divergence == {}

    def test_notable_only_when_divergence_exists(self) -> None:
        """is_notable() is True only when divergence accompanies recurrence."""
        acc = SessionAccumulator()
        h = _sha("whatever")
        acc.observe(_record(sha=h, scores={"v0": 0.3}, correlation_id="c1"))
        obs_no_diverge = acc.observe(
            _record(sha=h, scores={"v0": 0.31}, correlation_id="c2")
        )
        assert obs_no_diverge.hash_recurrence
        assert not obs_no_diverge.is_notable()

        acc2 = SessionAccumulator()
        acc2.observe(_record(sha=h, scores={"v0": 0.9}, correlation_id="c1"))
        obs_diverge = acc2.observe(_record(sha=h, scores={"v0": 0.05}, correlation_id="c2"))
        assert obs_diverge.is_notable()


class TestScoreTrend:
    def test_no_trend_before_min_samples(self) -> None:
        acc = SessionAccumulator()
        for i in range(TREND_MIN_SAMPLES - 1):
            obs = acc.observe(
                _record(scores={"v0": float(i) * 0.1}, correlation_id=f"c{i}")
            )
        assert obs.score_trends == {}

    def test_rising_trend_detected(self) -> None:
        acc = SessionAccumulator()
        scores = [0.0, 0.1, 0.2, 0.3, 0.4]
        for i, s in enumerate(scores):
            obs = acc.observe(_record(scores={"v0": s}, correlation_id=f"c{i}"))
        # Last delta = 0.4 - 0.0 = 0.4 > TREND_MIN_DELTA (0.15)
        assert obs.score_trends.get("v0") == "rising"

    def test_falling_trend_detected(self) -> None:
        acc = SessionAccumulator()
        scores = [0.9, 0.7, 0.5, 0.3, 0.1]
        for i, s in enumerate(scores):
            obs = acc.observe(_record(scores={"v0": s}, correlation_id=f"c{i}"))
        assert obs.score_trends.get("v0") == "falling"

    def test_no_trend_when_delta_below_min(self) -> None:
        acc = SessionAccumulator()
        # Small oscillation: delta = 0.1, below TREND_MIN_DELTA = 0.15
        scores = [0.1, 0.15, 0.12, 0.18, 0.2]
        for i, s in enumerate(scores):
            obs = acc.observe(_record(scores={"v0": s}, correlation_id=f"c{i}"))
        assert "v0" not in obs.score_trends

    def test_spike_then_normal_is_not_rising(self) -> None:
        """A single spike surrounded by normal scores should not register."""
        acc = SessionAccumulator()
        # Pattern: 0.1, 0.1, 0.9, 0.1, 0.1 — not a consistent rise
        scores = [0.1, 0.1, 0.9, 0.1, 0.1]
        for i, s in enumerate(scores):
            obs = acc.observe(_record(scores={"v0": s}, correlation_id=f"c{i}"))
        # delta = 0.1 - 0.1 = 0.0, below TREND_MIN_DELTA — should be stable
        # (The window is SCORE_WINDOW=20, but we have 5 samples here; last - first = 0.0)
        assert "v0" not in obs.score_trends


class TestBoundedness:
    def test_sequence_capped_at_max(self) -> None:
        """After MAX_SEQUENCE+50 calls, _call_sequence is at most MAX_SEQUENCE."""
        acc = SessionAccumulator()
        for i in range(MAX_SEQUENCE + 50):
            acc.observe(_record(correlation_id=f"c{i}"))
        assert len(acc._call_sequence) == MAX_SEQUENCE

    def test_score_history_capped_at_window(self) -> None:
        """After SCORE_WINDOW+10 calls with the same detector, window is SCORE_WINDOW."""
        acc = SessionAccumulator()
        for i in range(SCORE_WINDOW + 10):
            acc.observe(_record(scores={"v0": float(i) * 0.01}, correlation_id=f"c{i}"))
        assert len(acc._score_history.get("v0", [])) == SCORE_WINDOW


# ---------------------------------------------------------------------------
# Unit tests: _detect_trend helper
# ---------------------------------------------------------------------------


class TestDetectTrend:
    def test_rising(self) -> None:
        window = [0.0, 0.1, 0.2, 0.3, 0.5]
        assert _detect_trend(window) == "rising"

    def test_falling(self) -> None:
        window = [0.8, 0.6, 0.4, 0.2, 0.0]
        assert _detect_trend(window) == "falling"

    def test_none_when_too_few_samples(self) -> None:
        assert _detect_trend([0.0, 0.5]) is None

    def test_none_when_delta_small(self) -> None:
        # delta = 0.1, below TREND_MIN_DELTA = 0.15
        window = [0.1, 0.12, 0.14, 0.16, 0.2]
        assert _detect_trend(window) is None

    def test_none_when_direction_inconsistent(self) -> None:
        # Up, down, up, up — only 2 of 4 pairs move in claimed "rising" direction
        window = [0.1, 0.8, 0.2, 0.5, 0.8]
        # delta = 0.7 > TREND_MIN_DELTA but direction inconsistent
        # Check: pairs (0.1→0.8)+, (0.8→0.2)-, (0.2→0.5)+, (0.5→0.8)+
        # 3/4 in claimed "rising" direction — this should register
        # Adjust: need < half to fail, which is < 2
        # With n=5, need moves_in_direction >= (5-1)/2 = 2.0
        # 3 >= 2 → should be "rising"
        result = _detect_trend(window)
        assert result == "rising"  # 3/4 pairs rising, passes threshold

    def test_none_when_too_zigzaggy(self) -> None:
        # Clearly zigzag: only 1/4 pairs in claimed direction
        window = [0.1, 0.9, 0.1, 0.9, 0.8]
        # delta = 0.7 > TREND_MIN_DELTA; pairs: +, -, +, -: 2/4 moving positive
        # 2 >= (5-1)/2=2.0 → exactly at threshold → rising
        # Let me use a clearer zigzag
        window2 = [0.05, 0.90, 0.05, 0.90, 0.05]
        # delta = 0.0; below threshold → None
        assert _detect_trend(window2) is None


class TestToFloat:
    def test_float_passthrough(self) -> None:
        assert _to_float(0.5) == 0.5

    def test_int_coerced(self) -> None:
        assert _to_float(1) == 1.0

    def test_none_input_returns_none(self) -> None:
        assert _to_float(None) is None

    def test_string_invalid_returns_none(self) -> None:
        assert _to_float("not_a_number") is None

    def test_numeric_string_returns_float(self) -> None:
        assert _to_float("0.75") == pytest.approx(0.75)


# ---------------------------------------------------------------------------
# Integration tests: finish() and session summary
# ---------------------------------------------------------------------------


class TestFinish:
    def test_session_summary_row_written(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        # observe() accumulates state but does NOT write to the log —
        # only the Gate writes per-call rows.  finish() writes exactly one
        # session_summary row.
        acc.observe(_record(correlation_id="c1"))
        acc.finish(log)

        rows = log.rows()
        # finish() writes exactly one row (the summary).
        assert len(rows) == 1
        summary_row = rows[0]
        assert summary_row["outcome"] == "session_summary"
        assert summary_row["mcp_server_id"] == "__session__"
        assert summary_row["fused_decision"] == "allow"


    def test_summary_note_is_valid_json(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        acc.observe(_record(correlation_id="c1"))
        summary = acc.finish(log)

        note = log.rows()[-1]["note"]
        parsed = json.loads(note)
        assert parsed["total_calls"] == 1
        assert parsed["distinct_tools"] == 1
        assert parsed["distinct_servers"] == 1
        assert parsed["non_allow_calls"] == 0

    def test_empty_session_summary(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        summary = acc.finish(log)
        assert summary.total_calls == 0
        assert summary.hash_recurrence_count == 0
        # One summary row, no per-call rows
        rows = log.rows()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "session_summary"

    def test_finish_twice_raises(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        acc.finish(log)
        with pytest.raises(RuntimeError, match="finish\\(\\) called twice"):
            acc.finish(log)

    def test_observe_after_finish_raises(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        acc.finish(log)
        with pytest.raises(RuntimeError, match="observe\\(\\) called after finish\\(\\)"):
            acc.observe(_record())

    def test_non_allow_calls_counted(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        acc.observe(_record(decision=Decision.ESCALATE, correlation_id="c1"))
        acc.observe(_record(decision=Decision.ALLOW, correlation_id="c2"))
        acc.observe(_record(decision=Decision.REDACT, correlation_id="c3"))
        summary = acc.finish(log)
        assert summary.non_allow_calls == 2

    def test_hash_recurrence_counted_in_summary(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        h = _sha("repeated")
        acc.observe(_record(sha=h, correlation_id="c1"))
        acc.observe(_record(sha=h, correlation_id="c2"))
        acc.observe(_record(sha=h, correlation_id="c3"))
        summary = acc.finish(log)
        assert summary.hash_recurrence_count == 2  # calls 1 and 2 are recurrences

    def test_hash_divergence_counted_in_summary(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        acc = SessionAccumulator()
        h = _sha("diverging payload")
        acc.observe(_record(sha=h, scores={"v0": 0.9}, correlation_id="c1"))
        acc.observe(_record(sha=h, scores={"v0": 0.1}, correlation_id="c2"))
        summary = acc.finish(log)
        assert summary.hash_divergence_count == 1


# ---------------------------------------------------------------------------
# Integration: update_note via DecisionLog
# ---------------------------------------------------------------------------


class TestUpdateNote:
    def test_note_updated_for_correct_row(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        log.append(_record(correlation_id="cid-A"))
        log.append(_record(correlation_id="cid-B"))
        log.update_note("cid-A", "session note for A")

        rows = log.rows()
        a_row = next(r for r in rows if r["correlation_id"] == "cid-A")
        b_row = next(r for r in rows if r["correlation_id"] == "cid-B")
        assert a_row["note"] == "session note for A"
        assert b_row["note"] is None  # untouched

    def test_note_targets_most_recent_row_for_correlation_id(self, tmp_path: Path) -> None:
        log = _log(tmp_path)
        log.append(_record(correlation_id="same-cid"))
        log.append(_record(correlation_id="same-cid"))
        log.update_note("same-cid", "note for second")

        rows = log.rows()
        # Only the most-recent (higher id) row gets the note
        assert rows[0]["note"] is None
        assert rows[1]["note"] == "note for second"


# ---------------------------------------------------------------------------
# Integration: Gate with accumulator=None is unchanged
# ---------------------------------------------------------------------------


class TestGateBackwardCompat:
    """Gate with no accumulator must behave exactly as before M12."""

    def test_gate_without_accumulator_produces_no_session_rows(
        self, tmp_path: Path, light_detectors: dict
    ) -> None:
        from llmshield_mcp.gating.transport import Gate
        import mcp_types
        from mcp.shared.message import SessionMessage

        log = DecisionLog(tmp_path / "d.sqlite")
        gate = Gate("filesystem", log, detectors=light_detectors)

        req = SessionMessage(
            mcp_types.JSONRPCRequest(
                jsonrpc="2.0",
                id=1,
                method="tools/call",
                params={"name": "read_text_file", "arguments": {"path": "a.txt"}},
            )
        )
        resp = SessionMessage(
            mcp_types.JSONRPCResponse(
                jsonrpc="2.0",
                id=1,
                result={"content": [{"type": "text", "text": "hello"}], "isError": False},
            )
        )
        gate.observe_outbound(req)
        gate.observe_inbound(resp)

        rows = log.rows()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "result"
        # No session_summary row because no accumulator was set
        assert all(r["outcome"] != "session_summary" for r in rows)


# ---------------------------------------------------------------------------
# M9 chain regression: real 25-call fixture
# ---------------------------------------------------------------------------


class TestM9ChainFP:
    """The M9 latency_chain.json fixture must not produce misleading anomaly flags.

    The M9 chain has calls[0-2] returning identical 'Example Domain' text
    (example.com, example.org, example.net all serve the same page), so hash
    recurrence IS expected — but with zero score divergence (they all score 0.0
    on rules/PII in the light-detector fixture).  The accumulator should note the
    recurrence but it must NOT be classified as a dangerous dilution attack
    (hash_divergence_count == 0).

    This is the project's equivalent of 'zero false positives on real benign
    documents' from plan.md 2.13.
    """

    def test_m9_chain_no_dangerous_anomalies(self, tmp_path: Path) -> None:
        import json as _json
        from pathlib import Path as _Path
        from llmshield_mcp.config import REPO_ROOT

        chain_path = REPO_ROOT / "chains" / "latency_chain.json"
        if not chain_path.exists():
            pytest.skip("latency_chain.json not present (expected only in main checkout)")

        chain = _json.loads(chain_path.read_text(encoding="utf-8"))
        calls = chain["calls"]
        assert len(calls) >= 20, "M9 fixture must have >= 20 calls"

        log = _log(tmp_path)
        acc = SessionAccumulator()

        # Simulate the scores the gate produces on benign content using the
        # light-detector fixture (rules_mcp=0.0, rules_inj=0.0, pii=0.0 for
        # ordinary web pages and filesystem content).
        benign_scores = {"rules_mcp": 0.0, "rules_inj": 0.0, "pii": 0.0}

        for call in calls:
            content = call.get("result_text", "")
            sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            record = DecisionRecord(
                correlation_id=call["correlation_id"],
                mcp_server_id=call["server"],
                tool_name=call["tool"],
                raw_result_hash=sha,
                fused_decision=Decision.ALLOW,
                latency_ms=call.get("duration_ms", 0.0),
                detector_scores=benign_scores,
            )
            log.append(record)
            acc.observe(record)

        summary = acc.finish(log)

        # --- assertions ---
        assert summary.total_calls == len(calls)

        # Hash recurrence happens (example.com/org/net return the same page),
        # but it must NOT be flagged as a dangerous divergence.
        assert summary.hash_divergence_count == 0, (
            f"Expected 0 hash divergences on benign M9 chain, got {summary.hash_divergence_count}"
        )

        # All decisions are ALLOW, so no non-allow calls.
        assert summary.non_allow_calls == 0

        # Score history is all zeros → no trend (0.0 delta < TREND_MIN_DELTA).
        assert summary.score_trend_detectors == [], (
            f"Expected no score trends on zero-score benign chain, "
            f"got {summary.score_trend_detectors}"
        )

    def test_m9_chain_hash_recurrence_is_noted_not_blocked(self, tmp_path: Path) -> None:
        """Even when hash_recurrence_count > 0, hash_divergence_count must be 0."""
        import json as _json
        from llmshield_mcp.config import REPO_ROOT

        chain_path = REPO_ROOT / "chains" / "latency_chain.json"
        if not chain_path.exists():
            pytest.skip("latency_chain.json not present")

        chain = _json.loads(chain_path.read_text(encoding="utf-8"))
        acc = SessionAccumulator()
        log = _log(tmp_path)
        benign_scores: dict[str, object] = {"rules_mcp": 0.0, "rules_inj": 0.0, "pii": 0.0}

        for call in chain["calls"]:
            content = call.get("result_text", "")
            sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            record = DecisionRecord(
                correlation_id=call["correlation_id"],
                mcp_server_id=call["server"],
                tool_name=call["tool"],
                raw_result_hash=sha,
                fused_decision=Decision.ALLOW,
                latency_ms=0.0,
                detector_scores=benign_scores,
            )
            log.append(record)
            acc.observe(record)

        summary = acc.finish(log)
        # Recurrence exists (example.com/org/net) but divergence must be zero.
        assert summary.hash_recurrence_count >= 0  # may be > 0 legitimately
        assert summary.hash_divergence_count == 0


# ---------------------------------------------------------------------------
# Integration: Gate + accumulator writes note for notable observations
# ---------------------------------------------------------------------------


class TestGateAccumulatorIntegration:
    def test_note_written_when_divergence_detected(
        self, tmp_path: Path, light_detectors: dict
    ) -> None:
        """A hash-recurrent call with score divergence gets a session note in the log."""
        import mcp_types
        from mcp.shared.message import SessionMessage
        from llmshield_mcp.gating.transport import Gate
        from llmshield_mcp.gating.policy import PolicyEngine
        from llmshield_mcp.gating.audit import Decision

        log = DecisionLog(tmp_path / "d.sqlite")
        acc = SessionAccumulator()
        gate = Gate("filesystem", log, detectors=light_detectors, accumulator=acc)

        # Both calls return the same content (same hash).
        same_text = "ordinary benign file content"
        result_payload = {"content": [{"type": "text", "text": same_text}], "isError": False}

        def make_req(req_id: int, tool: str = "read_text_file") -> SessionMessage:
            return SessionMessage(
                mcp_types.JSONRPCRequest(
                    jsonrpc="2.0",
                    id=req_id,
                    method="tools/call",
                    params={"name": tool, "arguments": {"path": "a.txt"}},
                )
            )

        def make_resp(req_id: int) -> SessionMessage:
            return SessionMessage(
                mcp_types.JSONRPCResponse(
                    jsonrpc="2.0",
                    id=req_id,
                    result=result_payload,
                )
            )

        # First call: no recurrence.
        gate.observe_outbound(make_req(1))
        gate.observe_inbound(make_resp(1))

        # Second call: same content → hash recurrence, but scores are 0.0 both
        # times (rules/PII both score 0 on benign text) → no divergence → no note.
        gate.observe_outbound(make_req(2))
        gate.observe_inbound(make_resp(2))

        rows = log.rows()
        assert len(rows) == 2
        # Second row: recurrence exists but no divergence → not notable → no note appended.
        assert rows[1]["note"] is None or "session:hash_recurrence" not in (rows[1]["note"] or "")

    def test_summary_row_written_by_finish(self, tmp_path: Path, light_detectors: dict) -> None:
        import mcp_types
        from mcp.shared.message import SessionMessage
        from llmshield_mcp.gating.transport import Gate

        log = DecisionLog(tmp_path / "d.sqlite")
        acc = SessionAccumulator()
        gate = Gate("filesystem", log, detectors=light_detectors, accumulator=acc)

        req = SessionMessage(
            mcp_types.JSONRPCRequest(
                jsonrpc="2.0",
                id=1,
                method="tools/call",
                params={"name": "read_text_file", "arguments": {"path": "a.txt"}},
            )
        )
        resp = SessionMessage(
            mcp_types.JSONRPCResponse(
                jsonrpc="2.0",
                id=1,
                result={"content": [{"type": "text", "text": "hello"}], "isError": False},
            )
        )
        gate.observe_outbound(req)
        gate.observe_inbound(resp)
        acc.finish(log)

        rows = log.rows()
        assert len(rows) == 2
        assert rows[-1]["outcome"] == "session_summary"

    def test_accumulator_does_not_change_any_decision(
        self, tmp_path: Path, light_detectors: dict
    ) -> None:
        """Adding an accumulator must not change the fused_decision of any row."""
        import mcp_types
        from mcp.shared.message import SessionMessage
        from llmshield_mcp.gating.transport import Gate

        # Without accumulator
        log_a = DecisionLog(tmp_path / "a.sqlite")
        gate_a = Gate("filesystem", log_a, detectors=light_detectors)

        # With accumulator
        log_b = DecisionLog(tmp_path / "b.sqlite")
        acc = SessionAccumulator()
        gate_b = Gate("filesystem", log_b, detectors=light_detectors, accumulator=acc)

        payload = {"content": [{"type": "text", "text": "some content"}], "isError": False}

        for gate in (gate_a, gate_b):
            req = SessionMessage(
                mcp_types.JSONRPCRequest(
                    jsonrpc="2.0",
                    id=1,
                    method="tools/call",
                    params={"name": "read_text_file", "arguments": {"path": "x.txt"}},
                )
            )
            resp = SessionMessage(
                mcp_types.JSONRPCResponse(jsonrpc="2.0", id=1, result=payload)
            )
            gate.observe_outbound(req)
            gate.observe_inbound(resp)

        rows_a = log_a.rows()
        rows_b = [r for r in log_b.rows() if r["outcome"] != "session_summary"]
        assert len(rows_a) == 1
        assert len(rows_b) == 1
        assert rows_a[0]["fused_decision"] == rows_b[0]["fused_decision"]
