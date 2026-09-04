"""Tests for the interception layer.

The gate is driven directly with JSON-RPC frames -- no MCP servers, no network.
What is under test is which frames produce which log rows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import mcp_types
import pytest
from mcp.shared.message import SessionMessage

from llmshield_mcp.gating.audit import Decision, DecisionLog, Outcome
from llmshield_mcp.gating.transport import (
    Gate,
    GateConfig,
    _ObservedReadStream,
    _ObservedWriteStream,
    gating_transport,
)


@pytest.fixture
def log(tmp_path: Path) -> DecisionLog:
    return DecisionLog(tmp_path / "decisions.sqlite")


@pytest.fixture
def gate(log: DecisionLog) -> Gate:
    return Gate("filesystem", log)


def call_request(request_id: Any, tool: str = "read_text_file") -> SessionMessage:
    return SessionMessage(
        mcp_types.JSONRPCRequest(
            jsonrpc="2.0",
            id=request_id,
            method="tools/call",
            params={"name": tool, "arguments": {"path": "README.md"}},
        )
    )


def call_response(request_id: Any, text: str = "hello") -> SessionMessage:
    return SessionMessage(
        mcp_types.JSONRPCResponse(
            jsonrpc="2.0",
            id=request_id,
            result={"content": [{"type": "text", "text": text}], "isError": False},
        )
    )


def error_response(request_id: Any, code: int = -32602) -> SessionMessage:
    return SessionMessage(
        mcp_types.JSONRPCError(
            jsonrpc="2.0",
            id=request_id,
            error=mcp_types.ErrorData(code=code, message="Invalid params"),
        )
    )


# --- the happy path -------------------------------------------------------


def test_one_tool_call_produces_exactly_one_row(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(call_response(1))

    rows = log.rows()
    assert len(rows) == 1
    assert rows[0]["tool_name"] == "read_text_file"
    assert rows[0]["mcp_server_id"] == "filesystem"
    assert rows[0]["outcome"] == Outcome.RESULT
    assert rows[0]["fused_decision"] == Decision.ALLOW


def test_m2_records_no_detector_scores_and_never_redacts(gate: Gate, log: DecisionLog) -> None:
    # M2 is logging only. If either of these changes, detection leaked in early.
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(call_response(1))

    row = log.rows()[0]
    assert row["detector_scores"] == "{}"
    assert row["redacted"] == 0


def test_content_is_hashed_not_stored(gate: Gate, log: DecisionLog) -> None:
    # Section 12: the audit store must not become a corpus of adversarial text.
    secret = "a very distinctive payload string"
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(call_response(1, text=secret))

    row = log.rows()[0]
    assert secret not in " ".join(str(v) for v in tuple(row))
    assert len(row["raw_result_hash"]) == 64


def test_string_request_ids_work_as_well_as_numeric(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request("abc"))
    gate.observe_inbound(call_response("abc"))

    assert log.count() == 1


# --- FR-15: protocol errors ----------------------------------------------


def test_protocol_error_is_logged_under_its_own_outcome(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(error_response(1))

    row = log.rows()[0]
    assert row["outcome"] == Outcome.PROTOCOL_ERROR
    assert row["raw_result_hash"] == ""
    assert row["content_chars"] == 0
    assert "-32602" in row["note"]


def test_transport_exception_is_not_logged_as_a_result(gate: Gate, log: DecisionLog) -> None:
    # The read stream can yield an Exception instead of a message. It carries
    # no tool content and must not become a decision row.
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(ConnectionResetError("pipe closed"))

    assert log.count() == 0


# --- frames that are not tool results -------------------------------------


def test_untracked_responses_are_ignored(gate: Gate, log: DecisionLog) -> None:
    # initialize, tools/list and server-initiated requests are out of scope.
    gate.observe_inbound(call_response(99))

    assert log.count() == 0


def test_non_tool_call_requests_are_not_tracked(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(
        SessionMessage(mcp_types.JSONRPCRequest(jsonrpc="2.0", id=7, method="tools/list"))
    )
    gate.observe_inbound(call_response(7))

    assert log.count() == 0
    assert gate.pending_count == 0


def test_notifications_do_not_create_rows(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(
        SessionMessage(
            mcp_types.JSONRPCNotification(jsonrpc="2.0", method="notifications/initialized")
        )
    )

    assert log.count() == 0


# --- section 19: interleaving and state -----------------------------------


def test_interleaved_calls_are_attributed_correctly(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request(1, tool="read_text_file"))
    gate.observe_outbound(call_request(2, tool="list_directory"))
    # Responses arrive out of order, which is legal.
    gate.observe_inbound(call_response(2))
    gate.observe_inbound(call_response(1))

    rows = log.rows()
    assert [r["tool_name"] for r in rows] == ["list_directory", "read_text_file"]
    assert rows[0]["correlation_id"] != rows[1]["correlation_id"]


def test_correlation_ids_are_unique_per_call(gate: Gate, log: DecisionLog) -> None:
    for i in range(20):
        gate.observe_outbound(call_request(i))
        gate.observe_inbound(call_response(i))

    ids = {row["correlation_id"] for row in log.rows()}
    assert len(ids) == 20


def test_twenty_sequential_calls_produce_twenty_rows_and_no_state(
    gate: Gate, log: DecisionLog
) -> None:
    """NFR-5: 20+ calls without memory growth or state leakage."""
    for i in range(25):
        gate.observe_outbound(call_request(i))
        gate.observe_inbound(call_response(i))

    assert log.count() == 25
    assert gate.pending_count == 0


def test_cancellation_clears_the_pending_entry(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request(1))
    gate.observe_outbound(
        SessionMessage(
            mcp_types.JSONRPCNotification(
                jsonrpc="2.0",
                method="notifications/cancelled",
                params={"requestId": 1, "reason": "user cancelled"},
            )
        )
    )

    assert gate.pending_count == 0
    assert log.count() == 0


def test_unanswered_calls_are_evicted_rather_than_accumulating(log: DecisionLog) -> None:
    # NFR-5 again: responses that never arrive must not grow the map forever.
    gate = Gate("filesystem", log, GateConfig(max_pending=4))

    for i in range(10):
        gate.observe_outbound(call_request(i))

    assert gate.pending_count == 4
    # Every eviction is recorded, so lost calls are visible rather than silent.
    assert log.count() == 6
    assert all(r["outcome"] == Outcome.PROTOCOL_ERROR for r in log.rows())


# --- size policy through the gate -----------------------------------------


def test_oversized_result_is_flagged_in_the_log(log: DecisionLog) -> None:
    gate = Gate("filesystem", log, GateConfig(max_result_chars=50))
    gate.observe_outbound(call_request(1))
    gate.observe_inbound(call_response(1, text="x" * 500))

    row = log.rows()[0]
    assert row["truncated"] == 1
    assert row["content_chars"] == 500


# --- the stream wrappers ---------------------------------------------------


class _FakeReadStream:
    def __init__(self, items: list[Any]) -> None:
        self.items = list(items)
        self.closed = False

    async def receive(self) -> Any:
        return self.items.pop(0)

    async def aclose(self) -> None:
        self.closed = True

    def __aiter__(self) -> _FakeReadStream:
        return self

    async def __anext__(self) -> Any:
        if not self.items:
            raise StopAsyncIteration
        return self.items.pop(0)

    async def __aenter__(self) -> _FakeReadStream:
        return self

    async def __aexit__(self, *_: Any) -> bool:
        return False

    @property
    def last_context(self) -> str:
        return "inner-context"


class _FakeWriteStream:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    async def send(self, item: Any, /) -> None:
        self.sent.append(item)

    async def aclose(self) -> None:
        pass

    async def __aenter__(self) -> _FakeWriteStream:
        return self

    async def __aexit__(self, *_: Any) -> bool:
        return False


async def test_read_wrapper_forwards_the_identical_object(gate: Gate) -> None:
    """Transparency (AC-1): the session must receive exactly what arrived."""
    message = call_response(1)
    stream = _ObservedReadStream(_FakeReadStream([message]), gate)

    assert await stream.receive() is message


async def test_write_wrapper_forwards_the_identical_object(gate: Gate) -> None:
    inner = _FakeWriteStream()
    message = call_request(1)

    await _ObservedWriteStream(inner, gate).send(message)

    assert inner.sent == [message]
    assert inner.sent[0] is message


async def test_iteration_also_observes(gate: Gate, log: DecisionLog) -> None:
    gate.observe_outbound(call_request(1))
    stream = _ObservedReadStream(_FakeReadStream([call_response(1)]), gate)

    async for _ in stream:
        pass

    assert log.count() == 1


async def test_unknown_attributes_delegate_to_the_inner_stream(gate: Gate) -> None:
    # The SDK reads `last_context` off the stream; a wrapper that hides it
    # would silently change session behaviour.
    stream = _ObservedReadStream(_FakeReadStream([]), gate)

    assert stream.last_context == "inner-context"


async def test_gating_transport_wraps_both_streams(gate: Gate, log: DecisionLog) -> None:
    from contextlib import asynccontextmanager

    inner_read = _FakeReadStream([call_response(1)])
    inner_write = _FakeWriteStream()

    @asynccontextmanager
    async def inner() -> Any:
        yield inner_read, inner_write

    async with gating_transport(inner(), gate) as (read, write):
        await write.send(call_request(1))
        await read.receive()

    assert log.count() == 1
    assert inner_write.sent  # the frame really reached the inner transport
