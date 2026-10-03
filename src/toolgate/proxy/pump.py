"""The line pump of `toolgate wrap`: gate what crosses, forward the rest.

`toolgate wrap --name N --config C -- <server command>` sits between an MCP
host and one stdio server. `proxy/process.py` owns the server process; this
module owns the bytes. It reads newline-delimited JSON from each side, parses
every line only to decide, and forwards the **original bytes** of every line
it does not change. Only `tools/call` and `tools/list` are gated.

The logic lives in `ProxyCore`, which is synchronous and does no I/O: each
event (a client line, a server line, a timer tick) returns `Effects` -- bytes
for the server, bytes for the host, audit rows, stderr messages. `run_pump`
is the thin async loop around it. Keeping the decisions in plain functions of
their input is what lets every rule below be tested without processes.

Client -> server (design "Pump safety rules", D4, D5, D12, D13, R3-7)::

    line from host
      |-- longer than the cap ---------> id in first 4 KiB? -32600 : drop; log
      |-- not exactly one JSON value --> -32700, id null; log      (D5)
      |-- duplicate key / NaN ---------> -32600 if id unambiguous, else drop  (D4)
      |-- top-level array (batch) -----> -32600, id null; log      (R2-1)
      |-- request with invalid id -----> -32600, id null; log
      |-- request whose id is pending -> -32600 "duplicate request id" (D13)
      |-- method tools/call -----------> evaluate_tool_call(schema=declared)
      |       |-- block / bad params ----> local isError reply naming the rule;
      |       |                            nothing forwarded; id remembered
      |       |-- pending map full ------> local isError, rule <server>.<tool>.capacity
      |       '-- allow / escalate ------> ORIGINAL bytes forwarded; tracked
      |-- method tools/list -----------> full? -32000 (<server>.*.capacity)
      |                                  else ORIGINAL bytes forwarded; tracked
      |-- notifications/cancelled -----> for a locally answered id: dropped;
      |                                  for a tracked id: marked cancelled (D12)
      |                                  and forwarded
      '-- anything else ---------------> ORIGINAL bytes forwarded

A `tools/call` sent as a notification (no id) is gated too: a lenient server
may still run it. Blocked, it is dropped, since there is nothing to reply to.

Server -> client: see `ProxyCore.server_line`.

Each direction is one sequential loop (D14): read a line, decide, write,
then read the next. Order within a direction is therefore arrival order by
construction; a `notifications/cancelled` can never overtake its call.

Bookkeeping (R2-8, R2-9, D12, D13, R3-10): requests are tracked by
`lines.id_key`, so `"1"` and `1` are different. The pending map **blocks
when full and never evicts** -- eviction would let the evicted call's result
skip the result checks. Cancelled entries stay tracked (a late reply is still
inspected) but stop counting toward the limit. Entries unanswered for
`pending_timeout_s` (300 s) expire; a reply that arrives later is dropped.

Audit rows never hold an argument value, URL, path or result text (SEC-3):
rule ids, fixed reasons, hashes, timings.
"""

from __future__ import annotations

import sys
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

import anyio

from toolgate.gating.audit import AuditWriter, Decision, DecisionRecord, Outcome
from toolgate.gating.policy import PolicyConfig
from toolgate.gating.tool_calls import ToolDecision, evaluate_tool_call
from toolgate.proxy.lines import (
    MAX_LINE_BYTES,
    Eof,
    IdKey,
    Line,
    LineEvent,
    LineReader,
    Oversize,
    StrictJsonError,
    Tail,
    encode,
    id_from_prefix,
    id_key,
    loads_strict,
    top_level_ids,
)
from toolgate.proxy.process import ChildProcess, SessionEnd

TOOLS_CALL = "tools/call"
TOOLS_LIST = "tools/list"
CANCELLED = "notifications/cancelled"

# JSON-RPC error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INTERNAL_ERROR = -32603
#: Implementation-defined server error, used for "too many requests in flight".
SERVER_BUSY = -32000


@dataclass(frozen=True, slots=True)
class ProxySettings:
    """Everything the core needs, fixed when `wrap` starts."""

    #: `--name`, `[A-Za-z0-9_-]+`: the `<server>` part of every rule id.
    name: str
    policy: PolicyConfig
    max_line_bytes: int = MAX_LINE_BYTES
    #: Active (not cancelled) gated requests allowed in flight (R2-8).
    max_pending: int = 256
    #: Seconds before an unanswered gated request expires (D12).
    pending_timeout_s: float = 300.0
    #: How long, after the host closes stdin, to keep forwarding the server's
    #: remaining replies before ending the session anyway.
    drain_after_host_eof_s: float = 5.0


class Kind(Enum):
    CALL = "tools/call"
    LIST = "tools/list"


@dataclass(slots=True)
class Pending:
    """One forwarded `tools/call` or `tools/list` awaiting its reply."""

    kind: Kind
    tool: str
    request_id: Any
    correlation_id: str
    started: float
    cancelled: bool = False


@dataclass(slots=True)
class Effects:
    """What one event produced. Applied in this order by `run_pump`."""

    to_server: list[bytes] = field(default_factory=list)
    to_client: list[bytes] = field(default_factory=list)
    records: list[DecisionRecord] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    def extend(self, other: Effects) -> None:
        self.to_server += other.to_server
        self.to_client += other.to_client
        self.records += other.records
        self.messages += other.messages


def error_reply(request_id: Any, code: int, message: str) -> bytes:
    return encode({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


def blocked_reply(request_id: Any, rule: str) -> bytes:
    """The local answer to a refused `tools/call`. Never echoes an argument."""
    return encode(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": f"Blocked by toolgate policy: rule {rule}"}],
                "isError": True,
            },
        }
    )


class _BoundedSet:
    """Insertion-ordered set that forgets its oldest member past `limit`."""

    def __init__(self, limit: int) -> None:
        self._items: OrderedDict[IdKey, None] = OrderedDict()
        self._limit = limit

    def add(self, key: IdKey) -> None:
        self._items[key] = None
        self._items.move_to_end(key)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)

    def discard(self, key: IdKey) -> bool:
        return self._items.pop(key, False) is None

    def __contains__(self, key: object) -> bool:
        return key in self._items


class ProxyCore:
    """The gating decisions for one wrapped server. Synchronous, no I/O."""

    def __init__(self, settings: ProxySettings, *, clock: Callable[[], float] = time.monotonic):
        self.settings = settings
        self.name = settings.name
        self._clock = clock
        self.pending: dict[IdKey, Pending] = {}
        #: Ids the proxy answered itself (blocked calls), for dropping their
        #: `notifications/cancelled`. Bounded, oldest forgotten first.
        self.answered = _BoundedSet(settings.max_pending)
        #: Ids whose reply must be dropped if it ever arrives: expired, or
        #: answered by the proxy after a server line was dropped (D8, D12).
        self.closed = _BoundedSet(settings.max_pending * 4)
        #: Declared `inputSchema` per tool name, from `tools/list` replies.
        self.schemas: dict[str, Any] = {}

    # -- helpers ----------------------------------------------------------

    @property
    def active_pending(self) -> int:
        return sum(1 for entry in self.pending.values() if not entry.cancelled)

    def _record(
        self,
        *,
        decision: Decision,
        outcome: Outcome,
        note: str,
        tool: str | None = None,
        request_id: Any = None,
        correlation_id: str | None = None,
        started: float | None = None,
    ) -> DecisionRecord:
        return DecisionRecord(
            correlation_id=correlation_id or uuid.uuid4().hex,
            mcp_server_id=self.name,
            tool_name=tool,
            request_id=None if request_id is None else str(request_id),
            raw_result_hash="",
            fused_decision=decision,
            latency_ms=0.0 if started is None else (self._clock() - started) * 1000.0,
            outcome=outcome,
            note=note,
        )

    def _refuse_line(
        self, effects: Effects, reason: str, reply: bytes | None, request_id: Any = None
    ) -> Effects:
        if reply is not None:
            effects.to_client.append(reply)
        effects.records.append(
            self._record(
                decision=Decision.BLOCK,
                outcome=Outcome.PROTOCOL_ERROR,
                note=f"client line refused: {reason}",
                request_id=request_id,
            )
        )
        effects.messages.append(f"toolgate[{self.name}]: refused a client line ({reason})")
        return effects

    # -- client -> server -------------------------------------------------

    def client_event(self, event: LineEvent) -> Effects:
        if isinstance(event, Line):
            return self.client_line(event.data)
        if isinstance(event, Oversize):
            request_id = id_from_prefix(event.prefix)
            reply = (
                error_reply(request_id, INVALID_REQUEST, "line too long for toolgate")
                if request_id is not None
                else None
            )
            return self._refuse_line(
                Effects(), f"longer than {self.settings.max_line_bytes} bytes", reply, request_id
            )
        if isinstance(event, Tail):
            return self._refuse_line(Effects(), "unterminated final line", None)
        return Effects()

    def client_line(self, raw: bytes) -> Effects:
        effects = Effects()
        try:
            message = loads_strict(raw)
        except StrictJsonError as exc:
            if exc.kind == "parse":
                return self._refuse_line(
                    effects, str(exc), error_reply(None, PARSE_ERROR, "Parse error")
                )
            ids = top_level_ids(raw) or []
            reply = None
            request_id = None
            if len(ids) == 1 and id_key(ids[0]) is not None:
                request_id = ids[0]
                reply = error_reply(request_id, INVALID_REQUEST, f"Invalid Request: {exc}")
            return self._refuse_line(effects, str(exc), reply, request_id)

        if isinstance(message, list):
            return self._refuse_line(
                effects,
                "batch",
                error_reply(None, INVALID_REQUEST, "batches are not supported by toolgate"),
            )
        if not isinstance(message, dict):
            return self._refuse_line(
                effects, "not a JSON object", error_reply(None, PARSE_ERROR, "Parse error")
            )

        method = message.get("method")
        has_id = "id" in message

        if isinstance(method, str) and has_id:
            return self._client_request(raw, message, method)
        if method == TOOLS_CALL:
            return self._client_call_notification(raw, message)
        if method == CANCELLED:
            return self._client_cancelled(raw, message)
        effects.to_server.append(raw)
        return effects

    def _client_request(self, raw: bytes, message: dict[str, Any], method: str) -> Effects:
        effects = Effects()
        request_id = message["id"]
        key = id_key(request_id)
        if key is None:
            return self._refuse_line(
                effects,
                "invalid request id",
                error_reply(
                    None, INVALID_REQUEST, "Invalid Request: id must be a string or number"
                ),
            )
        if key in self.pending:
            return self._refuse_line(
                effects,
                "duplicate request id",
                error_reply(request_id, INVALID_REQUEST, "duplicate request id"),
                request_id,
            )
        # A reused id starts afresh: forget that it was answered or closed.
        self.answered.discard(key)
        self.closed.discard(key)

        if method == TOOLS_CALL:
            return self._client_call(raw, message, key)
        if method == TOOLS_LIST:
            return self._client_list(raw, request_id, key)
        effects.to_server.append(raw)
        return effects

    def _full(self) -> bool:
        # Cancelled entries do not count toward the limit (D12), but the map
        # as a whole is still bounded so cancellations cannot grow it freely;
        # expiry (300 s) is what empties it.
        return (
            self.active_pending >= self.settings.max_pending
            or len(self.pending) >= self.settings.max_pending * 4
        )

    def _judge_call(self, message: dict[str, Any]) -> tuple[str, str, ToolDecision, str]:
        """Return (tool, rule, decision, reason) for one `tools/call` message."""
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            return "*", f"{self.name}.*.args", ToolDecision.BLOCK, "params.name is not a string"
        arguments = params.get("arguments", {}) if isinstance(params, dict) else None
        if not isinstance(arguments, dict):
            return (
                name,
                f"{self.name}.{name}.args",
                ToolDecision.BLOCK,
                "arguments is not an object",
            )
        try:
            verdict = evaluate_tool_call(
                self.settings.policy.tool_calls,
                self.name,
                name,
                arguments,
                schema=self.schemas.get(name),
            )
        except Exception as exc:  # noqa: BLE001 -- fail closed on any gate error
            return (
                name,
                f"{self.name}.{name}.args",
                ToolDecision.BLOCK,
                f"internal error in the gate ({type(exc).__name__})",
            )
        return name, verdict.rule, verdict.decision, verdict.reason

    def _client_call(self, raw: bytes, message: dict[str, Any], key: IdKey) -> Effects:
        effects = Effects()
        started = self._clock()
        request_id = message["id"]
        correlation_id = uuid.uuid4().hex
        tool, rule, decision, reason = self._judge_call(message)

        if decision is not ToolDecision.BLOCK and self._full():
            rule, decision, reason = (
                f"{self.name}.{tool}.capacity",
                ToolDecision.BLOCK,
                "too many requests in flight",
            )

        if decision is ToolDecision.BLOCK:
            self.answered.add(key)
            effects.to_client.append(blocked_reply(request_id, rule))
            effects.messages.append(f"toolgate[{self.name}]: blocked {tool} (rule {rule})")
        else:
            effects.to_server.append(raw)
            self.pending[key] = Pending(Kind.CALL, tool, request_id, correlation_id, started)
            if decision is ToolDecision.ESCALATE:
                effects.messages.append(f"toolgate[{self.name}]: escalate {tool} (rule {rule})")

        if decision is not ToolDecision.ALLOW:
            effects.records.append(
                self._record(
                    decision=Decision.BLOCK
                    if decision is ToolDecision.BLOCK
                    else Decision.ESCALATE,
                    outcome=Outcome.TOOL_CALL,
                    note=f"rule {rule}: {reason}",
                    tool=tool,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    started=started,
                )
            )
        return effects

    def _client_call_notification(self, raw: bytes, message: dict[str, Any]) -> Effects:
        """A `tools/call` with no id. Nothing can be replied; gate it anyway."""
        effects = Effects()
        tool, rule, decision, reason = self._judge_call(message)
        if decision is ToolDecision.BLOCK:
            effects.messages.append(
                f"toolgate[{self.name}]: dropped {tool} sent without an id (rule {rule})"
            )
            effects.records.append(
                self._record(
                    decision=Decision.BLOCK,
                    outcome=Outcome.TOOL_CALL,
                    note=f"rule {rule}: {reason} (sent as a notification)",
                    tool=tool,
                )
            )
        else:
            effects.to_server.append(raw)
        return effects

    def _client_list(self, raw: bytes, request_id: Any, key: IdKey) -> Effects:
        effects = Effects()
        if self._full():
            rule = f"{self.name}.*.capacity"
            effects.to_client.append(
                error_reply(request_id, SERVER_BUSY, "toolgate: too many requests in flight")
            )
            effects.records.append(
                self._record(
                    decision=Decision.BLOCK,
                    outcome=Outcome.TOOL_DECLARATION,
                    note=f"rule {rule}: too many requests in flight",
                    request_id=request_id,
                )
            )
            effects.messages.append(f"toolgate[{self.name}]: refused tools/list (rule {rule})")
            return effects
        effects.to_server.append(raw)
        self.pending[key] = Pending(Kind.LIST, "*", request_id, uuid.uuid4().hex, self._clock())
        return effects

    def _client_cancelled(self, raw: bytes, message: dict[str, Any]) -> Effects:
        effects = Effects()
        params = message.get("params")
        target = params.get("requestId") if isinstance(params, dict) else None
        key = id_key(target)
        if key is not None and key in self.answered:
            # The server never saw that request; it must not see its cancel.
            self.answered.discard(key)
            return effects
        if key is not None and key in self.pending:
            self.pending[key].cancelled = True
        effects.to_server.append(raw)
        return effects

    # -- server -> client -------------------------------------------------

    def server_event(self, event: LineEvent) -> Effects:
        if isinstance(event, Line):
            return self.server_line(event.data)
        return Effects()

    def server_line(self, raw: bytes) -> Effects:
        """Forward a server line, closing the pending entry it answers.

        T4 scope: bookkeeping only. Result inspection, declaration checks and
        dropped-line replies are T5.
        """
        effects = Effects()
        try:
            message = loads_strict(raw)
        except StrictJsonError:
            effects.to_client.append(raw)
            return effects
        if isinstance(message, dict) and "method" not in message and "id" in message:
            key = id_key(message["id"])
            if key is not None:
                if key in self.closed:
                    self.closed.discard(key)
                    effects.records.append(
                        self._record(
                            decision=Decision.BLOCK,
                            outcome=Outcome.PROTOCOL_ERROR,
                            note="reply to an expired or closed request dropped",
                            request_id=message["id"],
                        )
                    )
                    return effects
                entry = self.pending.pop(key, None)
                if entry is not None and entry.kind is Kind.LIST:
                    self._remember_schemas(message.get("result"))
        effects.to_client.append(raw)
        return effects

    def _remember_schemas(self, result: Any) -> None:
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                self.schemas[tool["name"]] = tool.get("inputSchema")

    # -- timers -----------------------------------------------------------

    def sweep(self) -> Effects:
        """Expire gated requests unanswered for `pending_timeout_s` (D12)."""
        effects = Effects()
        now = self._clock()
        for key, entry in list(self.pending.items()):
            if now - entry.started < self.settings.pending_timeout_s:
                continue
            del self.pending[key]
            self.closed.add(key)
            effects.records.append(
                self._record(
                    decision=Decision.ALLOW,
                    outcome=Outcome.PROTOCOL_ERROR,
                    note=f"pending request expired after {self.settings.pending_timeout_s:g} s",
                    tool=entry.tool,
                    request_id=entry.request_id,
                    correlation_id=entry.correlation_id,
                )
            )
        return effects


# --------------------------------------------------------------------------
# the async loop
# --------------------------------------------------------------------------


class HostIO(Protocol):
    """The host side: the proxy's own stdin and stdout, as bytes."""

    async def receive(self) -> bytes:
        """The next chunk from the host, or b"" at end of stream."""
        ...

    async def send(self, data: bytes) -> None:
        """Write bytes to the host. Raises if the host has gone."""
        ...


class _ChildGone(Exception):
    """A write to the server failed: it has exited or closed stdin."""


class _HostGone(Exception):
    """A write to the host failed: it has closed our stdout."""


def _report_stderr(message: str) -> None:
    with suppress(OSError, ValueError, AttributeError):
        sys.stderr.write(message + "\n")
        sys.stderr.flush()


async def run_pump(
    child: ChildProcess,
    host: HostIO,
    core: ProxyCore,
    *,
    audit: AuditWriter | None = None,
    report: Callable[[str], None] = _report_stderr,
    tick_s: float = 1.0,
) -> SessionEnd:
    """Pump lines both ways until one side ends; return how it ended.

    Ending rules (with `proxy/process.py`):

    * server stdout ends first -> `CHILD_CLOSED`;
    * host stdin ends -> the child's stdin is closed and server replies keep
      flowing until the server's stdout ends or `drain_after_host_eof_s`
      passes, then `HOST_CLOSED` -- so a reply already in flight still
      reaches the host;
    * a write to the child fails -> `CHILD_CLOSED`; a write to the host fails
      -> `HOST_CLOSED`.

    Effects are applied in order: bytes to the server, bytes to the host,
    then audit rows (`AuditWriter`, so a failed write never changes what was
    already sent; its tenth failure in a row raises and ends the session as
    an internal error), then stderr messages.
    """
    ending: list[SessionEnd] = []
    host_eof = anyio.Event()
    server_done = anyio.Event()
    host_lock = anyio.Lock()

    async def apply(effects: Effects) -> None:
        try:
            for data in effects.to_server:
                await child.stdin.send(data)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError) as exc:
            raise _ChildGone from exc
        try:
            for data in effects.to_client:
                async with host_lock:
                    await host.send(data)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError) as exc:
            raise _HostGone from exc
        for message in effects.messages:
            report(message)
        if audit is not None:
            for record in effects.records:
                audit.append(record)

    async with anyio.create_task_group() as tg:

        def finish(end: SessionEnd) -> None:
            if not ending:
                ending.append(end)
            tg.cancel_scope.cancel()

        async def guarded(effects: Effects) -> bool:
            """Apply; on a vanished peer, end the session and return False."""
            try:
                await apply(effects)
            except _ChildGone:
                finish(SessionEnd.CHILD_CLOSED)
                return False
            except _HostGone:
                finish(SessionEnd.HOST_CLOSED)
                return False
            return True

        async def client_side() -> None:
            reader = LineReader(host.receive, core.settings.max_line_bytes)
            while True:
                event = await reader.next()
                if not await guarded(core.client_event(event)):
                    return
                if isinstance(event, Eof | Tail):
                    break
            host_eof.set()
            with suppress(Exception):
                await child.stdin.aclose()
            with anyio.move_on_after(core.settings.drain_after_host_eof_s):
                await server_done.wait()
            finish(SessionEnd.HOST_CLOSED)

        async def server_side() -> None:
            reader = LineReader(child.stdout.receive, core.settings.max_line_bytes)
            while True:
                event = await reader.next()
                if not await guarded(core.server_event(event)):
                    return
                if isinstance(event, Eof | Tail):
                    break
            server_done.set()
            # After host EOF the client side is draining and reports
            # HOST_CLOSED itself; otherwise the server went first.
            if not host_eof.is_set():
                finish(SessionEnd.CHILD_CLOSED)

        async def ticker() -> None:
            while True:
                await anyio.sleep(tick_s)
                await apply(core.sweep())

        tg.start_soon(client_side)
        tg.start_soon(server_side)
        tg.start_soon(ticker)
    return ending[0]


__all__ = [
    "Effects",
    "HostIO",
    "Kind",
    "Pending",
    "ProxyCore",
    "ProxySettings",
    "blocked_reply",
    "error_reply",
    "run_pump",
]
