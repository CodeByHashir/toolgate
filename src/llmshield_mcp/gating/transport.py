"""The interception layer (FR-1).

Sits at the MCP SDK's `Transport` boundary: a transport is an async context
manager yielding a `(ReadStream, WriteStream)` pair of `SessionMessage`, and
every transport -- stdio, SSE, streamable HTTP -- yields exactly that same pair
(`mcp/client/_transport.py`). Wrapping it therefore gives one code path for all
transports and requires no re-implementation of the protocol, which is why
plan.md 2.1 chose this over an out-of-process proxy.

M2 shipped with the wrappers forwarding every frame unchanged and no
detectors, on purpose: interception transparency had to be demonstrable on its
own, so that once detection arrived any behaviour change would be attributable
to the detectors rather than to the plumbing. M4 is that arrival. A frame is
still forwarded byte-identical for Allow and Escalate -- the fused decision has
to be Decision.BLOCK or a Redact with matched spans before `observe_inbound`
returns anything other than the object it received (`gating/policy.py`).

What is deliberately *not* done here:

* Nothing in a scanned frame is executed, evaluated or acted on (NFR-3, SEC-1).
  Frames are parsed for metadata and hashed; their content is never interpreted,
  only pattern-matched by the detectors it is handed to.
* Requests (client -> server) are only observed, never gated. PROPOSAL.md
  section 3.1 scopes this project to tool *results*.
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self

import mcp_types
from mcp.shared.message import SessionMessage

from llmshield_mcp.detectors.base import Detector, DetectorResult
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector
from llmshield_mcp.gating.audit import Decision, DecisionLog, DecisionRecord, Outcome
from llmshield_mcp.gating.content import apply_redaction, build_block_result, extract
from llmshield_mcp.gating.policy import PolicyConfig, PolicyEngine, load_policy_config

TOOL_CALL_METHOD = "tools/call"
CANCELLED_NOTIFICATION = "notifications/cancelled"


def _build_rules_mcp() -> Detector:
    return RuleDetector(families=frozenset({"mcp"}))


def _build_rules_inj() -> Detector:
    return RuleDetector(families=frozenset({"inj"}))


def _build_pii() -> Detector:
    return PiiDetector()


def _build_v0() -> Detector:
    # Imported lazily: constructing this loads a joblib artifact that is not
    # published (prd.md A1) and is not present in CI, so nothing should pay
    # for this import unless a policy file actually names "v0" in a role.
    from llmshield_mcp.config import load_models_config
    from llmshield_mcp.detectors.v0_lexical import V0LexicalDetector

    return V0LexicalDetector(load_models_config().v0)


def _build_v3() -> Detector:
    # Same reasoning as _build_v0, and doubly so here: this import pulls in
    # torch and transformers, seconds of cost nothing should pay unless "v3"
    # is actually named in a policy role.
    from llmshield_mcp.config import load_models_config
    from llmshield_mcp.detectors.v3_transformer import V3TransformerDetector

    return V3TransformerDetector(load_models_config().v3)


#: Every detector key a policy file's `detectors.*` roles may name. Adding V0
#: and V3 here (M5) is what makes `plan.md`'s "ablation by config alone"
#: verification literal: a key only gets constructed -- and only then pays its
#: load cost -- if some role in the policy actually names it.
_DETECTOR_FACTORIES: dict[str, Callable[[], Detector]] = {
    "rules_mcp": _build_rules_mcp,
    "rules_inj": _build_rules_inj,
    "pii": _build_pii,
    "v0": _build_v0,
    "v3": _build_v3,
}


def build_detectors(config: PolicyConfig) -> dict[str, Detector]:
    """Construct exactly the detectors `config` actually names.

    A key appears in the result if and only if it is listed in at least one
    of `config.injection_detectors`, `.redaction_detectors` or
    `.inert_detectors` -- the same three sets `PolicyEngine.decide` reads. A
    detector present in the gate but absent from all three roles would be
    dead weight (scored, never consulted, never logged as mattering); a role
    naming a key with no factory is a configuration error, not a silent skip.
    """
    keys = config.injection_detectors | config.redaction_detectors | config.inert_detectors
    detectors: dict[str, Detector] = {}
    for key in keys:
        factory = _DETECTOR_FACTORIES.get(key)
        if factory is None:
            raise ValueError(
                f"policy names detector {key!r}, which has no registered factory "
                f"(known: {sorted(_DETECTOR_FACTORIES)})"
            )
        detectors[key] = factory()
    return detectors


@dataclass(frozen=True, slots=True)
class GateConfig:
    """Policy knobs that exist before any detector does."""

    #: FR-16 / SEC-2. Bounds how much text a detector is ever asked to process.
    #: Measured in characters because that is what drives detector cost;
    #: truncation applies to *detection input only* and never to the frame
    #: forwarded to the agent.
    max_result_chars: int = 200_000

    #: NFR-5. A tool call whose response never arrives (cancelled, dropped
    #: connection) would otherwise leave an entry in the pending map forever.
    #: The oldest entry is evicted past this bound and the eviction is logged,
    #: so a 20-call session cannot grow state without it being visible.
    max_pending: int = 256


@dataclass(frozen=True, slots=True)
class _Pending:
    tool_name: str
    correlation_id: str
    started: float


def _request_key(request_id: Any) -> str:
    """JSON-RPC ids may be strings or numbers; the pending map keys on text."""
    return str(request_id)


class Gate:
    """Observes one server's frames and records a decision for each result.

    Stateful only in the pending-request map, which is bounded.
    """

    def __init__(
        self,
        server: str,
        log: DecisionLog,
        config: GateConfig | None = None,
        *,
        policy: PolicyEngine | None = None,
        detectors: Mapping[str, Detector] | None = None,
    ) -> None:
        self.server = server
        self.log = log
        self.policy = policy or PolicyEngine(load_policy_config())
        # `config.max_result_chars` now lives in policy.yaml (FR-9). An
        # explicitly passed GateConfig (e.g. the --max-result-chars CLI flag)
        # overrides it; the default Gate() picks up the policy file's value.
        self.config = config or GateConfig(max_result_chars=self.policy.config.max_result_chars)
        self.detectors = (
            dict(detectors) if detectors is not None else build_detectors(self.policy.config)
        )
        self._pending: OrderedDict[str, _Pending] = OrderedDict()

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    # --- client -> server ------------------------------------------------

    def observe_outbound(self, message: SessionMessage) -> None:
        payload = message.message

        if isinstance(payload, mcp_types.JSONRPCRequest) and payload.method == TOOL_CALL_METHOD:
            params = payload.params or {}
            name = params.get("name") if isinstance(params, dict) else None
            self._remember(
                _request_key(payload.id),
                _Pending(
                    tool_name=str(name) if name is not None else "unknown",
                    # A fresh correlation ID per call is what keeps interleaved
                    # calls attributable (PROPOSAL.md section 19).
                    correlation_id=uuid.uuid4().hex,
                    started=time.perf_counter(),
                ),
            )
            return

        if (
            isinstance(payload, mcp_types.JSONRPCNotification)
            and payload.method == CANCELLED_NOTIFICATION
        ):
            params = payload.params or {}
            if isinstance(params, dict) and "requestId" in params:
                self._pending.pop(_request_key(params["requestId"]), None)

    def _remember(self, key: str, pending: _Pending) -> None:
        self._pending[key] = pending
        while len(self._pending) > self.config.max_pending:
            evicted_key, evicted = self._pending.popitem(last=False)
            self.log.append(
                DecisionRecord(
                    correlation_id=evicted.correlation_id,
                    mcp_server_id=self.server,
                    tool_name=evicted.tool_name,
                    request_id=evicted_key,
                    raw_result_hash="",
                    fused_decision=Decision.ALLOW,
                    latency_ms=0.0,
                    outcome=Outcome.PROTOCOL_ERROR,
                    note="evicted from the pending map before a response arrived",
                )
            )

    # --- server -> client ------------------------------------------------

    def observe_inbound(self, item: SessionMessage | Exception) -> SessionMessage | Exception:
        if isinstance(item, Exception):
            # A transport-level failure, not a tool result. Nothing to scan.
            return item

        payload = item.message
        if not isinstance(payload, mcp_types.JSONRPCResponse | mcp_types.JSONRPCError):
            return item

        pending = self._pending.pop(_request_key(payload.id), None)
        if pending is None:
            # Not a tools/call we tracked -- initialize, tools/list, a
            # server-initiated request. Out of scope for result gating.
            return item

        roundtrip_ms = (time.perf_counter() - pending.started) * 1000.0
        gate_started = time.perf_counter()

        if isinstance(payload, mcp_types.JSONRPCError):
            # FR-15: a protocol-level error carries no tool content, so no
            # content-based detection runs. Logged under its own outcome so it
            # never lands in a false-positive denominator.
            self.log.append(
                DecisionRecord(
                    correlation_id=pending.correlation_id,
                    mcp_server_id=self.server,
                    tool_name=pending.tool_name,
                    request_id=_request_key(payload.id),
                    raw_result_hash="",
                    fused_decision=Decision.ALLOW,
                    latency_ms=(time.perf_counter() - gate_started) * 1000.0,
                    roundtrip_ms=roundtrip_ms,
                    outcome=Outcome.PROTOCOL_ERROR,
                    note=f"jsonrpc error {payload.error.code}",
                )
            )
            return item

        content = extract(payload.result, self.config.max_result_chars)

        # FR-2/FR-4: run every configured detector against the (normalised +
        # original, see scan_normalised) extracted text, then fuse.
        results: dict[str, DetectorResult] = {
            key: scan_normalised(detector, content.text) for key, detector in self.detectors.items()
        }
        fusion = self.policy.decide(results)

        result_out: Any = payload.result
        if fusion.decision is Decision.BLOCK:
            result_out = build_block_result(is_error=True)
        elif fusion.redacted:
            result_out = apply_redaction(payload.result, fusion.redact_spans)

        if result_out is not payload.result:
            new_payload = payload.model_copy(update={"result": result_out})
            item = dataclasses.replace(item, message=new_payload)

        self.log.append(
            DecisionRecord(
                correlation_id=pending.correlation_id,
                mcp_server_id=self.server,
                tool_name=pending.tool_name,
                request_id=_request_key(payload.id),
                raw_result_hash=content.sha256,
                fused_decision=fusion.decision,
                detector_scores={key: result.score for key, result in results.items()},
                redacted=fusion.redacted,
                latency_ms=(time.perf_counter() - gate_started) * 1000.0,
                roundtrip_ms=roundtrip_ms,
                outcome=fusion.outcome,
                tool_is_error=content.is_error,
                content_chars=content.original_chars,
                truncated=content.truncated,
                block_types=content.block_types,
                malformed=content.malformed,
                note=fusion.note,
            )
        )
        return item


class _ObservedReadStream:
    """Read side (server -> client). Observes, forwards unchanged."""

    def __init__(self, inner: Any, gate: Gate) -> None:
        self._inner = inner
        self._gate = gate

    async def receive(self) -> Any:
        item = await self._inner.receive()
        return self._gate.observe_inbound(item)

    async def aclose(self) -> None:
        await self._inner.aclose()

    def __aiter__(self) -> _ObservedReadStream:
        return self

    async def __anext__(self) -> Any:
        item = await self._inner.__anext__()
        return self._gate.observe_inbound(item)

    async def __aenter__(self) -> Self:
        await self._inner.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        result: bool | None = await self._inner.__aexit__(exc_type, exc_val, exc_tb)
        return result

    def __getattr__(self, name: str) -> Any:
        # Transparency (AC-1): anything the session looks for that this wrapper
        # does not define -- `last_context`, for instance -- must still resolve
        # to the real stream.
        return getattr(self._inner, name)


class _ObservedWriteStream:
    """Write side (client -> server). Observes, forwards unchanged."""

    def __init__(self, inner: Any, gate: Gate) -> None:
        self._inner = inner
        self._gate = gate

    async def send(self, item: Any, /) -> None:
        self._gate.observe_outbound(item)
        await self._inner.send(item)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def __aenter__(self) -> Self:
        await self._inner.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        result: bool | None = await self._inner.__aexit__(exc_type, exc_val, exc_tb)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


@asynccontextmanager
async def gating_transport(inner: Any, gate: Gate) -> AsyncIterator[tuple[Any, Any]]:
    """Wrap a transport so every frame passes through `gate`.

    Satisfies the same `Transport` protocol as what it wraps, so it can be
    handed anywhere the SDK expects a transport.
    """
    async with inner as (read_stream, write_stream):
        yield _ObservedReadStream(read_stream, gate), _ObservedWriteStream(write_stream, gate)
