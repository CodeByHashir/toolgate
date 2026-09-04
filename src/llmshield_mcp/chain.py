"""Recorded tool-call chains.

A chain is what the reference agent produces: an ordered record of the tool
calls a real Claude agent made against real MCP servers, together with the
results those servers returned.

Why this is a stored artifact rather than something replayed live: assumption
A2 in prd.md resolves the agent's role to *hosting chains only*. The agent runs
once to capture realistic call sequences; the GAUGE evaluation then runs
offline against the recording (NFR-6). That keeps API spend a one-off, makes
runs reproducible, and means evaluation does not depend on a live network or a
live model.

Chains recorded in M1 are the **benign baseline**. Adversarial payloads are
injected into result text at evaluation time from the decontaminated corpus
(M6); they are never stored in the sandbox or in a recorded chain.

Two properties of the stored form are deliberate:

*Portability.* The sandbox lives at a different absolute path on every machine,
and the raw path appears in both tool arguments and tool results. Storing it
literally would make fixtures machine-specific and would disclose the author's
directory layout in a published repository, so it is replaced by
`SANDBOX_PLACEHOLDER` on write and restored on read. The placeholder is
visibly a placeholder -- no fabricated path is ever written down.

*Cost visibility.* Every run records the tokens it consumed, so the one-off
spend behind a fixture is a recorded number rather than an estimate.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from llmshield_mcp.config import SANDBOX_PLACEHOLDER

SCHEMA_VERSION = 2

T = TypeVar("T")


def _rewrite(value: T, old: str, new: str) -> T:
    """Recursively replace `old` with `new` in every string inside `value`.

    Both the native and POSIX spellings of a Windows path are handled, because
    a model may issue either and MCP servers echo back whichever they received.
    """
    if isinstance(value, str):
        replaced = value.replace(old, new).replace(old.replace("\\", "/"), new)
        return replaced  # type: ignore[return-value]
    if isinstance(value, dict):
        return {k: _rewrite(v, old, new) for k, v in value.items()}  # type: ignore[return-value]
    if isinstance(value, list):
        return [_rewrite(v, old, new) for v in value]  # type: ignore[return-value]
    return value


def normalise(value: T, sandbox_root: str) -> T:
    """Replace the concrete sandbox path with the portable placeholder."""
    if not sandbox_root:
        return value
    return _rewrite(value, sandbox_root, SANDBOX_PLACEHOLDER)


def restore(value: T, sandbox_root: str) -> T:
    """Replace the placeholder with a concrete sandbox path."""
    if not sandbox_root:
        return value
    return _rewrite(value, SANDBOX_PLACEHOLDER, sandbox_root)


@dataclass(frozen=True, slots=True)
class UsageRecord:
    """Tokens consumed producing one chain.

    Recorded so the cost of a fixture is a measured number rather than a guess.
    Under assumption A2 this spend happens once per fixture and does not scale
    with the size of the evaluation corpus.
    """

    api_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def plus(self, usage: Any) -> UsageRecord:
        """Accumulate one API response's usage block."""

        def field_of(name: str) -> int:
            return int(getattr(usage, name, 0) or 0)

        return UsageRecord(
            api_calls=self.api_calls + 1,
            input_tokens=self.input_tokens + field_of("input_tokens"),
            output_tokens=self.output_tokens + field_of("output_tokens"),
            cache_creation_input_tokens=(
                self.cache_creation_input_tokens + field_of("cache_creation_input_tokens")
            ),
            cache_read_input_tokens=(
                self.cache_read_input_tokens + field_of("cache_read_input_tokens")
            ),
        )


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """One tool call and the result the MCP server returned for it."""

    index: int
    #: Correlation ID carried through to the decision log (FR-8, and the
    #: interleaved-call case in PROPOSAL.md section 19).
    correlation_id: str
    server: str
    tool: str
    arguments: dict[str, Any]
    #: Concatenated text of every text block in the result. This is the content
    #: the gating layer will scan, and the field payloads are injected into.
    result_text: str
    #: Every content block type the result carried, in order. Preserved because
    #: binary and embedded-resource blocks have their own handling policy
    #: (PROPOSAL.md section 19) and are not text-scanned.
    result_block_types: tuple[str, ...]
    #: True when the MCP server reported tool failure via CallToolResult.isError.
    #: Distinct from a protocol-level JSON-RPC error, which never reaches here.
    is_error: bool
    duration_ms: float


@dataclass(frozen=True, slots=True)
class ChainRecord:
    """One agent run: the task it was given and every tool call it made."""

    task: str
    model: str
    created_at: str
    servers: tuple[str, ...]
    calls: tuple[ToolCallRecord, ...] = field(default_factory=tuple)
    usage: UsageRecord = field(default_factory=UsageRecord)
    schema_version: int = SCHEMA_VERSION

    # Deliberately absent: the concrete sandbox path this fixture was recorded
    # against. Storing it "for provenance" would have reintroduced exactly the
    # host-path disclosure the placeholder exists to prevent, and nothing reads
    # it -- `read` resolves against the caller's sandbox, not the recorder's.

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n", encoding="utf-8")

    def with_sandbox(self, sandbox_root: str) -> ChainRecord:
        """Return a copy with the placeholder resolved to `sandbox_root`."""
        return ChainRecord(
            task=self.task,
            model=self.model,
            created_at=self.created_at,
            servers=self.servers,
            calls=tuple(
                ToolCallRecord(
                    index=c.index,
                    correlation_id=c.correlation_id,
                    server=c.server,
                    tool=c.tool,
                    arguments=restore(c.arguments, sandbox_root),
                    result_text=restore(c.result_text, sandbox_root),
                    result_block_types=c.result_block_types,
                    is_error=c.is_error,
                    duration_ms=c.duration_ms,
                )
                for c in self.calls
            ),
            usage=self.usage,
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ChainRecord:
        version = raw.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"chain schema version {version!r} is not supported "
                f"(this build reads version {SCHEMA_VERSION})"
            )
        calls = tuple(
            ToolCallRecord(
                index=int(c["index"]),
                correlation_id=str(c["correlation_id"]),
                server=str(c["server"]),
                tool=str(c["tool"]),
                arguments=dict(c["arguments"]),
                result_text=str(c["result_text"]),
                result_block_types=tuple(c["result_block_types"]),
                is_error=bool(c["is_error"]),
                duration_ms=float(c["duration_ms"]),
            )
            for c in raw["calls"]
        )
        return cls(
            task=str(raw["task"]),
            model=str(raw["model"]),
            created_at=str(raw["created_at"]),
            servers=tuple(raw["servers"]),
            calls=calls,
            usage=UsageRecord(**raw.get("usage", {})),
            schema_version=SCHEMA_VERSION,
        )

    @classmethod
    def read(cls, path: Path, sandbox_root: str | Path | None = None) -> ChainRecord:
        """Load a chain, optionally resolving the sandbox placeholder.

        Without `sandbox_root` the placeholder is left in place, which is what
        inspection and diffing want. Pass the local sandbox to get paths a
        replay can actually use.
        """
        record = cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        if sandbox_root is None:
            return record
        return record.with_sandbox(str(sandbox_root))
