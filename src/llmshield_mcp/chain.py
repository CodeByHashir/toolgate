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
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


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
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n", encoding="utf-8")

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
            schema_version=SCHEMA_VERSION,
        )

    @classmethod
    def read(cls, path: Path) -> ChainRecord:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
