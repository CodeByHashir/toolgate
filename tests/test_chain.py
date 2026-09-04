"""Tests for the recorded tool-call chain format."""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.chain import SCHEMA_VERSION, ChainRecord, ToolCallRecord


def _call(index: int = 0, **overrides: object) -> ToolCallRecord:
    fields: dict[str, object] = {
        "index": index,
        "correlation_id": f"cid{index}",
        "server": "filesystem",
        "tool": "read_text_file",
        "arguments": {"path": "README.md"},
        "result_text": "hello",
        "result_block_types": ("text",),
        "is_error": False,
        "duration_ms": 1.5,
    }
    fields.update(overrides)
    return ToolCallRecord(**fields)  # type: ignore[arg-type]


def _chain(*calls: ToolCallRecord) -> ChainRecord:
    return ChainRecord(
        task="summarise the sandbox",
        model="claude-opus-5",
        created_at="2026-09-04T12:00:00+00:00",
        servers=("filesystem", "fetch"),
        calls=calls,
    )


def test_round_trips_through_json(tmp_path: Path) -> None:
    original = _chain(_call(0), _call(1, server="fetch", tool="fetch"))
    path = tmp_path / "chain.json"

    original.write(path)
    restored = ChainRecord.read(path)

    assert restored == original


def test_round_trip_preserves_tuple_types(tmp_path: Path) -> None:
    # JSON has no tuples. Without explicit reconstruction these come back as
    # lists and equality against a freshly built record silently fails.
    path = tmp_path / "chain.json"
    _chain(_call()).write(path)

    restored = ChainRecord.read(path)

    assert isinstance(restored.calls, tuple)
    assert isinstance(restored.servers, tuple)
    assert isinstance(restored.calls[0].result_block_types, tuple)


def test_unknown_schema_version_is_rejected() -> None:
    raw = _chain(_call()).to_dict()
    raw["schema_version"] = SCHEMA_VERSION + 1

    with pytest.raises(ValueError, match="schema version"):
        ChainRecord.from_dict(raw)


def test_error_calls_are_recorded_not_dropped() -> None:
    # A failed tool call still occupies a position in the sequence; dropping it
    # would leave a hole and misalign later indices.
    chain = _chain(_call(0), _call(1, is_error=True, result_text="boom"))

    assert len(chain.calls) == 2
    assert chain.calls[1].is_error


def test_empty_chain_is_representable(tmp_path: Path) -> None:
    path = tmp_path / "chain.json"
    _chain().write(path)

    assert ChainRecord.read(path).calls == ()


def test_json_is_human_readable() -> None:
    # The fixture is committed and reviewed, so it must not be a single line.
    text = _chain(_call()).to_json()

    assert "\n" in text
    assert '"result_text": "hello"' in text
