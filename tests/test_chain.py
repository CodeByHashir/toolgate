"""Tests for the recorded tool-call chain format."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from llmshield_mcp.chain import (
    SCHEMA_VERSION,
    ChainRecord,
    ToolCallRecord,
    UsageRecord,
    normalise,
    restore,
)
from llmshield_mcp.config import REPO_ROOT, SANDBOX_PLACEHOLDER

SANDBOX = r"D:\LLMSHIELD-MCP\sandbox"


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


def _chain(*calls: ToolCallRecord, **overrides: object) -> ChainRecord:
    fields: dict[str, object] = {
        "task": "summarise the sandbox",
        "model": "claude-opus-5",
        "created_at": "2026-09-04T12:00:00+00:00",
        "servers": ("filesystem", "fetch"),
        "calls": calls,
    }
    fields.update(overrides)
    return ChainRecord(**fields)  # type: ignore[arg-type]


# --- round-tripping ------------------------------------------------------


def test_round_trips_through_json(tmp_path: Path) -> None:
    original = _chain(_call(0), _call(1, server="fetch", tool="fetch"))
    path = tmp_path / "chain.json"

    original.write(path)

    assert ChainRecord.read(path) == original


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


# --- sandbox normalisation (D2) ------------------------------------------


def test_normalise_replaces_native_and_posix_spellings() -> None:
    # A model may issue either spelling and servers echo back whichever they got.
    native = normalise({"path": SANDBOX + r"\README.md"}, SANDBOX)
    posix = normalise({"path": SANDBOX.replace("\\", "/") + "/README.md"}, SANDBOX)

    assert native == {"path": r"{sandbox}\README.md"}
    assert posix == {"path": "{sandbox}/README.md"}


def test_normalise_recurses_into_nested_structures() -> None:
    value = {"paths": [SANDBOX + r"\a", {"inner": SANDBOX + r"\b"}], "n": 3}

    assert normalise(value, SANDBOX) == {
        "paths": [r"{sandbox}\a", {"inner": r"{sandbox}\b"}],
        "n": 3,
    }


def test_restore_is_the_inverse_of_normalise() -> None:
    original = {"path": SANDBOX + r"\notes\meeting-notes.md"}

    assert restore(normalise(original, SANDBOX), SANDBOX) == original


def test_normalise_with_empty_root_is_a_no_op() -> None:
    value = {"path": "/anything"}

    assert normalise(value, "") == value
    assert restore(value, "") == value


def test_read_leaves_placeholder_when_no_sandbox_given(tmp_path: Path) -> None:
    # Inspection and diffing want the portable form.
    path = tmp_path / "chain.json"
    _chain(_call(arguments={"path": r"{sandbox}\README.md"})).write(path)

    assert ChainRecord.read(path).calls[0].arguments == {"path": r"{sandbox}\README.md"}


def test_read_with_sandbox_resolves_placeholder(tmp_path: Path) -> None:
    path = tmp_path / "chain.json"
    _chain(
        _call(
            arguments={"path": r"{sandbox}\README.md"},
            result_text=r"listing of {sandbox}",
        )
    ).write(path)

    restored = ChainRecord.read(path, sandbox_root=SANDBOX)

    assert restored.calls[0].arguments == {"path": SANDBOX + r"\README.md"}
    assert restored.calls[0].result_text == f"listing of {SANDBOX}"


def test_written_record_contains_no_host_path(tmp_path: Path) -> None:
    path = tmp_path / "chain.json"
    _chain(
        _call(
            arguments=normalise({"path": SANDBOX + r"\README.md"}, SANDBOX),
            result_text=normalise(f"Allowed directories: {SANDBOX}", SANDBOX),
        )
    ).write(path)

    assert SANDBOX not in path.read_text(encoding="utf-8")


def test_committed_fixture_discloses_no_absolute_path() -> None:
    r"""D2, checked against the real artifact rather than a constructed one.

    An earlier version of this test built its own record and set the offending
    field to empty, so it passed while the committed fixture still carried
    `D:\LLMSHIELD-MCP\sandbox`. Reading the actual file is what catches that.
    """
    fixture = REPO_ROOT / "chains" / "baseline.json"
    if not fixture.is_file():
        pytest.skip("no recorded chain committed yet")

    text = fixture.read_text(encoding="utf-8")

    assert SANDBOX_PLACEHOLDER in text, "fixture should use the portable placeholder"

    # A single-letter drive followed by a separator. The lookbehind keeps URL
    # schemes out of it -- "https://example.com" is legitimate fetched content,
    # not a host path, and matching it would make this test useless noise.
    drive = re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", text)
    assert drive is None, f"fixture discloses a host path near {text[drive.start() - 20 :][:60]!r}"

    for marker in ("/home/", "/Users/", "/root/"):
        assert marker not in text, f"fixture discloses a host path ({marker!r})"


# --- usage ---------------------------------------------------------------


@dataclass
class FakeUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


def test_usage_accumulates_across_api_calls() -> None:
    usage = UsageRecord()

    usage = usage.plus(FakeUsage(input_tokens=100, output_tokens=20))
    usage = usage.plus(FakeUsage(input_tokens=250, output_tokens=35))

    assert usage.api_calls == 2
    assert usage.input_tokens == 350
    assert usage.output_tokens == 55


def test_usage_tolerates_missing_and_none_fields() -> None:
    # Not every response carries every cache field; a None must not crash a run.
    usage = UsageRecord().plus(FakeUsage(input_tokens=10, cache_read_input_tokens=None))  # type: ignore[arg-type]

    assert usage.input_tokens == 10
    assert usage.cache_read_input_tokens == 0


def test_usage_survives_the_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "chain.json"
    _chain(usage=UsageRecord(api_calls=4, input_tokens=1234, output_tokens=567)).write(path)

    restored = ChainRecord.read(path)

    assert restored.usage.api_calls == 4
    assert restored.usage.input_tokens == 1234
