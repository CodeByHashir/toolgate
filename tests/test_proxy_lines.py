"""Tests for the proxy's line framing, strict parsing and id handling."""

from __future__ import annotations

import json
from typing import Any

import anyio
import pytest

from toolgate.proxy.lines import (
    PREFIX_BYTES,
    Eof,
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


async def _events(chunks: list[bytes], max_bytes: int = 64) -> list[LineEvent]:
    pending = list(chunks)

    async def receive() -> bytes:
        return pending.pop(0) if pending else b""

    reader = LineReader(receive, max_bytes)
    out: list[LineEvent] = []
    while True:
        event = await reader.next()
        out.append(event)
        if isinstance(event, Eof):
            return out


class TestLineReader:
    async def test_lines_are_split_on_newline_and_kept_byte_exact(self) -> None:
        events = await _events([b'{"a":1}\r\n{"b"', b":2}\n"])
        assert events == [Line(b'{"a":1}\r\n'), Line(b'{"b":2}\n'), Eof()]

    async def test_one_chunk_with_many_lines(self) -> None:
        assert await _events([b"a\nb\nc\n"]) == [Line(b"a\n"), Line(b"b\n"), Line(b"c\n"), Eof()]

    async def test_an_unterminated_final_line_is_a_tail_not_a_line(self) -> None:
        assert await _events([b"a\nhalf"]) == [Line(b"a\n"), Tail(b"half"), Eof()]

    async def test_an_oversize_line_is_reported_with_its_prefix_and_skipped(self) -> None:
        big = b"x" * 200
        events = await _events([b"ok\n", big[:100], big[100:] + b"\nnext\n"], max_bytes=64)
        assert events[0] == Line(b"ok\n")
        assert isinstance(events[1], Oversize) and events[1].prefix == big[:100][:PREFIX_BYTES]
        assert events[2:] == [Line(b"next\n"), Eof()]

    async def test_an_oversize_line_in_a_single_chunk(self) -> None:
        events = await _events([b"y" * 100 + b"\nz\n"], max_bytes=64)
        assert isinstance(events[0], Oversize)
        assert events[1:] == [Line(b"z\n"), Eof()]

    async def test_an_oversize_unterminated_tail(self) -> None:
        events = await _events([b"q" * 100], max_bytes=64)
        assert isinstance(events[0], Oversize)
        assert events[1:] == [Eof()]

    async def test_a_line_exactly_at_the_cap_passes(self) -> None:
        line = b"a" * 63 + b"\n"
        assert await _events([line], max_bytes=64) == [Line(line), Eof()]

    async def test_end_of_stream_exceptions_count_as_eof(self) -> None:
        send, receive = anyio.create_memory_object_stream[bytes](4)
        await send.send(b"a\n")
        await send.aclose()
        reader = LineReader(receive.receive)
        assert await reader.next() == Line(b"a\n")
        assert await reader.next() == Eof()

    async def test_an_eight_mib_line_passes_under_the_default_cap(self) -> None:
        big = b'{"x":"' + b"a" * (8 * 1024 * 1024) + b'"}\n'
        chunks = [big[i : i + 65536] for i in range(0, len(big), 65536)]
        events = await _events(chunks, max_bytes=64 * 1024 * 1024)
        assert events == [Line(big), Eof()]


class TestStrictParse:
    def test_one_object_parses(self) -> None:
        assert loads_strict(b'{"a":[1,{"b":null}]}\n') == {"a": [1, {"b": None}]}

    @pytest.mark.parametrize(
        "line",
        [
            b'{"method":"tools/call","method":"ping"}',
            b'{"method":"ping","method":"tools/call"}',
            b'{"params":{"name":"a","name":"b"}}',
            b'{"params":{"arguments":{"url":"x","url":"y"}}}',
            b'[{"a":1,"a":2}]',
        ],
    )
    def test_duplicate_keys_at_any_depth_are_refused(self, line: bytes) -> None:
        with pytest.raises(StrictJsonError) as excinfo:
            loads_strict(line)
        assert excinfo.value.kind == "duplicate"

    @pytest.mark.parametrize("token", [b"NaN", b"Infinity", b"-Infinity"])
    def test_non_finite_numbers_are_refused(self, token: bytes) -> None:
        with pytest.raises(StrictJsonError) as excinfo:
            loads_strict(b'{"x":' + token + b"}")
        assert excinfo.value.kind == "nonfinite"

    @pytest.mark.parametrize(
        "line",
        [
            b'\xef\xbb\xbf{"a":1}',  # UTF-8 BOM
            b'{"a":1}{"b":2}',  # two objects
            b'{"a":1} {"b":2}',
            b'{"a":1,}',  # trailing comma
            b'{"a":1 /* c */}',
            b"{'a':1}",
            b'{"a":"\xff"}',  # invalid UTF-8
            b"",
            b"   ",
        ],
    )
    def test_anything_else_ambiguous_is_a_parse_error(self, line: bytes) -> None:
        with pytest.raises(StrictJsonError) as excinfo:
            loads_strict(line)
        assert excinfo.value.kind == "parse"

    def test_error_text_never_quotes_content(self) -> None:
        with pytest.raises(StrictJsonError) as excinfo:
            loads_strict(b'{"secret":"sk-live-123","secret":1}')
        assert "sk-live" not in str(excinfo.value)


class TestIds:
    def test_ids_compare_by_json_type_and_value(self) -> None:
        assert id_key("1") != id_key(1)
        assert id_key(1) == id_key(1.0)
        assert id_key("a") == ("string", "a")

    @pytest.mark.parametrize("value", [True, False, None, [1], {"a": 1}])
    def test_invalid_ids(self, value: Any) -> None:
        assert id_key(value) is None

    def test_top_level_ids_sees_every_copy(self) -> None:
        assert top_level_ids(b'{"id":1,"id":2,"params":{"id":3}}') == [1, 2]
        assert top_level_ids(b'{"id":"a","x":NaN}') == ["a"]
        assert top_level_ids(b"[1,2]") is None
        assert top_level_ids(b"not json") is None

    def test_id_from_prefix(self) -> None:
        assert id_from_prefix(b'{"jsonrpc":"2.0","id":42,"result":{"content":[') == 42
        assert id_from_prefix(b'{"id" : "req-\\"7","method"') == 'req-"7'
        assert id_from_prefix(b'{"jsonrpc":"2.0","result":') is None
        assert id_from_prefix(b'{"id":true}') is None


class TestEncode:
    def test_round_trip_and_newline(self) -> None:
        message = {"a": "café", "b": [1, None]}
        line = encode(message)
        assert line.endswith(b"\n") and b"\n" not in line[:-1]
        assert json.loads(line) == message
        assert "café".encode() in line

    def test_a_lone_surrogate_falls_back_to_ascii_escapes(self) -> None:
        message = {"t": "\ud800"}
        line = encode(message)
        assert json.loads(line) == message
        line.decode("ascii")
