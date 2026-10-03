"""Newline-delimited JSON for the proxy: framing, strict parsing, request ids.

The pump forwards original bytes and parses only to decide. This module holds
the two halves of "parse only to decide" that must be exactly right:

**Framing.** `LineReader` splits a byte stream on `\\n` without decoding it,
with a hard cap on line length (design R2-11, 64 MiB by default). A line over
the cap is never buffered whole: its first `PREFIX_BYTES` are kept (enough to
read an id from) and the rest is discarded as it arrives. A final line with
no newline at EOF is reported as a tail, not as a line, because a line the
sender never finished is not a message.

**Strict parsing.** `loads_strict` accepts exactly one JSON value per line and
refuses anything two conforming parsers could read differently:

* duplicate keys at any depth (design D4). Python keeps the last copy, many
  parsers keep the first, so `{"method":"tools/call","method":"ping"}` would
  be a ping to the gate and a tool call to a first-wins server;
* `NaN`, `Infinity`, `-Infinity`, which are not JSON (R2-7);
* a UTF-8 byte-order mark, invalid UTF-8, trailing commas, comments and two
  objects on one line (D5): Python's parser already refuses these, and the
  bytes are decoded strictly before parsing so a BOM is not silently eaten.

After `loads_strict` succeeds, the original bytes can mean only one thing to
any conforming parser, which is what makes forwarding them unchanged safe.

**Ids.** JSON-RPC ids are compared by JSON type and value (`id_key`): `"1"`
and `1` are different requests, `1` and `1.0` are the same number. Booleans,
objects and arrays are not valid ids.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

import anyio

#: Default cap on one line, in bytes (design R2-11). Configurable per proxy.
MAX_LINE_BYTES = 64 * 1024 * 1024

#: How much of an over-long line is kept for reading an id (design D8).
PREFIX_BYTES = 4096

#: Read size for one chunk from a stream.
CHUNK_BYTES = 64 * 1024

IdKey = tuple[str, Any]


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Line:
    """One complete line, newline included, exactly as received."""

    data: bytes


@dataclass(frozen=True, slots=True)
class Oversize:
    """A line longer than the cap. Only its first `PREFIX_BYTES` were kept."""

    prefix: bytes


@dataclass(frozen=True, slots=True)
class Tail:
    """Bytes after the last newline when the stream ended."""

    data: bytes


@dataclass(frozen=True, slots=True)
class Eof:
    """The stream ended cleanly (no unterminated tail)."""


LineEvent = Line | Oversize | Tail | Eof


class LineReader:
    """Read `LineEvent`s from a byte source, never holding more than the cap.

    `receive` returns the next chunk, or `b""` (or raises `anyio.EndOfStream`)
    at end of stream. Memory is bounded by the cap plus one chunk: a line that
    passes the cap switches the reader to discarding until the next newline.
    """

    def __init__(
        self, receive: Callable[[], Awaitable[bytes]], max_bytes: int = MAX_LINE_BYTES
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        self._receive = receive
        self.max_bytes = max_bytes
        self._buffer = bytearray()
        self._scanned = 0  # bytes of _buffer already known to hold no newline
        self._discarding: bytes | None = None  # prefix of the oversize line being dropped
        self._ended = False

    async def next(self) -> LineEvent:
        while True:
            newline = self._buffer.find(b"\n", self._scanned)
            if newline >= 0:
                data = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                self._scanned = 0
                if self._discarding is not None:
                    prefix, self._discarding = self._discarding, None
                    return Oversize(prefix)
                if len(data) > self.max_bytes:
                    return Oversize(data[:PREFIX_BYTES])
                return Line(data)
            self._scanned = len(self._buffer)

            if self._discarding is None and len(self._buffer) > self.max_bytes:
                self._discarding = bytes(self._buffer[:PREFIX_BYTES])
                self._buffer.clear()
                self._scanned = 0
            elif self._discarding is not None:
                self._buffer.clear()
                self._scanned = 0

            if self._ended:
                return Eof()
            chunk = await self._read()
            if not chunk:
                self._ended = True
                if self._discarding is not None:
                    prefix, self._discarding = self._discarding, None
                    return Oversize(prefix)
                if self._buffer:
                    data = bytes(self._buffer)
                    self._buffer.clear()
                    self._scanned = 0
                    return Tail(data)
                return Eof()
            self._buffer += chunk

    async def _read(self) -> bytes:
        try:
            return await self._receive()
        except (anyio.EndOfStream, anyio.ClosedResourceError, anyio.BrokenResourceError):
            return b""


# --------------------------------------------------------------------------
# strict parsing
# --------------------------------------------------------------------------

StrictFailure = Literal["parse", "duplicate", "nonfinite"]


class StrictJsonError(ValueError):
    """A line that is not exactly one unambiguous JSON value."""

    def __init__(self, kind: StrictFailure, detail: str) -> None:
        self.kind: StrictFailure = kind
        super().__init__(detail)


class _Duplicate(Exception):
    pass


class _NonFinite(Exception):
    pass


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Duplicate(key)
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise _NonFinite(name)


def loads_strict(line: bytes) -> Any:
    """Parse one line, refusing every ambiguous form (see module docstring).

    Raises `StrictJsonError` whose `kind` says why: `"duplicate"` for a
    repeated key, `"nonfinite"` for NaN/Infinity, `"parse"` for everything
    else (invalid UTF-8, a BOM, malformed or concatenated JSON). The detail
    names the problem, never the content.
    """
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        raise StrictJsonError("parse", "line is not valid UTF-8") from None
    try:
        return json.loads(
            text, object_pairs_hook=_refuse_duplicates, parse_constant=_refuse_constant
        )
    except _Duplicate:
        raise StrictJsonError("duplicate", "duplicate object key") from None
    except _NonFinite:
        raise StrictJsonError("nonfinite", "NaN or Infinity is not JSON") from None
    except (ValueError, RecursionError) as exc:
        reason = exc.msg if isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        raise StrictJsonError("parse", f"not one JSON value ({reason})") from None


def top_level_ids(line: bytes) -> list[Any] | None:
    """Every top-level `"id"` value of a line that failed only the strict checks.

    Used to answer a refused request when its id is unambiguous. Returns None
    when the line is not a JSON object even leniently. Parsing here is lenient
    (duplicates kept, NaN allowed) because the point is to *see* every copy.
    """
    try:
        top = json.loads(line.decode("utf-8", "replace"), object_pairs_hook=lambda pairs: pairs)
    except (ValueError, RecursionError):
        return None
    # object_pairs_hook turns objects into lists of tuples; JSON arrays stay
    # lists of non-tuples, so the two cannot be confused.
    if not isinstance(top, list) or not all(isinstance(item, tuple) for item in top):
        return None
    return [value for key, value in top if key == "id"]


_PREFIX_ID_RE = re.compile(rb'"id"\s*:\s*("(?:[^"\\]|\\.)*"|-?[0-9]+(?:\.[0-9]+)?)')


def id_from_prefix(prefix: bytes) -> Any | None:
    """Best-effort id from the start of a line that was too long to parse.

    Takes the first `"id": <string or number>` in the prefix. JSON-RPC
    messages put `id` near the front in practice, but a nested `"id"` could
    come first; callers only use the result to send an error reply and to
    close the matching pending entry, and they treat a later reply to that id
    as dropped, so a wrong guess cannot let a result through unchecked.
    """
    match = _PREFIX_ID_RE.search(prefix[:PREFIX_BYTES])
    if match is None:
        return None
    try:
        value = json.loads(match.group(1))
    except ValueError:
        return None
    return value if id_key(value) is not None else None


# --------------------------------------------------------------------------
# ids and encoding
# --------------------------------------------------------------------------


def id_key(value: Any) -> IdKey | None:
    """Key a JSON-RPC id by JSON type and value; None if it is not a valid id."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, int | float):
        return ("number", value)
    return None


def encode(message: Any) -> bytes:
    """Serialise one message as a line.

    Non-ASCII is kept as UTF-8 where possible. A string holding a lone
    surrogate (legal as a JSON escape, not encodable as UTF-8) falls back to
    ASCII escapes, which are the same JSON value.
    """
    text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    try:
        return text.encode("utf-8") + b"\n"
    except UnicodeEncodeError:
        return json.dumps(message, separators=(",", ":")).encode("ascii") + b"\n"


__all__ = [
    "CHUNK_BYTES",
    "MAX_LINE_BYTES",
    "PREFIX_BYTES",
    "Eof",
    "IdKey",
    "Line",
    "LineEvent",
    "LineReader",
    "Oversize",
    "StrictJsonError",
    "Tail",
    "encode",
    "id_from_prefix",
    "id_key",
    "loads_strict",
    "top_level_ids",
]
