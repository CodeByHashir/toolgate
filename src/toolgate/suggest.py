"""`toolgate policy suggest --name N -- <server command>`: draft a policy.

Writing a policy by hand means reading each tool's input schema and sorting
every argument that could hold a string into `path_args`, `url_args` or
`ignore_args`: a rule with `paths` or `egress` that leaves one unsorted makes
the proxy withhold the tool (classification fails closed, T2). This command
does the reading. It starts the server, sends `initialize` and `tools/list`
(following `nextCursor`), and prints a draft:

* `default: block`;
* per tool, a rule built from argument names and schema `format`: a
  URL-like argument (`url`, `endpoint`, `format: uri`, ...) goes to
  `url_args` with an `egress` placeholder; a path-like one (`path`,
  `source`, `output_file`, ...) to `path_args` with a `paths` placeholder;
  every other string-capable argument to `ignore_args`; a tool with neither
  is allowed as-is (`{}`); a tool whose schema cannot be read is blocked.

Every rule is a guess and is marked `# review`. The placeholders,
`example.invalid` (a reserved name that never resolves) and an absolute
`/replace/with/...` glob, keep the draft loadable while allowing nothing
until they are edited, so an unreviewed draft fails closed. Whatever the
guesses, the draft classifies every declared argument of every tool, so the
proxy never withholds a tool it names.

The draft goes to stdout only; this command never writes a file. It uses the
standard library and `toolgate.gating.tool_calls` only, so it runs on the
slim install.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from toolgate.gating.tool_calls import (
    PATH_ARGUMENT_NAMES,
    URL_ARGUMENT_NAMES,
    _is_exact_non_string,
)

__all__ = [
    "PLACEHOLDER_HOST",
    "PLACEHOLDER_PATHS",
    "Classified",
    "SuggestError",
    "classify_tool",
    "draft_policy",
    "list_tools",
]

#: Reserved by RFC 2606: never resolves, so the placeholder allows nothing.
PLACEHOLDER_HOST = "example.invalid"
#: An absolute glob no real path matches.
PLACEHOLDER_PATHS = "/replace/with/allowed/dir/**"

_URL_TOKENS = frozenset(
    {"url", "urls", "uri", "uris", "href", "link", "links", "endpoint", "webhook"}
)
_URL_FORMATS = frozenset({"uri", "url", "iri", "uri-reference", "iri-reference"})
_PATH_TOKENS = frozenset(
    {"path", "paths", "file", "files", "filename", "dir", "directory", "folder", "root"}
    | PATH_ARGUMENT_NAMES
)
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")
_PLAIN_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")


class SuggestError(Exception):
    """The server could not be listed; nothing is drafted."""


@dataclass(frozen=True, slots=True)
class Classified:
    """One tool's string-capable arguments, sorted by guess."""

    url_args: tuple[str, ...] = ()
    path_args: tuple[str, ...] = ()
    ignore_args: tuple[str, ...] = ()
    readable: bool = True


def _tokens(name: str) -> set[str]:
    return {part.lower() for part in _SPLIT_RE.split(name) if part}


def _formats(prop: Any) -> set[str]:
    if not isinstance(prop, dict):
        return set()
    found = {prop["format"]} if isinstance(prop.get("format"), str) else set()
    items = prop.get("items")
    if isinstance(items, dict) and isinstance(items.get("format"), str):
        found.add(items["format"])
    return found


def classify_tool(schema: Any) -> Classified:
    """Sort the top-level arguments that need classification, in schema order.

    An argument whose schema is exactly `integer`, `number`, `boolean` or
    `null` needs none (`unclassified_arguments`' rule) and is left out. A
    top-level name classifies its whole value, nested or composite, so
    listing top-level names is always enough.
    """
    if not isinstance(schema, dict):
        return Classified(readable=False)
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return Classified(readable=False)
    urls: list[str] = []
    paths: list[str] = []
    others: list[str] = []
    for raw_name, prop in properties.items():
        name = str(raw_name)
        if _is_exact_non_string(prop):
            continue
        tokens = _tokens(name)
        if name in URL_ARGUMENT_NAMES or tokens & _URL_TOKENS or _formats(prop) & _URL_FORMATS:
            urls.append(name)
        elif name in PATH_ARGUMENT_NAMES or tokens & _PATH_TOKENS:
            paths.append(name)
        else:
            others.append(name)
    return Classified(tuple(urls), tuple(paths), tuple(others))


def _key(text: str) -> str:
    return text if _PLAIN_KEY_RE.match(text) else json.dumps(text)


def _flow(items: Sequence[str]) -> str:
    return json.dumps(list(items))


def draft_policy(name: str, tools: Sequence[dict[str, Any]]) -> str:
    """The policy draft for server `name`, as YAML text with review comments."""
    lines = [
        f"# toolgate policy draft for server {name!r}, from its tools/list",
        "# (toolgate policy suggest). Every rule below is a guess from argument",
        '# names and schema formats: review each line marked "# review" before use.',
        "# The placeholders allow nothing until you replace them:",
        f'#   egress: ["{PLACEHOLDER_HOST}"]  -> the hosts the tool may reach',
        f'#   paths: ["{PLACEHOLDER_PATHS}"]  -> the files the tool may touch',
        "tool_calls:",
        "  default: block",
    ]
    rules: list[str] = []
    seen: set[str] = set()
    for tool in tools:
        tool_name = tool.get("name")
        if not isinstance(tool_name, str) or tool_name in seen:
            continue
        seen.add(tool_name)
        key = _key(f"{name}.{tool_name}")
        classified = classify_tool(tool.get("inputSchema"))
        if not classified.readable:
            rules += [
                f"    {key}:  # review: input schema could not be read, so blocked",
                "      action: block",
            ]
            continue
        if not classified.url_args and not classified.path_args:
            rules.append(f"    {key}: {{}}  # review: no URL or path argument found; allowed")
            continue
        guessed = []
        if classified.url_args:
            guessed.append(f"URL: {', '.join(classified.url_args)}")
        if classified.path_args:
            guessed.append(f"path: {', '.join(classified.path_args)}")
        rules.append(f"    {key}:  # review: guessed {'; '.join(guessed)}")
        if classified.url_args:
            rules += [
                f'      egress: ["{PLACEHOLDER_HOST}"]  # review: the hosts this tool may reach',
                f"      url_args: {_flow(classified.url_args)}",
            ]
        if classified.path_args:
            rules += [
                f'      paths: ["{PLACEHOLDER_PATHS}"]  # review: the files this tool may touch',
                f"      path_args: {_flow(classified.path_args)}",
            ]
        if classified.ignore_args:
            rules.append(
                f"      ignore_args: {_flow(classified.ignore_args)}"
                "  # review: not checked against any rule"
            )
    lines += ["  rules:", *rules] if rules else ["  rules: {}"]
    return "\n".join(lines) + "\n"


# --- listing the server's tools ------------------------------------------------

_STDERR_KEEP = 4096


def _resolve(command: Sequence[str]) -> list[str]:
    """Find `npx` as `npx.cmd` on Windows, as `wrap` does (process.py)."""
    argv = list(command)
    if sys.platform == "win32" and argv and not os.path.dirname(argv[0]):
        found = shutil.which(argv[0])
        if found:
            argv[0] = found
    return argv


def list_tools(command: Sequence[str], *, timeout: float = 60.0) -> list[dict[str, Any]]:
    """Start the server, initialize, and return every tool from `tools/list`.

    Raises `SuggestError`, carrying the tail of the server's stderr, if the
    server cannot start, exits, answers with an error, or does not answer
    within `timeout` seconds overall.
    """
    if not command:
        raise SuggestError("no server command: use `toolgate policy suggest --name N -- <cmd>`")
    try:
        process = subprocess.Popen(
            _resolve(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise SuggestError(f"server failed to start: {exc}") from exc
    assert process.stdin is not None and process.stdout is not None
    assert process.stderr is not None
    lines: queue.Queue[bytes | None] = queue.Queue()
    stderr = bytearray()

    def read_stdout() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    def read_stderr() -> None:
        assert process.stderr is not None
        for chunk in iter(lambda: process.stderr.read(1024), b""):  # type: ignore[union-attr]
            stderr.extend(chunk)
            del stderr[:-_STDERR_KEEP]

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()
    deadline = time.monotonic() + timeout

    def fail(reason: str) -> SuggestError:
        tail = stderr.decode("utf-8", "replace").strip()
        return SuggestError(f"{reason}" + (f"; server stderr: {tail}" if tail else ""))

    def send(message: dict[str, Any]) -> None:
        try:
            process.stdin.write(json.dumps(message).encode() + b"\n")  # type: ignore[union-attr]
            process.stdin.flush()  # type: ignore[union-attr]
        except OSError as exc:
            raise fail(f"server closed its stdin ({exc})") from exc

    def reply(request_id: int) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise fail(f"no answer within {timeout:g} s")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if line is None:
                time.sleep(0.2)  # let the stderr reader catch the last words
                raise fail(f"server exited (status {process.poll()}) before answering")
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    raise fail(f"server answered with an error: {message['error']}")
                result = message.get("result")
                return result if isinstance(result, dict) else {}

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "toolgate-policy-suggest", "version": "0"},
                },
            }
        )
        reply(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        request_id = 2
        while True:
            params = {"cursor": cursor} if cursor else {}
            send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
            result = reply(request_id)
            page = result.get("tools")
            if not isinstance(page, list):
                raise fail("tools/list result has no tool list")
            tools += [tool for tool in page if isinstance(tool, dict)]
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor or request_id > 100:
                return tools
            cursor = next_cursor
            request_id += 1
    finally:
        with suppress(OSError):
            process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
