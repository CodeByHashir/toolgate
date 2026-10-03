"""A deliberately small MCP client: raw JSON-RPC lines over a child's stdio.

It does not use the `mcp` SDK, for two reasons. First, the demo must be able
to talk to *any* command -- a bare server, or the same server behind
`toolgate wrap ... --` -- and see exactly what a host would see, including a
locally-answered "blocked" reply. Second, the SDK parses and re-serialises
every message, which is the very behaviour the proxy's transparency tests
need to rule out on the client side.

Scope is what the demo needs and no more: `initialize`, `tools/list`,
`tools/call`, synchronous, one request in flight at a time. Server-to-client
requests (sampling, roots) are not expected because the client advertises no
capabilities; any that arrive are answered with "method not found" so the
server is never left waiting.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import shutil
import subprocess
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any

PROTOCOL_VERSION = "2025-06-18"


class McpClientError(RuntimeError):
    """The server did not answer, closed, or answered with a JSON-RPC error."""


def resolve_command(command: Sequence[str]) -> list[str]:
    """Resolve the executable on PATH, so `npx` finds `npx.cmd` on Windows."""
    if not command:
        raise ValueError("empty command")
    found = shutil.which(command[0])
    return [found or command[0], *command[1:]]


class StdioMcpClient:
    """Drive one MCP server process over newline-delimited JSON-RPC."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        timeout: float = 120.0,
    ) -> None:
        self.command = list(command)
        self.timeout = timeout
        self._process = subprocess.Popen(
            resolve_command(self.command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ if env is None else env),
            cwd=cwd,
        )
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self._stderr: list[str] = []
        self._next_id = 0
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    # -- plumbing -------------------------------------------------------------

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr.append(line.decode("utf-8", "replace").rstrip())

    @property
    def stderr(self) -> list[str]:
        """The child's stderr so far, for failure messages."""
        return list(self._stderr)

    def send(self, message: Mapping[str, Any]) -> None:
        self.send_raw(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n")

    def send_raw(self, line: bytes) -> None:
        """Write one line exactly as given. Lets tests send malformed input."""
        assert self._process.stdin is not None
        self._process.stdin.write(line)
        self._process.stdin.flush()

    def _receive(self) -> dict[str, Any]:
        try:
            line = self._lines.get(timeout=self.timeout)
        except queue.Empty:
            raise McpClientError(
                f"no reply within {self.timeout}s; stderr tail: {self._stderr[-5:]}"
            ) from None
        if line is None:
            raise McpClientError(f"server closed stdout; stderr tail: {self._stderr[-5:]}")
        message = json.loads(line)
        if not isinstance(message, dict):
            raise McpClientError(f"non-object message: {line[:200]!r}")
        return message

    def request(self, method: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Send one request and return the whole response message.

        Returns error responses rather than raising: a blocked call or a
        refused line is a result the demo inspects, not a client failure.
        """
        self._next_id += 1
        request_id = self._next_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = dict(params)
        self.send(message)
        while True:
            reply = self._receive()
            if "method" in reply and "id" in reply:
                # A server-to-client request. We advertised no capabilities.
                self.send(
                    {
                        "jsonrpc": "2.0",
                        "id": reply["id"],
                        "error": {"code": -32601, "message": "method not found"},
                    }
                )
                continue
            if reply.get("id") == request_id:
                return reply
            # A notification (logging, progress): not needed by the demo.

    # -- MCP ------------------------------------------------------------------

    def initialize(self) -> dict[str, Any]:
        reply = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "toolgate-demo-client", "version": "0"},
            },
        )
        if "error" in reply:
            raise McpClientError(f"initialize failed: {reply['error']}")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return reply

    def list_tools(self) -> list[dict[str, Any]]:
        """All tools, following `nextCursor` pagination."""
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            reply = self.request("tools/list", {"cursor": cursor} if cursor else {})
            if "error" in reply:
                raise McpClientError(f"tools/list failed: {reply['error']}")
            result = reply["result"]
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": dict(arguments)})

    # -- lifecycle -------------------------------------------------------------

    def close(self) -> int | None:
        """Close stdin, give the server 10 s to exit, then kill it."""
        if self._process.stdin is not None and not self._process.stdin.closed:
            with contextlib.suppress(OSError):
                self._process.stdin.close()
        try:
            return self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            return self._process.wait(timeout=10)

    def __enter__(self) -> StdioMcpClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def result_text(reply: Mapping[str, Any]) -> str:
    """Join the text blocks of a `tools/call` reply ("" for an error reply)."""
    result = reply.get("result")
    if not isinstance(result, dict):
        return ""
    return "\n".join(
        block.get("text", "")
        for block in result.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    )


def is_tool_error(reply: Mapping[str, Any]) -> bool:
    """True for a JSON-RPC error or a `CallToolResult` with `isError: true`."""
    if "error" in reply:
        return True
    result = reply.get("result")
    return isinstance(result, dict) and bool(result.get("isError"))


__all__ = [
    "PROTOCOL_VERSION",
    "McpClientError",
    "StdioMcpClient",
    "is_tool_error",
    "resolve_command",
    "result_text",
]
