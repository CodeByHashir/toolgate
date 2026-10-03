"""Transparency: what toolgate does not change, it forwards byte for byte (T11).

Design success criterion: wrapping `@modelcontextprotocol/server-everything`,
every line in either direction that is not a gated `tools/call`/`tools/list`
is forwarded byte-identical, compared as raw bytes, including sampling,
elicitation, roots, resources, prompts, logging and progress flows.

Set-up::

    test (host) <-> toolgate wrap <-> stdio_tee.py <-> server-everything
                                       (records bytes)

With a policy that names no rule and no redaction, the gated lines are not
changed either (an allowed call is forwarded as its original bytes, and an
unchanged result is not re-encoded), so the stronger statement holds and is
what is asserted: everything the host wrote is exactly what reached the
server, and everything the server wrote is exactly what reached the host.

The host side deliberately writes lines no re-serialiser would reproduce:
odd spacing, reordered keys, non-ASCII, `\\r\\n` endings, escaped slashes.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

EVERYTHING = ("npx", "-y", "@modelcontextprotocol/server-everything@2026.8.31")
TEE = Path(__file__).resolve().parent / "fixtures" / "stdio_tee.py"

POLICY = """
calibrated: false
on_detector_failure: escalate
detectors:
  injection: []
  redaction: []
  inert: []
state_dir: "state"
"""

pytestmark = [
    pytest.mark.live_servers,
    pytest.mark.skipif(shutil.which("npx") is None, reason="npx starts server-everything"),
]


class Host:
    """A scripted MCP host speaking raw lines to `toolgate wrap`."""

    def __init__(self, args: list[str], cwd: Path) -> None:
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=dict(os.environ),
        )
        self.sent = bytearray()
        self.received = bytearray()
        self.messages: list[dict[str, Any]] = []
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self.stderr = b""
        threading.Thread(target=self._read_stdout, daemon=True).start()
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        for raw in self.process.stdout:
            self._lines.put(raw)
        self._lines.put(None)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        self.stderr = self.process.stderr.read()

    def write(self, raw: bytes) -> None:
        assert self.process.stdin is not None
        self.sent += raw
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def request(self, raw: bytes, request_id: Any) -> dict[str, Any]:
        """Send one request; answer server requests until its reply arrives."""
        self.write(raw)
        while True:
            line = self._lines.get(timeout=120)
            assert line is not None, f"proxy closed stdout; stderr: {self.stderr[-2000:]!r}"
            self.received += line
            message = json.loads(line)
            self.messages.append(message)
            if "method" in message and "id" in message:
                self._answer(message)
            elif message.get("id") == request_id and "method" not in message:
                return message

    def _answer(self, message: dict[str, Any]) -> None:
        method = message["method"]
        if method == "sampling/createMessage":
            result: Any = {
                "role": "assistant",
                "content": {"type": "text", "text": "r\u00e9ponse \u2603"},
                "model": "test-model",
                "stopReason": "endTurn",
            }
        elif method == "elicitation/create":
            result = {"action": "decline"}
        elif method == "roots/list":
            result = {"roots": [{"uri": "file:///tmp/root", "name": "root"}]}
        else:
            result = {}
        # Hand-written, with spacing a re-serialiser would not reproduce.
        reply = json.dumps({"result": result, "id": message["id"], "jsonrpc": "2.0"}, indent=None)
        self.write(reply.replace(", ", " ,  ").encode("utf-8") + b"\n")

    def finish(self) -> int:
        assert self.process.stdin is not None
        self.process.stdin.close()
        while (line := self._lines.get(timeout=60)) is not None:
            self.received += line
        code = self.process.wait(timeout=60)
        self._stderr_thread.join(timeout=30)
        return code


def test_everything_session_is_byte_identical_in_both_directions(tmp_path: Path) -> None:
    config = tmp_path / "everything.yaml"
    config.write_text(POLICY, encoding="utf-8")
    tee_log = tmp_path / "tee"
    host = Host(
        [
            sys.executable,
            "-m",
            "toolgate",
            "wrap",
            "--name",
            "everything",
            "--config",
            str(config),
            "--",
            sys.executable,
            str(TEE),
            str(tee_log),
            "--respace",
            "--",
            *EVERYTHING,
        ],
        cwd=tmp_path,
    )

    host.request(
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
        b'"capabilities":{"sampling":{},"elicitation":{},"roots":{"listChanged":true}},'
        b'"clientInfo":{"name":"transparency-test","version":"0"}}}\n',
        1,
    )
    host.write(b'{ "method" : "notifications/initialized" , "jsonrpc" : "2.0" }\r\n')
    host.request(b'{"id":2,"jsonrpc":"2.0","method":"tools/list"}\n', 2)
    host.request(b'{"jsonrpc":"2.0","id":"p-3","method":"prompts/list"}\n', "p-3")
    host.request(
        b'{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"simple-prompt"}}\r\n', 4
    )
    resources = host.request(b'{"jsonrpc":"2.0","id":5,"method":"resources/list"}\n', 5)
    uri = resources["result"]["resources"][0]["uri"]
    host.request(
        b'{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":'
        + json.dumps(uri).encode()
        + b"}}\n",
        6,
    )
    host.request(
        b'{"jsonrpc":"2.0","id":7,"method":"logging/setLevel","params":{"level":"debug"}}\n', 7
    )
    host.request(
        '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo",'
        '"arguments":{"message":"h\u00e9llo \u2603 \\/ \\u00e9"}}}\n'.encode(),
        8,
    )
    host.request(
        b'{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":'
        b'"trigger-long-running-operation","arguments":{"duration":1,"steps":2},'
        b'"_meta":{"progressToken":"tok-9"}}}\n',
        9,
    )
    host.request(
        b'{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":'
        b'"trigger-sampling-request","arguments":{"prompt":"hi"}}}\n',
        10,
    )
    host.request(
        b'{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":'
        b'"trigger-elicitation-request","arguments":{}}}\n',
        11,
    )
    host.request(
        b'{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"get-roots-list",'
        b'"arguments":{}}}\n',
        12,
    )
    host.request(b'{"jsonrpc":"2.0","id":13,"method":"ping"}\n', 13)
    code = host.finish()
    assert code == 0, host.stderr.decode(errors="replace")

    # The flows the criterion names actually happened.
    methods = {m.get("method") for m in host.messages}
    assert {"sampling/createMessage", "elicitation/create", "notifications/progress"} <= methods

    # The claim itself: raw bytes, both directions.
    reached_server = (tmp_path / "tee.in").read_bytes()
    left_server = (tmp_path / "tee.out").read_bytes()
    assert reached_server == bytes(host.sent)
    assert left_server == bytes(host.received)
