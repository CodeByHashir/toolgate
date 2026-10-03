"""A minimal stdio MCP server for `toolgate wrap` tests. Test fixture only.

Answers `initialize`, `tools/list` (declares `fetch` and `echo`) and
`tools/call` (echoes the call back as text), one line at a time. Standard
library only, so it starts fast under any interpreter.

Options (argv):

* `--marker PATH`  write PATH when started, so a test can prove the server
  was (or was not) launched;
* `--exit-after N` exit with status 7 after answering N requests, so a test
  can make the server go first;
* `--env NAME`     include the value of environment variable NAME in every
  echo result;
* `--payload N`    answer every tools/call with N bytes of plain filler text
  instead of the echo (for the latency benchmark).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "fetch",
        "description": "fetch a URL",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "raw": {"type": "boolean"}},
            "required": ["url"],
        },
    },
    {"name": "echo", "description": "echo", "inputSchema": {"type": "object", "properties": {}}},
]


def main(argv: list[str]) -> int:
    marker = argv[argv.index("--marker") + 1] if "--marker" in argv else None
    exit_after = int(argv[argv.index("--exit-after") + 1]) if "--exit-after" in argv else None
    env_name = argv[argv.index("--env") + 1] if "--env" in argv else None
    payload_bytes = int(argv[argv.index("--payload") + 1]) if "--payload" in argv else None
    filler = ("the quick brown fox jumps over the lazy dog " * 4096)[: payload_bytes or 0]
    if marker:
        Path(marker).write_text("started", encoding="utf-8")

    answered = 0
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        message = json.loads(raw)
        if "id" not in message or "method" not in message:
            continue
        method = message["method"]
        if method == "initialize":
            result: object = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake", "version": "0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call" and payload_bytes is not None:
            result = {"content": [{"type": "text", "text": filler}]}
        elif method == "tools/call":
            text = json.dumps(message.get("params", {}), sort_keys=True)
            if env_name:
                text += f" env={os.environ.get(env_name, '<unset>')}"
            result = {"content": [{"type": "text", "text": text}]}
        else:
            result = {}
        out.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode())
        out.write(b"\n")
        out.flush()
        answered += 1
        if exit_after is not None and answered >= exit_after:
            return 7
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
