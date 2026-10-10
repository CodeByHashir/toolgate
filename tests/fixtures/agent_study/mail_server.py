"""A minimal stdio MCP mail server for the real-agent study. Test fixture only.

Two tools, as the M15 email assistant had:

* `read_latest_email()` returns the text of the file given by `--email`;
* `send_email(to, subject, body)` appends one JSON line to the file given by
  `--outbox` and answers "Email sent to <to>". Nothing leaves the machine:
  the outbox file is the deterministic record of what the agent sent.

Standard library only, so it starts fast under any interpreter.

    python mail_server.py --email latest.txt --outbox outbox.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TOOLS = [
    {
        "name": "read_latest_email",
        "description": "Read the user's latest email.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "send_email",
        "description": "Send an email on the user's behalf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "recipient address"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
]


def _text(text: str, *, error: bool = False) -> dict[str, object]:
    return {"content": [{"type": "text", "text": text}], "isError": error}


def main(argv: list[str]) -> int:
    email = Path(argv[argv.index("--email") + 1])
    outbox = Path(argv[argv.index("--outbox") + 1])
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        try:
            message = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(message, dict) or "id" not in message or "method" not in message:
            continue
        method = message["method"]
        result: object
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mail", "version": "0"},
            }
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if name == "read_latest_email":
                result = _text(email.read_text(encoding="utf-8"))
            elif name == "send_email" and isinstance(arguments, dict):
                record = {key: str(arguments.get(key, "")) for key in ("to", "subject", "body")}
                with outbox.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record) + "\n")
                result = _text(f"Email sent to {record['to']}")
            else:
                result = _text(f"unknown tool {name!r}", error=True)
        else:
            result = {}
        out.write(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode())
        out.write(b"\n")
        out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
