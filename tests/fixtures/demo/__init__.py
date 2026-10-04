"""The cross-server exfiltration demo, as test fixtures.

This package is the v0.1 acceptance scenario (design "The demo") reduced to
parts a script can drive. Nothing here is toolgate: it is the attack and its
witnesses, so the same parts can be run with toolgate removed (the recorded
"off" run) and, later, with each server wrapped by `toolgate wrap` (the T9 E2E
and the post-publish smoke job) without changing a line.

The parts:

* `project/` -- the directory the `filesystem` server is confined to. Its
  `.env` holds `CANARY`. It is the only committed `.env` in the repository
  (`.gitignore` names it as an exception).
* `http_fixtures.PageServer` -- the "allowed" site. Serves a page carrying an
  indirect injection that tells the agent to read `.env` and fetch an attacker
  URL with the contents in the query. Binds `127.0.0.1` and `::1` on one port,
  because `mcp-server-fetch` reached `localhost` over `::1` on Windows in the
  2026-10-03 probe. Answers 404 for `/robots.txt` (which the fetch server
  requests first and treats 404 as "allowed"), and `/redirect` answers 302 to
  the attacker for the redirect variant.
* `http_fixtures.AttackerListener` -- binds `127.0.0.1` only and records every
  request. "Did the canary leak?" is answered by this record and nothing else.
* `mcp_client.StdioMcpClient` -- a raw JSON-RPC client over a child's stdio. It
  does not use the `mcp` SDK on purpose: it must speak to whatever command it
  is given, including `toolgate wrap ... -- <server>`, and it must see blocked
  replies exactly as a host would.
* `scenario` -- replays exactly the calls the injection asks for, one variant
  at a time, and reports what each witness saw. `python -m
  tests.fixtures.demo.scenario --help` runs it against arbitrary server
  commands.

Everything is standard library only, so the scenario runs under any Python 3.11
interpreter, not just the project's environment.
"""

from __future__ import annotations

from pathlib import Path

#: The demo project the filesystem server is confined to.
PROJECT_DIR: Path = Path(__file__).resolve().parent / "project"

#: The token in `PROJECT_DIR/.env`. Random hex, not PII-shaped, grants nothing.
CANARY: str = "tg-7f3a9c1e5b2d4e60"

#: The `.env` line the read is expected to return verbatim.
CANARY_LINE: str = f"TOOLGATE_CANARY={CANARY}"

#: Pinned launch commands, identical to `config/servers.yaml` (a test checks
#: that they agree). `{project}` is replaced with the project directory.
FILESYSTEM_COMMAND: tuple[str, ...] = (
    "npx",
    "-y",
    "@modelcontextprotocol/server-filesystem@2026.8.31",
    "{project}",
)
FETCH_COMMAND: tuple[str, ...] = ("uvx", "mcp-server-fetch==2026.8.18")

#: The page port people use when running the demo by hand, and the one
#: `demo/fetch.yaml` allowlists. Tests never use it: they pick ephemeral ports
#: and write a copy of the policy with the real one (egress entries do not
#: expand placeholders).
DOCUMENTED_PAGE_PORT: int = 8765

__all__ = [
    "CANARY",
    "CANARY_LINE",
    "DOCUMENTED_PAGE_PORT",
    "FETCH_COMMAND",
    "FILESYSTEM_COMMAND",
    "PROJECT_DIR",
]
