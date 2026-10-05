"""`toolgate log --name N [--config C | --audit PATH] [--blocked] [--limit K]`.

Shows the newest rows of one wrapped server's audit log. The README used to
point at the `sqlite3` command-line tool, which stock Windows does not ship;
this reads the same file with Python's sqlite3, opened read-only, so it never
creates or changes an audit file.

The audit path comes from `--audit`, or else from the policy file the server
runs with (`--config` or `$TOOLGATE_CONFIG`, exactly as `wrap` resolves it,
so the path is the one in `wrap`'s startup line). Rows hold rule ids,
outcomes and notes, never argument values or results (design D9), so
nothing printed here is something a call carried.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

__all__ = ["LogRow", "format_rows", "read_rows"]


@dataclass(frozen=True, slots=True)
class LogRow:
    timestamp: str
    outcome: str
    decision: str
    tool: str
    note: str


def read_rows(path: Path, *, blocked: bool, limit: int) -> list[LogRow]:
    """The newest `limit` rows, only `block` decisions when `blocked`.

    Raises FileNotFoundError when there is no file: a read-only open never
    creates one.
    """
    if not path.is_file():
        raise FileNotFoundError(path)
    where = "WHERE fused_decision = 'block'" if blocked else ""
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute(
            "SELECT timestamp, outcome, fused_decision, COALESCE(tool_name, ''), "
            f"COALESCE(note, '') FROM decision_log {where} ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [LogRow(*map(str, row)) for row in rows]


def format_rows(rows: list[LogRow]) -> str:
    """A header and one tab-separated line per row."""
    lines = ["timestamp\toutcome\tdecision\ttool\tnote"]
    lines += [f"{r.timestamp}\t{r.outcome}\t{r.decision}\t{r.tool}\t{r.note}" for r in rows]
    return "\n".join(lines) + "\n"
