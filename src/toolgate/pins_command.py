"""`toolgate pins status|accept --name N [--config C] -- <server command>`.

`wrap` pins each tool declaration on first sight and never re-pins a
change, so that a rug-pull leaves evidence. The cost is that a legitimate
change, after an upgrade, stays `mutated` (and withheld, under `mutated:
block`) until an operator accepts it. Before this command the only way was
to delete the server's pin file, which re-trusted every tool at once.

`status` starts the server, reads its real `tools/list` (the same helper as
`policy suggest`) and prints one line per tool: its verdict against the pin
and, for a change, the names of the fields that moved. It writes nothing.
`accept` does the same check and then re-pins the tools that are new,
changed or pinned by an older canonicaliser, optionally only the ones named
with `--tool`. It pins what the server serves now, so it should be run
after reviewing the change, not instead of reviewing it.

Like the pin file itself, output carries tool names, verdicts and field
names, never a description or schema (SEC-3). A pin file that will not load
is refused, never overwritten: the operator decides whether to delete it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

import mcp_types
from pydantic import ValidationError

from toolgate.gating.declarations import hash_declaration
from toolgate.gating.pins import DeclarationVerdict, PinStore

__all__ = ["PinRow", "accept_tools", "check_tools", "format_rows"]

#: Verdicts `accept` re-pins. `unchanged` needs nothing; a declaration that
#: cannot be read cannot be pinned.
ACCEPTABLE = frozenset(
    {DeclarationVerdict.NEW, DeclarationVerdict.MUTATED, DeclarationVerdict.STALE_PIN}
)


@dataclass(frozen=True, slots=True)
class PinRow:
    tool: str
    #: A `DeclarationVerdict` value, `unreadable`, or `not listed` for a pin
    #: whose tool the server no longer declares.
    verdict: str
    changed: tuple[str, ...] = ()
    concealed: tuple[str, ...] = ()


def _parsed(tools: Iterable[dict[str, Any]]) -> list[tuple[str, mcp_types.Tool | None]]:
    out: list[tuple[str, mcp_types.Tool | None]] = []
    for raw in tools:
        name = str(raw.get("name", ""))
        try:
            out.append((name, mcp_types.Tool.model_validate(raw)))
        except (ValidationError, ValueError, TypeError):
            out.append((name, None))
    return out


def check_tools(store: PinStore, tools: Sequence[dict[str, Any]]) -> list[PinRow]:
    """Each listed tool's verdict against `store`, then pins no tool declares. Never writes."""
    rows: list[PinRow] = []
    listed: set[str] = set()
    for name, tool in _parsed(tools):
        listed.add(name)
        if tool is None:
            rows.append(PinRow(name, "unreadable"))
            continue
        verdict = store.verify_hashes(name, hash_declaration(tool))
        rows.append(PinRow(name, verdict.verdict.value, verdict.changed, verdict.concealed))
    rows += [PinRow(name, "not listed") for name in sorted(set(store.pins) - listed)]
    return rows


def accept_tools(
    store: PinStore, tools: Sequence[dict[str, Any]], only: Iterable[str] | None = None
) -> list[str]:
    """Re-pin new, changed and stale tools (only those in `only`, if given).

    Returns the names re-pinned. The caller saves the store. A name in
    `only` that the server does not declare is ignored; the caller reports
    it from `check_tools`.
    """
    wanted = None if only is None else set(only)
    accepted: list[str] = []
    for name, tool in _parsed(tools):
        if tool is None or (wanted is not None and name not in wanted):
            continue
        verdict = store.verify_hashes(name, hash_declaration(tool))
        if verdict.verdict in ACCEPTABLE:
            store.accept(tool)
            accepted.append(name)
    return accepted


def format_rows(rows: Sequence[PinRow]) -> str:
    """A header and one tab-separated line per tool."""
    lines = ["tool\tverdict\tchanged\tconcealed"]
    lines += [
        f"{r.tool}\t{r.verdict}\t{','.join(r.changed)}\t{','.join(r.concealed)}" for r in rows
    ]
    return "\n".join(lines) + "\n"
