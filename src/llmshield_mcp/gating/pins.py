"""Trust-on-first-use pin store for MCP tool declarations (step 2).

Step 1 (`gating/declarations.py`) can say whether two declarations are the same
bytes. This turns that into a control with memory: the first time a tool is
seen its digests are written down, and every later sighting is compared against
what was written.

## What a pin can and cannot tell you

**It cannot tell you a server is malicious.** A server that ships a poisoned
description at install time is pinned exactly as faithfully as an honest one,
and `new` is the verdict either way. Concealment is the one exception, and only
because it is a property of a single declaration rather than of a change
(`DeclarationHashes.concealed`).

**It can tell you a server changed its mind after you trusted it.** That is the
rug-pull case, and it is the whole claim. `notifications/tools/list_changed`
exists in the protocol, so a server can do this mid-session, after any approval
a human gave.

Those are different claims and only the second is being made.

## Trust on first use, and why the first sight is still logged

An unseen tool is recorded and allowed. The alternative -- refusing anything
unpinned -- would mean no server works until an operator hand-writes a pin file,
which is a control people switch off. `config/policy.yaml`'s own header records
that lesson.

But first sight is never *silent*: it returns `NEW`, which a caller logs. An
operator who sees `new` for a tool they have been using for a month is looking
at either a reinstalled pin store or a renamed tool, and both are worth knowing.

## A mutation never re-pins itself

`observe()` writes a pin on `NEW` and on nothing else. If a mutated declaration
updated the pin, the second sighting would report `UNCHANGED` and the evidence
would be gone -- the control would erase exactly the event it exists to record.
Accepting a change is an explicit operator act, `accept()`.

## The pin file is not tamper-proof, and this does not pretend otherwise

An attacker who can write to `pins/` can delete a pin and reset that tool to
trust-on-first-use, or rewrite one to match a poisoned declaration. File
permissions are the answer to that, not this module. Stating it plainly is
better than implying a guarantee the storage layer does not provide.

What the store *does* refuse to do is fail open quietly: an unreadable or
malformed pin file raises `PinStoreCorrupt` rather than starting empty, because
"start empty" and "trust everything again" are the same thing.

## No content, ever

Hashes, field names, timestamps and a version. Never a description, a schema,
or any string a server supplied. A tool description can carry anything --
including the payload this module exists to catch -- and SEC-3 is the rule that
this project does not accumulate a corpus of it on disk. `test_gating_pins.py`
asserts this against the written bytes rather than trusting the intent.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import mcp_types

from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.gating.declarations import (
    CANONICALISER_VERSION,
    HASHED_FIELDS,
    DeclarationHashes,
    hash_declaration,
)

#: Gitignored by default, like every other runtime artifact here. An operator
#: who wants pins under review commits them deliberately; see `.gitignore`.
DEFAULT_PIN_DIR = REPO_ROOT / "pins"

#: The on-disk layout. Separate from `CANONICALISER_VERSION`: the file format
#: and the hashing rules can move independently, and a reader has to be able to
#: tell which one changed.
PIN_SCHEMA_VERSION = 1


class DeclarationVerdict(StrEnum):
    """What the pin store says about one declaration.

    `SHADOWED` is deliberately absent: a name owned by another server is not a
    property of this server's pin file, so it belongs to the cross-server view
    in step 3 rather than here.
    """

    #: Never seen before. Recorded and allowed (trust on first use).
    NEW = "new"
    #: Byte-identical to the pin.
    UNCHANGED = "unchanged"
    #: Pinned, and at least one field's digest differs.
    MUTATED = "mutated"
    #: A pin exists but was written by a different canonicaliser version, so no
    #: integrity claim can be made about it either way.
    STALE_PIN = "stale_pin"


class PinStoreCorrupt(Exception):
    """Raised when a pin file exists but cannot be trusted to mean anything.

    Not caught and turned into an empty store on purpose. Silently restarting
    from zero would convert "someone damaged the pin file" into "every tool is
    new again", which is indistinguishable from a successful attack on the
    control.
    """


@dataclass(frozen=True, slots=True)
class ToolPin:
    """What is remembered about one tool. Digests and metadata only."""

    fields: Mapping[str, str]
    combined: str
    canonicaliser_version: int
    first_seen: str
    #: Fields that carried non-rendering characters when first pinned, so a
    #: later verdict can distinguish "always concealed" from "started
    #: concealing".
    concealed: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "fields": dict(self.fields),
            "combined": self.combined,
            "canonicaliser_version": self.canonicaliser_version,
            "first_seen": self.first_seen,
            "concealed": list(self.concealed),
        }

    @classmethod
    def from_json(cls, raw: Any, *, tool: str) -> ToolPin:
        if not isinstance(raw, dict):
            raise PinStoreCorrupt(f"pin for {tool!r} is not an object")
        try:
            fields = raw["fields"]
            combined = raw["combined"]
            version = raw["canonicaliser_version"]
            first_seen = raw["first_seen"]
        except KeyError as exc:
            raise PinStoreCorrupt(f"pin for {tool!r} is missing {exc.args[0]!r}") from exc
        if not isinstance(fields, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in fields.items()
        ):
            raise PinStoreCorrupt(f"pin for {tool!r} has a malformed field map")
        if not isinstance(combined, str) or not isinstance(first_seen, str):
            raise PinStoreCorrupt(f"pin for {tool!r} has a malformed digest or timestamp")
        if not isinstance(version, int) or isinstance(version, bool):
            raise PinStoreCorrupt(f"pin for {tool!r} has a malformed canonicaliser version")
        concealed = raw.get("concealed", [])
        if not isinstance(concealed, list) or not all(isinstance(x, str) for x in concealed):
            raise PinStoreCorrupt(f"pin for {tool!r} has a malformed concealed list")
        return cls(
            fields=fields,
            combined=combined,
            canonicaliser_version=version,
            first_seen=first_seen,
            concealed=tuple(concealed),
        )


@dataclass(frozen=True, slots=True)
class PinVerdict:
    """One declaration, checked against the store."""

    server: str
    tool: str
    verdict: DeclarationVerdict
    #: Field names whose digest moved. Empty unless `verdict` is `MUTATED`.
    changed: tuple[str, ...] = ()
    #: Field names carrying non-rendering characters *now*. Orthogonal to
    #: `verdict` -- a first-sight declaration can be concealed.
    concealed: tuple[str, ...] = ()
    #: True when concealment is present now and was not present at first pin.
    concealment_is_new: bool = False
    first_seen: str | None = None
    #: Combined digest of the declaration as just seen. Carried so an audit row
    #: can identify which bytes a verdict was about without storing any of them.
    combined: str = ""

    @property
    def is_actionable(self) -> bool:
        """Anything an operator would want to look at.

        `NEW` counts: trust-on-first-use allows it, but the plan's requirement
        is that the first sight is never silent.
        """
        return self.verdict is not DeclarationVerdict.UNCHANGED or bool(self.concealed)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def pin_path(server: str, *, directory: Path | None = None) -> Path:
    """Where one server's pins live.

    The server name comes from `config/servers.yaml`, which is operator-written
    rather than server-supplied, but it is still put through a check: a name
    containing a separator would place the file outside `directory`.
    """
    if not server or "/" in server or "\\" in server or server in {".", ".."}:
        raise ValueError(f"server name {server!r} is not usable as a filename")
    return (directory or DEFAULT_PIN_DIR) / f"{server}.json"


@dataclass
class PinStore:
    """The pins for one MCP server, held in memory and written atomically."""

    server: str
    path: Path
    pins: dict[str, ToolPin]
    #: Set when `record`/`accept`/`forget` changed something not yet on disk.
    dirty: bool = False

    @classmethod
    def load(cls, server: str, *, directory: Path | None = None) -> PinStore:
        """Read a server's pin file, or start empty if it does not exist.

        A *missing* file is a first run. A file that exists but cannot be
        parsed raises: see `PinStoreCorrupt`.
        """
        path = pin_path(server, directory=directory)
        if not path.exists():
            return cls(server=server, path=path, pins={})

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PinStoreCorrupt(f"{path} could not be read: {exc}") from exc

        if not isinstance(raw, dict):
            raise PinStoreCorrupt(f"{path} is not a JSON object")

        schema = raw.get("schema_version")
        if schema != PIN_SCHEMA_VERSION:
            raise PinStoreCorrupt(
                f"{path} has schema_version {schema!r}, this build writes {PIN_SCHEMA_VERSION}"
            )

        tools = raw.get("tools")
        if not isinstance(tools, dict):
            raise PinStoreCorrupt(f"{path} has no usable 'tools' object")

        return cls(
            server=server,
            path=path,
            pins={name: ToolPin.from_json(pin, tool=name) for name, pin in tools.items()},
        )

    def verify(self, tool: mcp_types.Tool) -> PinVerdict:
        """Check one declaration against the store. Never writes."""
        return self.verify_hashes(tool.name, hash_declaration(tool))

    def verify_hashes(self, name: str, hashes: DeclarationHashes) -> PinVerdict:
        """The same check from pre-computed digests.

        Split out so a caller that already hashed a declaration -- step 3 will
        have, to detect shadowing across servers -- does not hash it twice.
        """
        pin = self.pins.get(name)
        if pin is None:
            return PinVerdict(
                server=self.server,
                tool=name,
                verdict=DeclarationVerdict.NEW,
                concealed=hashes.concealed,
                concealment_is_new=bool(hashes.concealed),
                combined=hashes.combined,
            )

        concealment_is_new = bool(set(hashes.concealed) - set(pin.concealed))

        if pin.canonicaliser_version != hashes.version:
            # Deliberately not compared field by field: digests from different
            # canonicaliser versions are not commensurable, and reporting
            # `unchanged` or `mutated` here would be inventing a claim.
            return PinVerdict(
                server=self.server,
                tool=name,
                verdict=DeclarationVerdict.STALE_PIN,
                concealed=hashes.concealed,
                concealment_is_new=concealment_is_new,
                first_seen=pin.first_seen,
                combined=hashes.combined,
            )

        changed = tuple(
            field for field in HASHED_FIELDS if pin.fields.get(field) != hashes.fields.get(field)
        )
        return PinVerdict(
            server=self.server,
            tool=name,
            verdict=DeclarationVerdict.MUTATED if changed else DeclarationVerdict.UNCHANGED,
            changed=changed,
            concealed=hashes.concealed,
            concealment_is_new=concealment_is_new,
            first_seen=pin.first_seen,
            combined=hashes.combined,
        )

    def observe(self, tool: mcp_types.Tool) -> PinVerdict:
        """Verify, and pin on first sight only.

        The asymmetry is the point. `NEW` records, because trust on first use
        is how this ships without breaking every server. `MUTATED` does not,
        because a pin that updated itself on mutation would report `UNCHANGED`
        the next time and destroy the evidence.
        """
        hashes = hash_declaration(tool)
        verdict = self.verify_hashes(tool.name, hashes)
        if verdict.verdict is DeclarationVerdict.NEW:
            self._write_pin(tool.name, hashes, first_seen=_now())
        return verdict

    def record_hashes(self, name: str, hashes: DeclarationHashes) -> None:
        """Pin pre-computed digests. The write path for a caller that already
        hashed the declaration, so it is not hashed twice per listing."""
        self._write_pin(name, hashes, first_seen=_now())

    def accept(self, tool: mcp_types.Tool) -> None:
        """Re-pin a tool to its current declaration. An explicit operator act.

        `first_seen` is reset, because the pin now records a different
        declaration and carrying the old timestamp forward would misdate it.
        """
        self._write_pin(tool.name, hash_declaration(tool), first_seen=_now())

    def forget(self, name: str) -> bool:
        """Drop a pin. Returns whether there was one."""
        if name not in self.pins:
            return False
        del self.pins[name]
        self.dirty = True
        return True

    def _write_pin(self, name: str, hashes: DeclarationHashes, *, first_seen: str) -> None:
        self.pins[name] = ToolPin(
            fields=dict(hashes.fields),
            combined=hashes.combined,
            canonicaliser_version=hashes.version,
            first_seen=first_seen,
            concealed=hashes.concealed,
        )
        self.dirty = True

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PIN_SCHEMA_VERSION,
            "canonicaliser_version": CANONICALISER_VERSION,
            "server": self.server,
            "tools": {name: pin.to_json() for name, pin in sorted(self.pins.items())},
        }

    def save(self) -> None:
        """Write the pin file atomically.

        Temp file plus `os.replace`, which is atomic on POSIX and on Windows.
        A half-written pin file is a corrupt one, and a corrupt one refuses to
        load -- so a crash mid-write would take the control offline rather than
        quietly weaken it.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(f"{self.path.name}.tmp")
        payload = json.dumps(self.to_json(), indent=2, sort_keys=True, ensure_ascii=False)
        try:
            temp.write_text(payload + "\n", encoding="utf-8")
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)
        self.dirty = False


__all__ = [
    "DEFAULT_PIN_DIR",
    "PIN_SCHEMA_VERSION",
    "DeclarationVerdict",
    "PinStore",
    "PinStoreCorrupt",
    "PinVerdict",
    "ToolPin",
    "pin_path",
]
