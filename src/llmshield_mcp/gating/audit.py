"""Structured audit log of every gating decision (FR-8, PROPOSAL.md section 12).

SQLite, single operator, no concurrency beyond the reference agent.

The full decision vocabulary and the whole column set are defined here in M2
even though M2 only ever emits `allow` and records no detector scores. Fixing
the schema before detection exists means the log written by later milestones is
comparable to the log written now, and that the M2 "logging only" run is a real
baseline rather than a different format that happens to share a name.

Raw tool-result content is deliberately **not** stored. Section 12 keeps a hash
instead, so the audit store does not accumulate a corpus of adversarial text.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path


class Decision(StrEnum):
    """The four outcomes FR-4 allows. M2 only ever produces ALLOW."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    ESCALATE = "escalate"


class Outcome(StrEnum):
    """What kind of frame the decision was made about.

    `PROTOCOL_ERROR` exists to satisfy FR-15: a JSON-RPC error carries no tool
    content, so it is passed through with no content-based detection. Logging
    it under a distinct outcome keeps those rows out of any later false-positive
    denominator instead of silently counting as benign allows.

    A fourth member, `SESSION_SUMMARY`, existed briefly for M12's session
    accumulator and was removed with it (`plan.md` 2.25). Every row in this
    table is a per-call decision again, so no consumer has to remember to
    filter a non-decision row out of an FPR denominator or a latency average.
    """

    RESULT = "result"
    PROTOCOL_ERROR = "protocol_error"
    DETECTOR_FAILURE = "detector_failure"
    #: A `tools/call` REQUEST judged by the capability layer
    #: (`gating/tool_calls.py`) before it was sent. Distinct from RESULT so
    #: request-side decisions never land in a denominator meant for
    #: content-detection statistics -- they are a different experiment.
    TOOL_CALL = "tool_call"


SCHEMA = """
CREATE TABLE IF NOT EXISTS decision_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL,
    correlation_id    TEXT    NOT NULL,
    mcp_server_id     TEXT    NOT NULL,
    tool_name         TEXT,
    request_id        TEXT,
    raw_result_hash   TEXT    NOT NULL,
    detector_scores   TEXT    NOT NULL,
    fused_decision    TEXT    NOT NULL,
    redacted          INTEGER NOT NULL,
    latency_ms        REAL    NOT NULL,
    roundtrip_ms      REAL    NOT NULL,
    outcome           TEXT    NOT NULL,
    tool_is_error     INTEGER NOT NULL,
    content_chars     INTEGER NOT NULL,
    truncated         INTEGER NOT NULL,
    block_types       TEXT    NOT NULL,
    malformed         TEXT,
    note              TEXT
);
CREATE INDEX IF NOT EXISTS idx_decision_correlation ON decision_log (correlation_id);
CREATE INDEX IF NOT EXISTS idx_decision_server_tool ON decision_log (mcp_server_id, tool_name);
"""


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """One row of the decision log."""

    correlation_id: str
    mcp_server_id: str
    raw_result_hash: str
    fused_decision: Decision
    #: Time spent inside the gate itself. This is the number FR-13 and NFR-1
    #: are about; in M2, with no detectors, it is the cost of the plumbing.
    latency_ms: float
    #: Time from the tool call leaving the client to its response arriving.
    #: Kept separate so gate overhead is never confused with server time.
    roundtrip_ms: float = 0.0
    outcome: Outcome = Outcome.RESULT
    tool_name: str | None = None
    request_id: str | None = None
    detector_scores: dict[str, object] = field(default_factory=dict)
    redacted: bool = False
    tool_is_error: bool = False
    content_chars: int = 0
    truncated: bool = False
    block_types: tuple[str, ...] = ()
    malformed: str | None = None
    note: str | None = None
    timestamp: str = ""

    def with_timestamp(self) -> DecisionRecord:
        if self.timestamp:
            return self
        return replace(self, timestamp=datetime.now(UTC).isoformat())


class DecisionLog:
    """Append-only SQLite store for gating decisions.

    Append-only literally: there is no update or delete on this class. An
    earlier revision added an `update_note` for M12's session accumulator; both
    were removed (`plan.md` 2.25), which restored the property that a written
    row never changes.

    `path=None` opens an in-memory database instead of a file. That is what
    makes gating usable *without* persisting anything: the `Gate` requires a
    log to write to, but "I want interception without an audit file on disk"
    is a legitimate configuration, and before this it was unreachable -- the
    CLI turned gating on only when a `--db` path was supplied, so declining to
    log also declined to gate. Rows still exist for the process lifetime, so
    `count()` reports honestly; nothing is written to disk and nothing
    survives `close()`.
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        if path is None:
            self._connection = sqlite3.connect(":memory:", check_same_thread=False)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    @property
    def persistent(self) -> bool:
        """False for an in-memory log whose rows are discarded on close."""
        return self.path is not None

    def append(self, record: DecisionRecord) -> None:
        stamped = record.with_timestamp()
        self._connection.execute(
            """
            INSERT INTO decision_log (
                timestamp, correlation_id, mcp_server_id, tool_name, request_id,
                raw_result_hash, detector_scores, fused_decision, redacted,
                latency_ms, roundtrip_ms, outcome, tool_is_error, content_chars,
                truncated, block_types, malformed, note
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                stamped.timestamp,
                stamped.correlation_id,
                stamped.mcp_server_id,
                stamped.tool_name,
                stamped.request_id,
                stamped.raw_result_hash,
                json.dumps(stamped.detector_scores, sort_keys=True),
                str(stamped.fused_decision),
                int(stamped.redacted),
                stamped.latency_ms,
                stamped.roundtrip_ms,
                str(stamped.outcome),
                int(stamped.tool_is_error),
                stamped.content_chars,
                int(stamped.truncated),
                json.dumps(list(stamped.block_types)),
                stamped.malformed,
                stamped.note,
            ),
        )
        self._connection.commit()

    def rows(self) -> list[sqlite3.Row]:
        self._connection.row_factory = sqlite3.Row
        with closing(self._connection.execute("SELECT * FROM decision_log ORDER BY id")) as cursor:
            return cursor.fetchall()

    def count(self) -> int:
        with closing(self._connection.execute("SELECT COUNT(*) FROM decision_log")) as cursor:
            return int(cursor.fetchone()[0])

    def close(self) -> None:
        self._connection.close()


@contextmanager
def decision_log(path: Path | None) -> Iterator[DecisionLog]:
    log = DecisionLog(path)
    try:
        yield log
    finally:
        log.close()
