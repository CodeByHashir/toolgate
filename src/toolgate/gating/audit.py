"""Structured audit log of every gating decision (FR-8, PROPOSAL.md section 12).

SQLite. File-backed logs run in WAL mode with `synchronous=NORMAL` and a 2 s
busy timeout, so several `toolgate wrap` processes can share one file if the
operator chooses to; by default each wrapped server writes its own
(`default_audit_path`). `AuditWriter` is the proxy's failure rule around it.

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
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

#: How long a writer waits for another process's lock before the write fails
#: and counts toward `AuditWriter`'s failure rule (design D9).
BUSY_TIMEOUT_MS = 2000


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
    accumulator and was removed with it. Every row in this
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
    #: A tool DECLARATION judged against its pin (`gating/declaration_gate.py`),
    #: at most once per tool per listing. Distinct from the two above for the
    #: same reason they are distinct from each other: these rows are the output
    #: of a hash comparison, not of a classifier, so counting them in any
    #: detection statistic would mix a deterministic check into a measured one.
    #:
    #: They also serve a second purpose. The pin file is not tamper-proof
    #: (`SECURITY.md`), and these rows are the corroborating record: a `new`
    #: verdict for a tool this log pinned months ago is a contradiction rather
    #: than a first sighting, which is what `declaration_seen()` reports.
    TOOL_DECLARATION = "tool_declaration"


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
    were removed, which restored the property that a written
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
            self._connection = sqlite3.connect(
                path, check_same_thread=False, timeout=BUSY_TIMEOUT_MS / 1000
            )
            # WAL with synchronous=NORMAL drops the fsync per commit (design
            # D17): each `toolgate wrap` writes its row inline, in front of the
            # tool call, and a disk flush per call would dominate the proxy's
            # added latency. The cost, stated: a power loss can lose the last
            # few committed rows. WAL also lets several `wrap` processes share
            # one file (D9); the busy timeout bounds how long a writer waits
            # for another's lock before the write counts as failed.
            self._connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            self._enable_wal()
            self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    def _enable_wal(self) -> None:
        """Switch to WAL, retrying within the busy timeout.

        Changing the journal mode needs an exclusive lock, and SQLite can
        report "database is locked" for it at once rather than through the
        busy handler. Two `wrap` processes opening a fresh shared file at the
        same moment hit exactly that (caught by the two-process test). Retrying
        within the same 2 s bound gives the other opener time to finish; past
        it the error is real and propagates.
        """
        deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1000
        while True:
            try:
                self._connection.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

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

    def declaration_seen(self, server: str, tool: str) -> bool:
        """Whether this log already holds a declaration row for one tool.

        The corroborating half of pin-file integrity. A pin file can be deleted
        to return a tool to trust-on-first-use, and nothing inside that file can
        prevent it (`SECURITY.md`). But the deletion does not reach this log, so
        a `new` verdict for a tool with rows here is a contradiction between two
        stores rather than a first sighting.

        This raises the cost of a silent reset from "delete one file" to "tamper
        with two stores consistently". It is not a guarantee: an attacker who
        can delete the pin file can usually delete the database too. It makes
        the attack noisier, which is the honest claim.

        Uses the existing `(mcp_server_id, tool_name)` index.
        """
        query = (
            "SELECT 1 FROM decision_log "
            "WHERE mcp_server_id = ? AND tool_name = ? AND outcome = ? LIMIT 1"
        )
        with closing(
            self._connection.execute(query, (server, tool, Outcome.TOOL_DECLARATION.value))
        ) as cursor:
            return cursor.fetchone() is not None

    def close(self) -> None:
        self._connection.close()


@contextmanager
def decision_log(path: Path | None) -> Iterator[DecisionLog]:
    log = DecisionLog(path)
    try:
        yield log
    finally:
        log.close()


def default_audit_path(state_dir: Path, server: str) -> Path:
    """Where `toolgate wrap --name <server>` writes its log by default.

    One file per server (design D9): each wrapped server is its own process,
    and separate files mean no two of them ever contend for a write lock. A
    shared path is still allowed by configuration; WAL handles that case.
    """
    return state_dir / "audit" / f"{server}.sqlite"


class AuditFailure(RuntimeError):
    """The audit log failed too many times in a row to keep running."""


class _Appendable(Protocol):
    def append(self, record: DecisionRecord) -> None: ...


def _report_to_stderr(message: str) -> None:
    with suppress(OSError, ValueError, AttributeError):
        sys.stderr.write(f"toolgate: {message}\n")
        sys.stderr.flush()


class AuditWriter:
    """Writes decision rows for the proxy without letting a write failure decide.

    Design D10, stated as a rule: **an audit write failure never changes the
    decision.** A blocked call stays blocked and an allowed call is still
    forwarded, because the security property is the block, not the row, and
    refusing allowed traffic over a locked or full disk would turn a disk
    problem into an outage that looks like a policy bug.

    What a failure does instead: it is reported (stderr, which the host keeps
    as the server log) and counted. A success resets the count. After
    `max_consecutive_failures` failures in a row the next one raises
    `AuditFailure`, which ends the session as an internal error (`wrap` exits
    3), so a broken log stops the proxy loudly before a long unaudited run.
    The cost, accepted in D10: up to nine calls in a failure burst have no row.

    Callers append *after* acting on the decision, so the raise can only ever
    stop the proxy, never undo or alter a decision already made.

    Reports name the error, never the record: a row can carry a tool name or
    a note that has no business in a log line about disk trouble.
    """

    def __init__(
        self,
        log: _Appendable,
        *,
        max_consecutive_failures: int = 10,
        report: Callable[[str], None] = _report_to_stderr,
    ) -> None:
        if max_consecutive_failures < 1:
            raise ValueError("max_consecutive_failures must be at least 1")
        self.log = log
        self.max_consecutive_failures = max_consecutive_failures
        self.consecutive_failures = 0
        self._report = report

    def append(self, record: DecisionRecord) -> bool:
        """Write one row. True on success; False after a reported failure."""
        try:
            self.log.append(record)
        except (sqlite3.Error, OSError) as exc:
            self.consecutive_failures += 1
            self._report(
                f"audit write failed ({type(exc).__name__}: {exc}); "
                f"{self.consecutive_failures} consecutive failure(s)"
            )
            if self.consecutive_failures >= self.max_consecutive_failures:
                raise AuditFailure(
                    f"audit log failed {self.consecutive_failures} consecutive times; stopping"
                ) from exc
            return False
        self.consecutive_failures = 0
        return True
