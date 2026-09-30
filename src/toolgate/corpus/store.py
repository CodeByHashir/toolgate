"""The payload corpus store (FR-10, AC-6, M6).

SQLite schema per `PROPOSAL.md` section 12's `PayloadCorpusItem`. Unlike
`gating/audit.py`'s `DecisionLog` -- which deliberately never stores raw tool
content -- this store's whole purpose is to hold the corpus text: the corpus
itself is a project deliverable (AC-6/AC-7 want it published), not an audit
trail of something that happened to pass through the gate.

Contaminated items are kept, flagged via `decontamination_status`, not
deleted: the milestone's own verification bar is a *drop-count report*, which
needs the dropped items still visible to report on. Evaluation code (M7+)
is expected to filter to `decontamination_status == "clean"`.

The SQLite file itself is gitignored (`*.sqlite`, repo-wide), matching every
other store in this project. `export_jsonl()` produces the actual publishable
snapshot, mirroring `chains/baseline.json`'s role for the recorded chain.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path


class CorpusLabel(StrEnum):
    BENIGN = "benign"
    ADVERSARIAL = "adversarial"


class DecontaminationStatus(StrEnum):
    #: Checked against the reference corpus and found clean.
    CLEAN = "clean"
    #: Checked and flagged as a near-duplicate (or exact match) of training data.
    CONTAMINATED = "contaminated"
    #: Never run through decontamination -- distinct from CLEAN so a corpus
    #: cannot look decontaminated by construction (an empty check would
    #: otherwise be indistinguishable from a clean one).
    UNCHECKED = "unchecked"


SCHEMA = """
CREATE TABLE IF NOT EXISTS payload_corpus_item (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    source               TEXT    NOT NULL,
    threat_type          TEXT,
    label                TEXT    NOT NULL,
    text                 TEXT    NOT NULL,
    decontamination_status TEXT  NOT NULL,
    minhash_signature    TEXT,
    added_at             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corpus_label ON payload_corpus_item (label);
CREATE INDEX IF NOT EXISTS idx_corpus_source ON payload_corpus_item (source);
CREATE INDEX IF NOT EXISTS idx_corpus_status ON payload_corpus_item (decontamination_status);
"""


@dataclass(frozen=True, slots=True)
class PayloadCorpusItem:
    source: str
    label: CorpusLabel
    text: str
    threat_type: str | None = None
    decontamination_status: DecontaminationStatus = DecontaminationStatus.UNCHECKED
    #: MinHash hash values, kept for provenance and for a future item-vs-item
    #: (not just item-vs-training-corpus) duplicate check across ingest runs.
    minhash_signature: tuple[int, ...] | None = None
    added_at: str = ""
    id: int | None = None

    def with_added_at(self) -> PayloadCorpusItem:
        if self.added_at:
            return self
        return replace(self, added_at=datetime.now(UTC).isoformat())


class CorpusStore:
    """Append-mostly SQLite store for the payload corpus."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.executescript(SCHEMA)
        self._connection.commit()

    def add(self, item: PayloadCorpusItem) -> int:
        stamped = item.with_added_at()
        cursor = self._connection.execute(
            """
            INSERT INTO payload_corpus_item (
                source, threat_type, label, text, decontamination_status,
                minhash_signature, added_at
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (
                stamped.source,
                stamped.threat_type,
                str(stamped.label),
                stamped.text,
                str(stamped.decontamination_status),
                json.dumps(stamped.minhash_signature) if stamped.minhash_signature else None,
                stamped.added_at,
            ),
        )
        self._connection.commit()
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    def add_many(self, items: list[PayloadCorpusItem]) -> list[int]:
        return [self.add(item) for item in items]

    def rows(self) -> list[sqlite3.Row]:
        self._connection.row_factory = sqlite3.Row
        with closing(
            self._connection.execute("SELECT * FROM payload_corpus_item ORDER BY id")
        ) as cursor:
            return cursor.fetchall()

    def count(
        self, *, label: CorpusLabel | None = None, status: DecontaminationStatus | None = None
    ) -> int:
        query = "SELECT COUNT(*) FROM payload_corpus_item WHERE 1=1"
        params: list[str] = []
        if label is not None:
            query += " AND label = ?"
            params.append(str(label))
        if status is not None:
            query += " AND decontamination_status = ?"
            params.append(str(status))
        with closing(self._connection.execute(query, params)) as cursor:
            return int(cursor.fetchone()[0])

    def close(self) -> None:
        self._connection.close()

    def export_jsonl(self, path: Path) -> int:
        """Write every row as one JSON object per line -- the publishable snapshot.

        Field order matches `PROPOSAL.md` section 12's `PayloadCorpusItem` so
        the exported file is a direct, readable rendering of the schema.
        """
        rows = self.rows()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                record = {
                    "id": row["id"],
                    "source": row["source"],
                    "threat_type": row["threat_type"],
                    "label": row["label"],
                    "text": row["text"],
                    "decontamination_status": row["decontamination_status"],
                    "added_at": row["added_at"],
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return len(rows)


@contextmanager
def corpus_store(path: Path) -> Iterator[CorpusStore]:
    store = CorpusStore(path)
    try:
        yield store
    finally:
        store.close()


__all__ = [
    "CorpusLabel",
    "CorpusStore",
    "DecontaminationStatus",
    "PayloadCorpusItem",
    "corpus_store",
]
