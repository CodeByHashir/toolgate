"""Tests for the payload corpus store (FR-10, AC-6, M6)."""

from __future__ import annotations

import json
from pathlib import Path

from llmshield_mcp.corpus.store import (
    CorpusLabel,
    CorpusStore,
    DecontaminationStatus,
    PayloadCorpusItem,
)


def test_add_assigns_an_id_and_a_timestamp(tmp_path: Path) -> None:
    store = CorpusStore(tmp_path / "corpus.sqlite")

    item_id = store.add(PayloadCorpusItem(source="bipia", label=CorpusLabel.ADVERSARIAL, text="x"))

    row = store.rows()[0]
    assert row["id"] == item_id
    assert row["added_at"]
    store.close()


def test_default_decontamination_status_is_unchecked(tmp_path: Path) -> None:
    store = CorpusStore(tmp_path / "corpus.sqlite")

    store.add(PayloadCorpusItem(source="repository", label=CorpusLabel.BENIGN, text="hello"))

    assert store.rows()[0]["decontamination_status"] == DecontaminationStatus.UNCHECKED
    store.close()


def test_count_filters_by_label_and_status(tmp_path: Path) -> None:
    store = CorpusStore(tmp_path / "corpus.sqlite")
    store.add_many(
        [
            PayloadCorpusItem(
                source="bipia",
                label=CorpusLabel.ADVERSARIAL,
                text="a",
                decontamination_status=DecontaminationStatus.CLEAN,
            ),
            PayloadCorpusItem(
                source="bipia",
                label=CorpusLabel.ADVERSARIAL,
                text="b",
                decontamination_status=DecontaminationStatus.CONTAMINATED,
            ),
            PayloadCorpusItem(
                source="repository",
                label=CorpusLabel.BENIGN,
                text="c",
                decontamination_status=DecontaminationStatus.CLEAN,
            ),
        ]
    )

    assert store.count() == 3
    assert store.count(label=CorpusLabel.ADVERSARIAL) == 2
    assert store.count(status=DecontaminationStatus.CLEAN) == 2
    assert store.count(label=CorpusLabel.ADVERSARIAL, status=DecontaminationStatus.CLEAN) == 1
    store.close()


def test_minhash_signature_round_trips_through_json(tmp_path: Path) -> None:
    store = CorpusStore(tmp_path / "corpus.sqlite")

    store.add(
        PayloadCorpusItem(
            source="bipia",
            label=CorpusLabel.ADVERSARIAL,
            text="x",
            minhash_signature=(1, 2, 3),
        )
    )

    row = store.rows()[0]
    assert json.loads(row["minhash_signature"]) == [1, 2, 3]
    store.close()


def test_a_contaminated_item_is_kept_not_deleted(tmp_path: Path) -> None:
    # The store is an audit trail: a drop-count report needs the dropped
    # items still visible, not silently removed.
    store = CorpusStore(tmp_path / "corpus.sqlite")

    store.add(
        PayloadCorpusItem(
            source="bipia",
            label=CorpusLabel.ADVERSARIAL,
            text="contaminated one",
            decontamination_status=DecontaminationStatus.CONTAMINATED,
        )
    )

    assert store.count() == 1
    assert store.count(status=DecontaminationStatus.CONTAMINATED) == 1
    store.close()


def test_export_jsonl_writes_one_object_per_row(tmp_path: Path) -> None:
    store = CorpusStore(tmp_path / "corpus.sqlite")
    store.add_many(
        [
            PayloadCorpusItem(
                source="bipia", threat_type="phishing", label=CorpusLabel.ADVERSARIAL, text="a"
            ),
            PayloadCorpusItem(source="repository", label=CorpusLabel.BENIGN, text="b"),
        ]
    )

    export_path = tmp_path / "export.jsonl"
    written = store.export_jsonl(export_path)

    assert written == 2
    lines = export_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["source"] == "bipia"
    assert first["threat_type"] == "phishing"
    assert first["label"] == "adversarial"
    assert first["text"] == "a"
    store.close()


def test_reopening_the_same_path_preserves_rows(tmp_path: Path) -> None:
    path = tmp_path / "corpus.sqlite"
    store = CorpusStore(path)
    store.add(PayloadCorpusItem(source="bipia", label=CorpusLabel.ADVERSARIAL, text="persisted"))
    store.close()

    reopened = CorpusStore(path)
    assert reopened.count() == 1
    reopened.close()
