"""Ingesting into a non-empty corpus store must fail, not silently double it.

`CorpusStore.add` is a plain INSERT with no uniqueness constraint, so running
`toolgate corpus-ingest` twice against the same file appends rather than
replaces. This is quietly destructive to evidence rather than loudly broken:
the drop-count report simply prints a larger "clean" total, which reads like a
bigger corpus instead of a duplicated one, and every downstream statistic --
AUROC, ASR, achieved FPR -- is then computed over doubled data.

It happened. A second ingest during the licensing cleanup took the store from
11,238 items to 23,139 and nothing said so.

The guard runs before `fetch()`, so these tests need no network and no weights.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.cli import ingest_corpus
from llmshield_mcp.corpus import CorpusLabel, PayloadCorpusItem, corpus_store


def _seed(db: Path, n: int = 3) -> None:
    with corpus_store(db) as store:
        for i in range(n):
            store.add(
                PayloadCorpusItem(
                    source="synthetic",
                    label=CorpusLabel.BENIGN,
                    text=f"a benign line number {i} long enough to be realistic",
                )
            )


def test_ingest_into_a_populated_store_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "payload_corpus.sqlite"
    _seed(db)

    assert ingest_corpus(db, None, None) == 1


def test_refusal_names_the_count_and_both_ways_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "payload_corpus.sqlite"
    _seed(db, n=7)

    ingest_corpus(db, None, None)

    err = capsys.readouterr().err
    assert "already holds 7 items" in err
    assert "Delete it to rebuild" in err
    assert "--append" in err


def test_refusal_happens_before_any_network_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise the check would cost a download before deciding to stop.

    Patched on `llmshield_mcp.corpus`, not `...corpus.sources`: `ingest_corpus`
    does `from llmshield_mcp.corpus import fetch`, so the package namespace is
    the one it actually resolves. Patching `sources` looks right and does
    nothing.
    """
    import llmshield_mcp.corpus as corpus_pkg

    def _explode() -> None:  # pragma: no cover - must never run
        raise AssertionError("fetch() was called despite a populated store")

    monkeypatch.setattr(corpus_pkg, "fetch", _explode)
    db = tmp_path / "payload_corpus.sqlite"
    _seed(db)

    assert ingest_corpus(db, None, None) == 1


class _Stop(RuntimeError):
    """Sentinel raised in place of the real network fetch."""


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ingest stop deterministically at the first fetch.

    Without this the two tests below would depend on whether the machine
    running them happens to have network access and a decontamination corpus
    configured -- and on a machine that has both, they would silently perform a
    full multi-minute ingest. The assertion is about the guard NOT firing, so
    everything after it just needs to stop predictably.
    """
    import llmshield_mcp.corpus as corpus_pkg

    def _stop() -> None:
        raise _Stop("network disabled for this test")

    monkeypatch.setattr(corpus_pkg, "fetch", _stop)


def test_an_empty_store_file_does_not_trigger_the_guard(tmp_path: Path, no_network: None) -> None:
    """A store created but never populated is not a corpus worth protecting.

    This is the "I ran it once and it crashed" case; refusing there would just
    force a confusing manual delete.
    """
    db = tmp_path / "payload_corpus.sqlite"
    with corpus_store(db) as store:
        assert store.count() == 0

    with pytest.raises(_Stop):
        ingest_corpus(db, None, None)


def test_missing_store_does_not_trigger_the_guard(tmp_path: Path, no_network: None) -> None:
    db = tmp_path / "does_not_exist.sqlite"

    with pytest.raises(_Stop):
        ingest_corpus(db, None, None)


def test_append_flag_bypasses_the_guard(tmp_path: Path, no_network: None) -> None:
    """--append is the documented escape hatch, so it must actually work."""
    db = tmp_path / "payload_corpus.sqlite"
    _seed(db)

    with pytest.raises(_Stop):
        ingest_corpus(db, None, None, True, True)
