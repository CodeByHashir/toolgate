"""Tests for the corpus source loaders that don't need the network (M6).

`fetch()`/`load_adversarial()` need BIPIA/InjecAgent cached under
`corpus/external/` (fetched by `scripts/benchmark_rules.py` or `toolgate
corpus-ingest`), so they are exercised by actually running those, not by a
network-dependent unit test here -- matching how this project has never unit
tested `agent.run_agent`'s real network path either.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.corpus import sources as sources_module
from llmshield_mcp.corpus.sources import (
    SOURCES,
    CorpusIntegrityError,
    digest,
    load_benign,
    verify_cache,
)


class TestSourcePinning:
    def test_every_source_is_pinned_to_a_commit_not_a_branch(self) -> None:
        """A branch ref would let upstream change what a published figure measured."""
        for name, source in SOURCES.items():
            assert len(source.commit) == 40, f"{name}: {source.commit!r} is not a full commit SHA"
            assert all(c in "0123456789abcdef" for c in source.commit), name
            assert source.commit not in {"main", "master", "HEAD"}, name

    def test_every_source_records_a_sha256(self) -> None:
        for name, source in SOURCES.items():
            assert len(source.sha256) == 64, name
            assert all(c in "0123456789abcdef" for c in source.sha256), name

    def test_url_embeds_the_pinned_commit(self) -> None:
        source = SOURCES["bipia_text.json"]
        assert source.commit in source.url
        assert "/main/" not in source.url
        assert source.url.startswith("https://")


class TestVerifyCache:
    def test_absent_cache_verifies_vacuously(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sources_module, "CACHE", tmp_path)

        assert verify_cache() == {}

    def test_matching_file_is_reported_as_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sources_module, "CACHE", tmp_path)
        payload = b'{"category": ["payload"]}'
        name = "bipia_text.json"
        (tmp_path / name).write_bytes(payload)
        monkeypatch.setitem(
            sources_module.SOURCES,
            name,
            sources_module.Source(
                repo=SOURCES[name].repo,
                commit=SOURCES[name].commit,
                path=SOURCES[name].path,
                sha256=digest(payload),
            ),
        )

        assert verify_cache()[name] == digest(payload)

    def test_tampered_file_raises_rather_than_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A silently-modified corpus would make every figure unfalsifiable."""
        monkeypatch.setattr(sources_module, "CACHE", tmp_path)
        (tmp_path / "bipia_text.json").write_bytes(b"not the pinned content")

        with pytest.raises(CorpusIntegrityError, match="does not match its recorded digest"):
            verify_cache()

    def test_mismatch_message_names_both_digests_and_the_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sources_module, "CACHE", tmp_path)
        (tmp_path / "injecagent_dh.jsonl").write_bytes(b"tampered")

        with pytest.raises(CorpusIntegrityError) as excinfo:
            verify_cache()

        message = str(excinfo.value)
        assert SOURCES["injecagent_dh.jsonl"].sha256 in message
        assert digest(b"tampered") in message
        assert SOURCES["injecagent_dh.jsonl"].url in message


def test_load_benign_returns_real_repository_lines() -> None:
    lines = load_benign()

    assert len(lines) > 100
    assert all(len(line) >= 20 for line in lines)


def test_load_benign_picks_up_known_trigger_word_content() -> None:
    # sandbox/src/config_loader.py deliberately contains "ignore all previous"
    # in genuinely benign code (M1); confirms the glob actually reaches it.
    lines = load_benign()

    assert any("ignore all previous" in line.lower() for line in lines)
