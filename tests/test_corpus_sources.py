"""Tests for the corpus source loaders that don't need the network (M6).

`fetch()`/`load_adversarial()` need BIPIA/InjecAgent cached under
`corpus/external/` (fetched by `scripts/benchmark_rules.py` or `mcp-shield
corpus-ingest`), so they are exercised by actually running those, not by a
network-dependent unit test here -- matching how this project has never unit
tested `agent.run_agent`'s real network path either.
"""

from __future__ import annotations

from llmshield_mcp.corpus.sources import load_benign


def test_load_benign_returns_real_repository_lines() -> None:
    lines = load_benign()

    assert len(lines) > 100
    assert all(len(line) >= 20 for line in lines)


def test_load_benign_picks_up_known_trigger_word_content() -> None:
    # sandbox/src/config_loader.py deliberately contains "ignore all previous"
    # in genuinely benign code (M1); confirms the glob actually reaches it.
    lines = load_benign()

    assert any("ignore all previous" in line.lower() for line in lines)
