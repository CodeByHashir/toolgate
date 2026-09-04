"""Reuse audit: the actual LLMShield V0/V3 artifacts load and score on CPU.

Marked `models` and skipped when the artifacts are absent, so CI stays green
without shipping unpublishable weights. Run locally with:

    pytest -m models
"""

from __future__ import annotations

import pytest

from llmshield_mcp.cli import LONG_PROBE, PROBES
from llmshield_mcp.config import DETECTOR_CLASSES, load_models_config

pytestmark = pytest.mark.models

BENIGN = PROBES[0][1]
INJECTION = PROBES[2][1]


@pytest.fixture(scope="module")
def config():  # type: ignore[no-untyped-def]
    return load_models_config()


@pytest.fixture(scope="module")
def v0(config):  # type: ignore[no-untyped-def]
    from llmshield_mcp.detectors import V0LexicalDetector

    if not config.v0.path.exists():
        pytest.skip(f"V0 artifact not present at {config.v0.path}")
    return V0LexicalDetector(config.v0)


@pytest.fixture(scope="module")
def v3(config):  # type: ignore[no-untyped-def]
    from llmshield_mcp.detectors import V3TransformerDetector

    if not config.v3.path.exists():
        pytest.skip(f"V3 artifact not present at {config.v3.path}")
    return V3TransformerDetector(config.v3)


def test_v0_loads_and_scores(v0) -> None:  # type: ignore[no-untyped-def]
    result = v0.score(BENIGN)

    assert not result.failed
    assert set(DETECTOR_CLASSES).issubset(result.detail)
    assert sum(result.detail[c] for c in DETECTOR_CLASSES) == pytest.approx(1.0, abs=1e-6)


def test_v0_separates_benign_from_injection(v0) -> None:  # type: ignore[no-untyped-def]
    assert v0.score(INJECTION).score > v0.score(BENIGN).score


def test_v0_has_no_token_limit(v0) -> None:  # type: ignore[no-untyped-def]
    result = v0.score(LONG_PROBE)
    assert not result.failed
    assert not result.truncated


def test_v3_loads_with_four_classes(v3) -> None:  # type: ignore[no-untyped-def]
    result = v3.score(BENIGN)

    assert not result.failed
    assert sum(result.detail[c] for c in DETECTOR_CLASSES) == pytest.approx(1.0, abs=1e-5)


def test_v3_separates_benign_from_injection(v3) -> None:  # type: ignore[no-untyped-def]
    assert v3.score(INJECTION).score > v3.score(BENIGN).score


def test_v3_truncate_flags_lost_content(config) -> None:  # type: ignore[no-untyped-def]
    import dataclasses

    from llmshield_mcp.detectors import V3TransformerDetector

    if not config.v3.path.exists():
        pytest.skip("V3 artifact not present")

    truncating = V3TransformerDetector(
        dataclasses.replace(config.v3, long_text_strategy="truncate")
    )
    result = truncating.score(LONG_PROBE)

    assert result.truncated, "long probe should exceed the 512-token window"
    assert result.detail["n_windows_scored"] == 1.0
    assert result.detail["n_windows_total"] > 1.0


def test_chunking_never_scores_below_truncation(config) -> None:  # type: ignore[no-untyped-def]
    """chunk_max's first window is exactly the truncate window.

    Taking a maximum over a superset that includes it therefore cannot produce
    a lower score. This is a structural guarantee, not an empirical claim, so
    a regression here means the windowing logic is wrong.
    """
    import dataclasses

    from llmshield_mcp.detectors import V3TransformerDetector

    if not config.v3.path.exists():
        pytest.skip("V3 artifact not present")

    truncated = V3TransformerDetector(
        dataclasses.replace(config.v3, long_text_strategy="truncate")
    ).score(LONG_PROBE)
    chunked = V3TransformerDetector(
        dataclasses.replace(config.v3, long_text_strategy="chunk_max")
    ).score(LONG_PROBE)

    assert chunked.detail["n_windows_scored"] > 1.0
    assert not chunked.truncated
    assert chunked.score >= truncated.score - 1e-9
