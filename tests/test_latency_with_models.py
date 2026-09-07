"""Sanity check that `time_calls` reports plausible latency for a real detector (M9).

Not a benchmark in itself -- `scripts/benchmark_latency.py` is the
reproducible script for the real numbers in `docs/LATENCY-BENCHMARK.md`, and
like `scripts/benchmark_rules.py` it has no dedicated test. This confirms the
timing wrapper composes correctly with a real (not synthetic) detector.
"""

from __future__ import annotations

import pytest

from llmshield_mcp.config import load_models_config
from llmshield_mcp.detectors.v0_lexical import V0LexicalDetector
from llmshield_mcp.latency import time_calls

pytestmark = pytest.mark.models

TEXTS = [f"probe text number {i} for latency timing" for i in range(15)]


def test_time_calls_reports_plausible_latency_for_a_real_detector() -> None:
    detector = V0LexicalDetector(load_models_config().v0)

    stats = time_calls(lambda text: detector.score(text), TEXTS, n_warm=10)

    assert stats.n == 5
    # V0 is the cheap lexical path (docs/LATENCY-BENCHMARK.md: ~2ms mean on
    # real corpus text); generous bounds here guard against a completely
    # broken timer (e.g. measuring in the wrong unit) without being a
    # brittle re-assertion of the documented benchmark numbers.
    assert 0.0 < stats.mean_ms < 500.0
    assert stats.p95_ms >= stats.mean_ms * 0.5
