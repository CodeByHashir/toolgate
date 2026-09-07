"""Tests for latency measurement primitives (FR-13, FR-14, M9)."""

from __future__ import annotations

import time

import pytest

from llmshield_mcp.latency import LatencyStats, summarize, time_calls


def test_summarize_computes_mean_and_p95() -> None:
    stats = summarize([10.0, 20.0, 30.0, 40.0, 50.0])

    assert stats.mean_ms == pytest.approx(30.0)
    assert stats.n == 5
    # p95 of [10..50] via linear-interpolation percentile (numpy's default,
    # matching exp2_eval.py's np.percentile(lat, 95)): rank = 0.95*4 = 3.8
    # -> between index 3 (40) and 4 (50), 80% of the way -> 48.0.
    assert stats.p95_ms == pytest.approx(48.0)


def test_summarize_single_value() -> None:
    stats = summarize([42.0])

    assert stats.mean_ms == 42.0
    assert stats.p95_ms == 42.0
    assert stats.n == 1


def test_summarize_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="at least one"):
        summarize([])


def test_latency_stats_rejects_non_positive_n() -> None:
    with pytest.raises(ValueError, match="at least one sample"):
        LatencyStats(mean_ms=1.0, p95_ms=1.0, n=0)


def test_time_calls_excludes_the_warmup_calls() -> None:
    calls: list[int] = []

    def record(item: int) -> None:
        calls.append(item)

    stats = time_calls(record, list(range(15)), n_warm=10)

    assert calls == list(range(15))  # every item was actually called
    assert stats.n == 5  # only the post-warmup calls are timed


def test_time_calls_measures_real_elapsed_time() -> None:
    def sleep_a_little(_: int) -> None:
        time.sleep(0.01)

    stats = time_calls(sleep_a_little, list(range(12)), n_warm=10)

    assert stats.mean_ms >= 5.0  # comfortably above zero, well under a full second


def test_time_calls_requires_more_items_than_the_warmup_count() -> None:
    with pytest.raises(ValueError, match="n_warm"):
        time_calls(lambda _: None, [1, 2, 3], n_warm=10)
