"""Latency measurement primitives (FR-13, FR-14, NFR-1, NFR-2).

Mean + p95 in milliseconds, with a warmup pass excluded before timing starts
-- this is `evaluation/experiment2/exp2_eval.py`'s own `latency_hf`/
`latency_sklearn` convention (`n_warm=10`), reused here rather than invented,
so this project's latency numbers are measured the same way the dissertation
measured its own.

This module is the reusable, testable timing logic; `scripts/benchmark_latency.py`
is the thin script that points it at the real detectors and corpus, mirroring
the `corpus/sources.py` / `scripts/benchmark_rules.py` split.
"""

from __future__ import annotations

import statistics
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class LatencyStats:
    mean_ms: float
    p95_ms: float
    n: int

    def __post_init__(self) -> None:
        if self.n < 1:
            raise ValueError(f"LatencyStats needs at least one sample, got n={self.n}")


def summarize(durations_ms: Sequence[float]) -> LatencyStats:
    if not durations_ms:
        raise ValueError("summarize requires at least one duration")
    return LatencyStats(
        mean_ms=statistics.mean(durations_ms),
        # Percentile method matches numpy's default (linear interpolation),
        # which is what exp2_eval.py's own `np.percentile(lat, 95)` used.
        p95_ms=_percentile(sorted(durations_ms), 95),
        n=len(durations_ms),
    )


def _percentile(sorted_values: Sequence[float], pct: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100) * (len(sorted_values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = rank - lower
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * fraction


def time_calls(fn: Callable[[T], object], items: Sequence[T], *, n_warm: int = 10) -> LatencyStats:
    """Call `fn` once per item, timing every call after the first `n_warm`.

    The warmup calls still run (so any one-time cost -- JIT, cache fill,
    lazy import inside `fn` -- happens before timing starts) but are not
    counted, matching the dissertation's `latency_hf`/`latency_sklearn`.
    """
    if len(items) <= n_warm:
        raise ValueError(
            f"time_calls needs more than n_warm={n_warm} items to leave any timed calls, "
            f"got {len(items)}"
        )
    durations: list[float] = []
    for index, item in enumerate(items):
        started = time.perf_counter()
        fn(item)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if index >= n_warm:
            durations.append(elapsed_ms)
    return summarize(durations)


__all__ = ["LatencyStats", "summarize", "time_calls"]
