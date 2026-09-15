"""Benchmark SessionAccumulator overhead (M12).

Measures the per-call cost of observe() and the cost of finish() with a
summary write, using the same timing convention as the rest of the project
(latency.py: warmup excluded, mean + p95 in milliseconds).

The accumulator runs synchronously on the Gate's hot path.  The budget is
informal: it should be negligible relative to rules/PII overhead (< 1ms mean)
and entirely negligible relative to V3 (< 0.1ms mean).

Run:
    uv run python scripts/benchmark_session.py
"""

from __future__ import annotations

import hashlib
import statistics
import sys
import time
from pathlib import Path

# Make sure the project package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llmshield_mcp.gating.audit import Decision, DecisionLog, DecisionRecord
from llmshield_mcp.gating.session import SessionAccumulator


# ---------------------------------------------------------------------------
# Synthetic data
# ---------------------------------------------------------------------------

N_WARM = 10
N_TIMED = 200


def _make_records(n: int) -> list[DecisionRecord]:
    """Build n DecisionRecords with varied content (distinct hashes)."""
    records = []
    for i in range(n):
        # Every 5th call returns the same content as call 0 (hash recurrence).
        text = f"content-{i % 5}"
        sha = hashlib.sha256(text.encode()).hexdigest()
        records.append(
            DecisionRecord(
                correlation_id=f"cid-{i}",
                mcp_server_id="filesystem" if i % 3 != 0 else "fetch",
                tool_name="read_text_file" if i % 3 != 0 else "fetch",
                raw_result_hash=sha,
                fused_decision=Decision.ALLOW if i % 10 != 0 else Decision.ESCALATE,
                latency_ms=2.5,
                detector_scores={"rules_mcp": 0.0, "rules_inj": 0.0, "pii": 0.0, "v0": i * 0.001},
            )
        )
    return records


# ---------------------------------------------------------------------------
# Benchmark 1: per-call observe() overhead
# ---------------------------------------------------------------------------


def bench_observe(records: list[DecisionRecord]) -> tuple[float, float]:
    """Return (mean_ms, p95_ms) for a single observe() call after warmup."""
    acc = SessionAccumulator()
    durations: list[float] = []

    for i, rec in enumerate(records):
        t0 = time.perf_counter()
        acc.observe(rec)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if i >= N_WARM:
            durations.append(elapsed_ms)

    mean_ms = statistics.mean(durations)
    sorted_d = sorted(durations)
    n = len(sorted_d)
    rank = 0.95 * (n - 1)
    lo, hi = int(rank), min(int(rank) + 1, n - 1)
    p95_ms = sorted_d[lo] + (sorted_d[hi] - sorted_d[lo]) * (rank - lo)
    return mean_ms, p95_ms


# ---------------------------------------------------------------------------
# Benchmark 2: finish() cost (one SQLite write)
# ---------------------------------------------------------------------------


def bench_finish(tmp_dir: Path, n_calls: int = 25) -> tuple[float, float]:
    """Return (mean_ms, p95_ms) for a finish() call after n_calls observe()."""
    records = _make_records(n_calls)
    durations: list[float] = []
    iterations = N_TIMED

    for trial in range(N_WARM + iterations):
        log = DecisionLog(tmp_dir / f"bench_{trial}.sqlite")
        acc = SessionAccumulator()
        for rec in records:
            acc.observe(rec)

        t0 = time.perf_counter()
        acc.finish(log)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        log.close()

        if trial >= N_WARM:
            durations.append(elapsed_ms)

    mean_ms = statistics.mean(durations)
    sorted_d = sorted(durations)
    n = len(sorted_d)
    rank = 0.95 * (n - 1)
    lo, hi = int(rank), min(int(rank) + 1, n - 1)
    p95_ms = sorted_d[lo] + (sorted_d[hi] - sorted_d[lo]) * (rank - lo)
    return mean_ms, p95_ms


# ---------------------------------------------------------------------------
# Benchmark 3: full M9-scale session (25 calls + finish)
# ---------------------------------------------------------------------------


def bench_full_session(tmp_dir: Path) -> tuple[float, float]:
    """Return (mean_ms, p95_ms) for a complete 25-call session."""
    records = _make_records(25)
    durations: list[float] = []

    for trial in range(N_WARM + N_TIMED):
        log = DecisionLog(tmp_dir / f"session_{trial}.sqlite")
        t0 = time.perf_counter()
        acc = SessionAccumulator()
        for rec in records:
            acc.observe(rec)
        acc.finish(log)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        log.close()

        if trial >= N_WARM:
            durations.append(elapsed_ms)

    mean_ms = statistics.mean(durations)
    sorted_d = sorted(durations)
    n = len(sorted_d)
    rank = 0.95 * (n - 1)
    lo, hi = int(rank), min(int(rank) + 1, n - 1)
    p95_ms = sorted_d[lo] + (sorted_d[hi] - sorted_d[lo]) * (rank - lo)
    return mean_ms, p95_ms


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    import tempfile

    print("M12 SessionAccumulator overhead benchmark")
    print(f"Warmup: {N_WARM} runs excluded from timing.  Timed: {N_TIMED} runs.")
    print(f"Timing convention: latency.py (time.perf_counter, mean + p95 ms).")
    print()

    records = _make_records(N_WARM + N_TIMED)

    print("1. per-call observe() overhead")
    mean_obs, p95_obs = bench_observe(records)
    print(f"   mean: {mean_obs:.4f} ms    p95: {p95_obs:.4f} ms")
    print(f"   vs rules/PII budget (~0.1 ms): {'OK' if mean_obs < 0.1 else 'OVER'}")
    print()

    with tempfile.TemporaryDirectory() as tmpd:
        tmp = Path(tmpd)

        print("2. finish() cost (SQLite write of one summary row, after 25 observe() calls)")
        mean_fin, p95_fin = bench_finish(tmp, n_calls=25)
        print(f"   mean: {mean_fin:.4f} ms    p95: {p95_fin:.4f} ms")
        print()

        print("3. Full 25-call session (25 × observe() + finish()) — M9 scale")
        mean_full, p95_full = bench_full_session(tmp)
        print(f"   mean: {mean_full:.4f} ms    p95: {p95_full:.4f} ms")
        print(f"   Per-call share: {mean_full / 25:.5f} ms/call")
        print()

    print("Reference: per-call detector overhead (from LATENCY-BENCHMARK.md):")
    print("   rules_mcp: 0.06 ms mean  |  pii: 0.07 ms mean  |  v0: 2.07 ms mean")
    print("   v3: 208 ms mean (real web pages)")
    print()
    print(
        "Verdict: accumulator overhead is expected to be < 0.01 ms/call "
        "(pure dict lookup + list append, no I/O on hot path)."
    )


if __name__ == "__main__":
    main()
