"""Dilution benchmark: how injection detection degrades with context dilution (M12).

Measures systematically what `docs/M0-OBSERVATIONS.md §1` observed as a single
data point: a payload scoring P(injection)=0.998 in isolation dropped to 0.052
at 5× dilution within a single window.

This script:

1.  Loads adversarial payloads from the already-cached BIPIA + InjecAgent files
    (no network call if `scripts/benchmark_rules.py` or `corpus-ingest` has run).
2.  Loads benign filler from the repository's own source files (via
    `corpus.sources.load_benign()`).
3.  Scores each payload × dilution level × position with all light detectors
    (rules_mcp, rules_inj, pii) -- no V0/V3 weights needed.
4.  Writes `results/dilution/dilution_results.json` (gitignored, same as
    `results/gauge/`) and prints a human-readable summary table to stdout.

Run:
    uv run python scripts/benchmark_dilution.py

The summary table is what goes into docs/DILUTION-BENCHMARK.md.

Design constraints
------------------
- No random generation: deterministic, reproducible without a seed.
- No ML: the documented V3 dilution collapse (0.998→0.052) is already in M0.
  Rules and PII are binary; their dilution behaviour is whether a *lexical* or
  *regex* pattern survives being surrounded by more text -- which it always will,
  since word-concatenation doesn't mutate the pattern itself. That is a finding
  worth reporting honestly, not a test we hide.
- No new detection logic. Detectors are used as-is; we measure their scores, not
  change them.
- No policy changes.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

# Make sure the project package is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llmshield_mcp.corpus.sources import load_adversarial, load_benign
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector
from llmshield_mcp.dilution import (
    DilutionResult,
    load_neutral_filler,
    mean_score_at_ratio,
    recall_at_ratio,
    score_diluted,
)

OUTPUT_DIR = Path(__file__).parent.parent / "results" / "dilution"

# ---------------------------------------------------------------------------
# Benchmark parameters
# ---------------------------------------------------------------------------

#: Dilution ratios to test.  0.0 = payload alone (isolated baseline).
RATIOS: tuple[float, ...] = (0.0, 0.5, 0.75, 0.9)

#: Positions to test at each non-zero ratio.
POSITIONS: tuple[str, ...] = ("start", "middle", "end")

#: Number of payloads sampled from each adversarial family.
#: Set large enough to include all payloads from both cached families.
#: BIPIA = 125, InjecAgent = 62 -> 187 total.
PAYLOADS_PER_FAMILY: int = 200  # effectively "all"

#: Warmup before latency timing.
N_WARM: int = 5

# ---------------------------------------------------------------------------
# Detector construction
# ---------------------------------------------------------------------------


def build_light_detectors() -> dict[str, object]:
    return {
        "rules_mcp": RuleDetector(families=frozenset({"mcp"})),
        "rules_inj": RuleDetector(families=frozenset({"inj"})),
        "pii": PiiDetector(),
    }


# ---------------------------------------------------------------------------
# Helper: load and sample payloads
# ---------------------------------------------------------------------------


def load_payloads(max_per_family: int) -> list[tuple[str, str, str]]:
    """Return (family, threat_type, payload) tuples, capped per family."""
    try:
        raw = load_adversarial()
    except FileNotFoundError:
        print(
            "WARNING: cached corpus not found.  Run:\n"
            "  uv run python scripts/benchmark_rules.py\n"
            "or:\n"
            "  uv run toolgate corpus-ingest\n"
            "to fetch the adversarial benchmark data first.",
            file=sys.stderr,
        )
        sys.exit(1)

    by_family: dict[str, list[tuple[str, str, str]]] = {}
    for family, threat_type, payload in raw:
        by_family.setdefault(family, []).append((family, threat_type, payload))

    result: list[tuple[str, str, str]] = []
    for family, items in sorted(by_family.items()):
        result.extend(items[:max_per_family])
    return result


# ---------------------------------------------------------------------------
# Main benchmark
# ---------------------------------------------------------------------------


def run_dilution_benchmark(verbose: bool = True) -> dict:
    # --- load data -----------------------------------------------------------
    if verbose:
        print("Loading adversarial payloads...")
    payloads_raw = load_payloads(PAYLOADS_PER_FAMILY)
    n_payloads = len(payloads_raw)
    if verbose:
        print(f"  {n_payloads} payloads from {len({p[0] for p in payloads_raw})} families")

    if verbose:
        print("Loading verified-neutral filler...")
    # IMPORTANT: filler MUST score 0.0 on all detectors before use.
    # load_neutral_filler() screens every candidate line through the detectors.
    # Using unscreened lines (e.g. from load_benign() which includes CLAUDE.md)
    # can cause cross-word rule matches at certain dilution ratios, falsely
    # inflating recall -- see dilution.py module docstring.
    detectors = build_light_detectors()
    filler = load_neutral_filler(detectors)
    if verbose:
        print(f"  filler: {len(filler.split())} verified-neutral words")
    det_names = list(detectors.keys())

    # --- per-call dilution scoring -------------------------------------------
    if verbose:
        print(f"\nScoring {n_payloads} payloads × {len(RATIOS)} ratios × "
              f"{len(POSITIONS)} positions × {len(det_names)} detectors...")

    all_results: list[DilutionResult] = []
    latency_by_detector: dict[str, list[float]] = {name: [] for name in det_names}

    for idx, (family, threat_type, payload) in enumerate(payloads_raw):
        payload_id = f"{family}-{idx}"
        if verbose and idx % 5 == 0:
            print(f"  payload {idx + 1}/{n_payloads}...")

        for det_name, det in detectors.items():
            # Warmup (first N_WARM payloads treated as warmup per detector)
            for ratio in RATIOS:
                positions_to_test = POSITIONS if ratio > 0.0 else ("isolated",)
                for pos in positions_to_test:
                    result = score_diluted(
                        det, det_name, payload, payload_id, filler, ratio=ratio, position=pos
                    )
                    all_results.append(result)
                    if idx >= N_WARM:
                        latency_by_detector[det_name].append(result.latency_ms)

    # --- benign false-positive measurement -----------------------------------
    if verbose:
        print("\nMeasuring false positives on benign sequences...")

    # Use load_benign() directly for FP measurement (distinct from filler source).
    # The benign sample is scored as-is -- no dilution -- to measure raw FPR.
    benign_fp_lines = [ln for ln in load_benign() if len(ln) > 40][:50]
    benign_fp_results: list[DilutionResult] = []
    for i, text in enumerate(benign_fp_lines):
        for det_name, det in detectors.items():
            t0 = time.perf_counter()
            res = scan_normalised(det, text)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            benign_fp_results.append(
                DilutionResult(
                    payload_id=f"benign-{i}",
                    detector=det_name,
                    ratio=0.0,
                    actual_ratio=0.0,
                    position="n/a",
                    n_filler_words=0,
                    n_payload_words=len(text.split()),
                    n_total_words=len(text.split()),
                    score=res.score,
                    latency_ms=latency_ms,
                )
            )

    # --- latency summary -----------------------------------------------------
    latency_stats = {}
    for det_name, lats in latency_by_detector.items():
        if lats:
            latency_stats[det_name] = {
                "mean_ms": statistics.mean(lats),
                "p95_ms": sorted(lats)[int(0.95 * len(lats))],
                "n": len(lats),
            }

    # --- build output --------------------------------------------------------
    report = _build_report(
        all_results=all_results,
        benign_fp_results=benign_fp_results,
        latency_stats=latency_stats,
        payloads_raw=payloads_raw,
        filler=filler,
        n_payloads=n_payloads,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / "dilution_results.json"
    out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    if verbose:
        _print_report(report)
        print(f"\nFull results written to: {out_path}")

    return report


# ---------------------------------------------------------------------------
# Report construction
# ---------------------------------------------------------------------------


def _build_report(
    all_results: list[DilutionResult],
    benign_fp_results: list[DilutionResult],
    latency_stats: dict,
    payloads_raw: list[tuple[str, str, str]],
    filler: str,
    n_payloads: int,
) -> dict:
    det_names = sorted({r.detector for r in all_results})

    # Recall by detector × ratio
    recall_table: dict[str, dict[str, dict]] = {}
    for det in det_names:
        recall_table[det] = {}
        for ratio in RATIOS:
            detected, total = recall_at_ratio(all_results, ratio, det)
            recall_table[det][str(ratio)] = {
                "detected": detected,
                "total": total,
                "recall": detected / total if total > 0 else None,
            }

    # Mean score by detector × ratio
    score_table: dict[str, dict[str, float | None]] = {}
    for det in det_names:
        score_table[det] = {}
        for ratio in RATIOS:
            score_table[det][str(ratio)] = mean_score_at_ratio(all_results, ratio, det)

    # Recall by position (non-zero ratios only)
    position_table: dict[str, dict[str, dict]] = {}
    for det in det_names:
        position_table[det] = {}
        for pos in POSITIONS:
            matching = [
                r for r in all_results
                if r.detector == det and r.position == pos and r.ratio > 0.0
            ]
            flagged = sum(1 for r in matching if r.flagged)
            position_table[det][pos] = {
                "detected": flagged,
                "total": len(matching),
                "recall": flagged / len(matching) if matching else None,
            }

    # Benign false-positive rates
    fp_table: dict[str, dict] = {}
    for det in det_names:
        matching = [r for r in benign_fp_results if r.detector == det]
        flagged = sum(1 for r in matching if r.flagged)
        fp_table[det] = {
            "flagged": flagged,
            "total": len(matching),
            "fpr": flagged / len(matching) if matching else None,
        }

    # Score degradation: isolated vs 90%
    degradation: dict[str, dict] = {}
    for det in det_names:
        baseline = mean_score_at_ratio(all_results, 0.0, det)
        heavy = mean_score_at_ratio(all_results, 0.9, det)
        degradation[det] = {
            "isolated_mean_score": baseline,
            "diluted_90pct_mean_score": heavy,
            "absolute_drop": (
                round(baseline - heavy, 4)
                if baseline is not None and heavy is not None
                else None
            ),
            "relative_drop_pct": (
                round(100.0 * (baseline - heavy) / baseline, 1)
                if baseline is not None and heavy is not None and baseline > 0
                else None
            ),
        }

    return {
        "parameters": {
            "n_payloads": n_payloads,
            "n_benign_fp_items": len({r.payload_id for r in benign_fp_results}),
            "ratios": list(RATIOS),
            "positions": list(POSITIONS),
            "filler_words": len(filler.split()),
            "adversarial_families": sorted({p[0] for p in payloads_raw}),
        },
        "recall_by_ratio": recall_table,
        "mean_score_by_ratio": score_table,
        "recall_by_position": position_table,
        "score_degradation": degradation,
        "benign_false_positives": fp_table,
        "latency_stats": latency_stats,
    }


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------


def _print_report(report: dict) -> None:
    params = report["parameters"]
    print("\n" + "=" * 72)
    print("DILUTION BENCHMARK RESULTS")
    print("=" * 72)
    print(f"Payloads: {params['n_payloads']} from {params['adversarial_families']}")
    print(f"Dilution ratios: {params['ratios']}")
    print(f"Positions: {params['positions']}")
    print(f"Filler size: {params['filler_words']} words")
    print()

    # Recall by ratio
    print("-- Recall by Dilution Level " + "-" * 44)
    print(f"{'Detector':<16}", end="")
    for ratio in params["ratios"]:
        print(f"  ratio={ratio:.2f}", end="")
    print()
    print("-" * 72)
    for det, ratio_data in report["recall_by_ratio"].items():
        print(f"{det:<16}", end="")
        for ratio_s, data in ratio_data.items():
            r = data["recall"]
            cell = f"{r:.1%}" if r is not None else "  N/A "
            print(f"  {cell:>10}", end="")
        print()
    print()

    # Score degradation
    print("-- Score Degradation (Isolated -> 90% Dilution) " + "-" * 24)
    print(f"{'Detector':<16}  {'Isolated':<10}  {'@90% dilution':<15}  {'Drop (abs)':<12}")
    print("-" * 72)
    for det, data in report["score_degradation"].items():
        iso = data["isolated_mean_score"]
        heavy = data["diluted_90pct_mean_score"]
        drop = data["absolute_drop"]
        print(
            f"{det:<16}  "
            f"{iso:.4f}   " if iso is not None else f"{'N/A':<10}   ",
            end="",
        )
        print(
            f"{heavy:.4f}         " if heavy is not None else f"{'N/A':<15}  ",
            end="",
        )
        print(f"{drop:.4f}" if drop is not None else "N/A")
    print()

    # Benign FP
    print("-- False Positives on Benign Sequences " + "-" * 33)
    print(f"{'Detector':<16}  {'FPs':<6}  {'Total':<7}  {'FPR':<8}")
    print("-" * 72)
    for det, data in report["benign_false_positives"].items():
        fpr = data["fpr"]
        print(
            f"{det:<16}  {data['flagged']:<6}  {data['total']:<7}  "
            f"{fpr:.1%}" if fpr is not None else "N/A"
        )
    print()

    # Latency
    print("-- Latency per Call " + "-" * 52)
    print(f"{'Detector':<16}  {'mean ms':<10}  {'p95 ms':<10}  {'n'}")
    print("-" * 72)
    for det, stats in report["latency_stats"].items():
        print(
            f"{det:<16}  {stats['mean_ms']:.4f}     "
            f"{stats['p95_ms']:.4f}     {stats['n']}"
        )
    print("=" * 72)


if __name__ == "__main__":
    run_dilution_benchmark(verbose=True)
