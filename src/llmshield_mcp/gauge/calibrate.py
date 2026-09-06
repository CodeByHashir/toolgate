"""Matched-FPR threshold calibration (FR-11).

Convention ported from `evaluation/experiment2/exp2_multi_fpr.py` (which
reuses `exp2_eval.thr_at_fpr`/`asr` rather than reimplementing them, per its
own docstring): a score is "flagged" when it is `>= threshold`, and the
threshold sits just above the `(1 - target)`-quantile of the CALIBRATION
benign scores, so the achieved FPR is always `<= target` -- ties push it
below, never above. `run.py` reports the *achieved* FPR (with a Wilson CI),
never the requested target, "so nothing is faked" (that file's own words).

Constant-scored detectors (a rule family that scores 0 on every item, for
instance) cannot be meaningfully calibrated: any threshold either blocks
everything or nothing, and reporting an "achieved FPR" for that would look
like a real number while proving nothing. `unreachable=True` on
`CalibrationResult` flags this instead of a silently misleading threshold.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

#: Pushes the threshold just past the calibration quantile so ties are
#: excluded rather than included -- the reason achieved FPR is <= target,
#: never >, per exp2_multi_fpr.py's convention.
EPS = 1e-9


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    threshold: float
    target_fpr: float
    achieved_fpr: float
    achieved_count: int
    calibration_n: int
    #: True when the calibration scores had no variance (e.g. a detector that
    #: scores identically on every item) -- no threshold in this regime is
    #: meaningful, so `threshold`/`achieved_fpr` should not be read as real
    #: calibration, only as "nothing to calibrate against".
    unreachable: bool


def threshold_at_fpr(scores: Sequence[float], target_fpr: float) -> CalibrationResult:
    """Calibrate a threshold against `scores` (the calibration benign set)."""
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError(f"target_fpr must be in [0, 1], got {target_fpr}")
    n = len(scores)
    if n == 0:
        raise ValueError("threshold_at_fpr requires at least one calibration score")

    unreachable = len(set(scores)) <= 1
    ordered = sorted(scores)
    k = math.floor(target_fpr * n)
    threshold = (ordered[-1] if k == 0 else ordered[n - k]) + EPS
    achieved_count = sum(1 for s in scores if s >= threshold)

    return CalibrationResult(
        threshold=threshold,
        target_fpr=target_fpr,
        achieved_fpr=achieved_count / n,
        achieved_count=achieved_count,
        calibration_n=n,
        unreachable=unreachable,
    )


def flagged(scores: Sequence[float], threshold: float) -> list[bool]:
    return [score >= threshold for score in scores]


def attack_success_rate(scores: Sequence[float], threshold: float) -> tuple[int, int]:
    """Return `(successes, total)`. A success is an attack the threshold MISSED."""
    successes = sum(1 for score in scores if score < threshold)
    return successes, len(scores)


__all__ = ["CalibrationResult", "attack_success_rate", "flagged", "threshold_at_fpr"]
