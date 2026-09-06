"""Statistics for the GAUGE protocol (FR-11, NFR-7).

Wilson and Clopper-Pearson intervals and the McNemar test come from
`statsmodels` -- not ported from the dissertation. `evaluation/metrics.py`
and `evaluation/experiment2/exp2_eval.py` both hand-roll these (the latter's
`wilson`/`cp` are simple closed-form/`scipy.stats.beta` snippets, not
"established library implementations"). `PROPOSAL.md` section 9 asks for
established implementations for exactly this reason, and `statsmodels` is
already a pinned dependency with nothing else using it yet.

DeLong AUROC is the one exception: there is no ready `statsmodels`/`scipy`
implementation of it, and `evaluation/experiment2/exp2_auroc_delong.py`'s
pure-Python midrank version is correct (confirmed by reading it, not
assumed -- `plan.md` section 3's Reuse Inventory already flagged it as "the
one already implemented correctly"). Ported near-verbatim; only renamed for
this project's style and typed.
"""

from __future__ import annotations

import statistics
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from statsmodels.stats.contingency_tables import mcnemar as _mcnemar
from statsmodels.stats.proportion import proportion_confint


@dataclass(frozen=True, slots=True)
class Interval:
    point: float
    low: float
    high: float


def wilson_ci(count: int, nobs: int, alpha: float = 0.05) -> Interval:
    """Wilson score interval for a proportion `count / nobs`."""
    if nobs == 0:
        return Interval(point=float("nan"), low=float("nan"), high=float("nan"))
    low, high = proportion_confint(count, nobs, alpha=alpha, method="wilson")
    return Interval(point=count / nobs, low=float(low), high=float(high))


def clopper_pearson_ci(count: int, nobs: int, alpha: float = 0.05) -> Interval:
    """Clopper-Pearson (exact) interval for a proportion `count / nobs`."""
    if nobs == 0:
        return Interval(point=float("nan"), low=float("nan"), high=float("nan"))
    low, high = proportion_confint(count, nobs, alpha=alpha, method="beta")
    return Interval(point=count / nobs, low=float(low), high=float(high))


@dataclass(frozen=True, slots=True)
class McNemarResult:
    #: Discordant pairs: detector A right / B wrong, and the reverse.
    a_only_correct: int
    b_only_correct: int
    p_value: float


def mcnemar_test(a_correct: Sequence[bool], b_correct: Sequence[bool]) -> McNemarResult:
    """Paired comparison of two detectors' correctness on the SAME items.

    `a_correct[i]`/`b_correct[i]` must refer to the same item -- this is a
    paired test, not a comparison of two independent samples.
    """
    if len(a_correct) != len(b_correct):
        raise ValueError("a_correct and b_correct must be the same length (paired items)")

    a = np.asarray(a_correct, dtype=bool)
    b = np.asarray(b_correct, dtype=bool)
    a_only = int(np.sum(a & ~b))
    b_only = int(np.sum(~a & b))
    table = np.array([[0, a_only], [b_only, 0]])
    # exact=True uses the binomial test, appropriate for the small discordant
    # counts this project's corpus sizes ("low hundreds") will produce.
    result = _mcnemar(table, exact=True)
    return McNemarResult(a_only_correct=a_only, b_only_correct=b_only, p_value=float(result.pvalue))


def _midrank(values: Sequence[float]) -> list[float]:
    """Midranks, with ties averaged. Shared machinery for `auroc_delong`."""
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and values[order[j]] == values[order[i]]:
            j += 1
        rank = 0.5 * (i + j - 1) + 1
        for k in range(i, j):
            ranks[order[k]] = rank
        i = j
    return ranks


@dataclass(frozen=True, slots=True)
class DelongResult:
    auc: float
    variance: float
    ci_low: float
    ci_high: float


def auroc_delong(positive: Sequence[float], negative: Sequence[float]) -> DelongResult:
    """AUROC with a DeLong (1988) variance estimate and normal 95% CI.

    Ported from `evaluation/experiment2/exp2_auroc_delong.py`'s `auroc_delong`
    (the fast midrank formulation), which is the one hand-rolled statistic in
    the reference repository confirmed correct rather than replaced with a
    library call -- there is no ready DeLong implementation in
    statsmodels/scipy.
    """
    m, n = len(positive), len(negative)
    if m == 0 or n == 0:
        raise ValueError("auroc_delong requires at least one positive and one negative score")

    combined_ranks = _midrank(list(positive) + list(negative))
    positive_ranks = _midrank(list(positive))
    negative_ranks = _midrank(list(negative))

    auc = sum(combined_ranks[:m]) / m / n - (m + 1) / (2.0 * n)
    v01 = [(combined_ranks[i] - positive_ranks[i]) / n for i in range(m)]
    v10 = [1.0 - (combined_ranks[m + i] - negative_ranks[i]) / m for i in range(n)]
    variance = (statistics.variance(v01) / m if m > 1 else 0.0) + (
        statistics.variance(v10) / n if n > 1 else 0.0
    )
    se = variance**0.5
    low = max(0.0, auc - 1.96 * se)
    high = min(1.0, auc + 1.96 * se)
    return DelongResult(auc=auc, variance=variance, ci_low=low, ci_high=high)


__all__ = [
    "DelongResult",
    "Interval",
    "McNemarResult",
    "auroc_delong",
    "clopper_pearson_ci",
    "mcnemar_test",
    "wilson_ci",
]
