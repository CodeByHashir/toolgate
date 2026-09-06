"""Known-answer tests for GAUGE statistics (FR-11, NFR-7, M7 verification bar).

Wilson, Clopper-Pearson and McNemar are thin `statsmodels` wrappers -- the
"known answer" is what the pinned `statsmodels`/`scipy` version itself
produces for a textbook input, confirmed once here and pinned so a version
bump that silently changes behaviour is caught. DeLong has no library
implementation to defer to, so its point estimate is cross-checked against
`sklearn.metrics.roc_auc_score` -- an independent, well-tested library -- and
its CI behaviour is checked structurally (contains the point estimate,
collapses correctly under perfect separation).
"""

from __future__ import annotations

import random

import pytest
from sklearn.metrics import roc_auc_score

from llmshield_mcp.gauge.stats import (
    auroc_delong,
    clopper_pearson_ci,
    mcnemar_test,
    wilson_ci,
)


def test_wilson_ci_matches_statsmodels_for_a_known_proportion() -> None:
    interval = wilson_ci(5, 20)

    assert interval.point == pytest.approx(0.25)
    assert interval.low == pytest.approx(0.11186170140766563)
    assert interval.high == pytest.approx(0.4687008776187441)


def test_clopper_pearson_ci_matches_statsmodels_for_a_known_proportion() -> None:
    interval = clopper_pearson_ci(5, 20)

    assert interval.point == pytest.approx(0.25)
    assert interval.low == pytest.approx(0.08657146910143462)
    assert interval.high == pytest.approx(0.4910458717079575)


def test_clopper_pearson_is_wider_than_wilson() -> None:
    # Exact intervals are conservative relative to the (asymptotic) Wilson
    # interval -- a standard property, not specific to this project.
    wilson = wilson_ci(5, 20)
    cp = clopper_pearson_ci(5, 20)

    assert cp.low <= wilson.low
    assert cp.high >= wilson.high


def test_wilson_ci_handles_zero_observations() -> None:
    interval = wilson_ci(0, 0)

    assert interval.point != interval.point  # nan


def test_mcnemar_matches_the_exact_binomial_test() -> None:
    # 1 pair where only A is right, 3 where only B is right (n=4 discordant,
    # min(1,3)=1) -- scipy.stats.binomtest(1, 4, 0.5) gives 0.625, confirmed
    # directly against the pinned scipy version.
    a_correct = [True, False, False, False, True, True]
    b_correct = [False, True, True, True, True, True]

    result = mcnemar_test(a_correct, b_correct)

    assert result.a_only_correct == 1
    assert result.b_only_correct == 3
    assert result.p_value == pytest.approx(0.625)


def test_mcnemar_with_unequal_discordant_counts() -> None:
    # Discordant only at indices 2-3 (a=False, b=True -> b_only=2); no index
    # has a=True, b=False, so a_only=0. scipy.stats.binomtest(0, 2, 0.5) = 0.5.
    a_correct = [True, True, False, False, False, False, False, False, False, False]
    b_correct = [True, True, True, True, False, False, False, False, False, False]

    result = mcnemar_test(a_correct, b_correct)

    assert result.a_only_correct == 0
    assert result.b_only_correct == 2
    assert result.p_value == pytest.approx(0.5)


def test_mcnemar_requires_paired_equal_length_inputs() -> None:
    with pytest.raises(ValueError, match="same length"):
        mcnemar_test([True, False], [True])


# --- DeLong AUROC ------------------------------------------------------------


def test_auroc_delong_matches_sklearn_point_estimate() -> None:
    rng = random.Random(0)
    positive = [rng.random() for _ in range(30)]
    negative = [rng.random() for _ in range(40)]

    result = auroc_delong(positive, negative)

    labels = [1] * len(positive) + [0] * len(negative)
    expected = roc_auc_score(labels, positive + negative)
    assert result.auc == pytest.approx(expected, abs=1e-9)


def test_auroc_delong_perfect_separation_is_one_with_a_tight_upper_bound() -> None:
    positive = [0.9, 0.95, 0.99]
    negative = [0.1, 0.2, 0.3]

    result = auroc_delong(positive, negative)

    assert result.auc == pytest.approx(1.0)
    assert result.ci_high == pytest.approx(1.0)
    assert result.ci_low <= result.auc


def test_auroc_delong_ci_always_contains_the_point_estimate() -> None:
    rng = random.Random(1)
    positive = [rng.random() for _ in range(25)]
    negative = [rng.random() for _ in range(25)]

    result = auroc_delong(positive, negative)

    assert result.ci_low <= result.auc <= result.ci_high


def test_auroc_delong_rejects_an_empty_class() -> None:
    with pytest.raises(ValueError, match="at least one"):
        auroc_delong([], [0.1, 0.2])
