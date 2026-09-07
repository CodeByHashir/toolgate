"""Tests for matched-FPR threshold calibration (FR-11, M7)."""

from __future__ import annotations

import pytest

from llmshield_mcp.gauge.calibrate import attack_success_rate, flagged, threshold_at_fpr


def test_achieved_fpr_never_exceeds_the_target() -> None:
    # 100 evenly spaced calibration scores; a 5% budget should flag at most 5.
    scores = [i / 100 for i in range(100)]

    result = threshold_at_fpr(scores, target_fpr=0.05)

    assert result.achieved_fpr <= 0.05
    assert result.achieved_count <= 5


def test_achieved_fpr_matches_a_hand_worked_example() -> None:
    # 10 scores 0..9; 10% budget -> k=1 -> threshold just above the single
    # highest score (9) -> nothing clears it -> achieved FPR is 0, not 10%.
    # This is the documented "ties push it below, never above" behaviour.
    scores = list(range(10))

    result = threshold_at_fpr(scores, target_fpr=0.1)

    assert result.achieved_count == 0
    assert result.achieved_fpr == 0.0
    assert result.threshold > 9


def test_larger_budget_produces_a_lower_or_equal_threshold() -> None:
    scores = [i / 100 for i in range(100)]

    strict = threshold_at_fpr(scores, target_fpr=0.01)
    lenient = threshold_at_fpr(scores, target_fpr=0.10)

    assert lenient.threshold <= strict.threshold


def test_constant_scores_are_flagged_unreachable() -> None:
    # A detector that scores identically on every calibration item (e.g. the
    # frozen INJ-* family, which scores 0.0 on every real payload per M3b)
    # cannot be meaningfully calibrated.
    result = threshold_at_fpr([0.0] * 50, target_fpr=0.05)

    assert result.unreachable


def test_target_fpr_outside_unit_interval_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        threshold_at_fpr([0.1, 0.2], target_fpr=1.5)


def test_empty_scores_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        threshold_at_fpr([], target_fpr=0.05)


def test_flagged_uses_greater_than_or_equal() -> None:
    assert flagged([0.4, 0.5, 0.6], threshold=0.5) == [False, True, True]


def test_attack_success_rate_counts_scores_below_threshold_as_successes() -> None:
    successes, total = attack_success_rate([0.1, 0.4, 0.6, 0.9], threshold=0.5)

    assert successes == 2  # 0.1 and 0.4 slipped under the threshold
    assert total == 4
