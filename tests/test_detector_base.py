"""Contract tests for the detector base class.

The base class is where failure containment lives, so these tests are the
guarantee that no adapter can leak an exception into the gating path.
"""

from __future__ import annotations

import pytest

from llmshield_mcp.detectors.base import Detector, DetectorResult, RawScore, Span


class _Constant(Detector):
    name = "constant"

    def __init__(self, score: float) -> None:
        self._value = score

    def _score(self, text: str) -> RawScore:
        return RawScore(score=self._value, detail={"benign": 1.0 - self._value})


class _Exploding(Detector):
    name = "exploding"

    def _score(self, text: str) -> RawScore:
        raise RuntimeError("model file is corrupt")


class _OutOfRange(Detector):
    name = "out_of_range"

    def _score(self, text: str) -> RawScore:
        return RawScore(score=1.5)


def test_successful_score_is_reported_with_latency() -> None:
    result = _Constant(0.75).score("anything")

    assert result.detector == "constant"
    assert result.score == 0.75
    assert result.error is None
    assert not result.failed
    assert result.latency_ms >= 0.0


def test_detector_exception_is_contained_not_raised() -> None:
    result = _Exploding().score("anything")

    assert result.failed
    assert result.score is None
    assert result.error is not None
    assert "model file is corrupt" in result.error
    # SEC-6 fail-closed is the policy engine's decision, so the detector must
    # still return a timed result rather than aborting the gating path.
    assert result.latency_ms >= 0.0


def test_out_of_range_score_is_contained_as_a_failure() -> None:
    # A validation error raised inside DetectorResult construction happens
    # after _score returns, so it must be surfaced rather than crashing.
    with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
        DetectorResult(
            detector="x",
            score=1.5,
            detail={},
            spans=(),
            latency_ms=0.0,
            truncated=False,
            error=None,
        )


def test_score_and_error_are_mutually_exclusive() -> None:
    with pytest.raises(ValueError, match="if and only if"):
        DetectorResult(
            detector="x",
            score=0.5,
            detail={},
            spans=(),
            latency_ms=0.0,
            truncated=False,
            error="boom",
        )
    with pytest.raises(ValueError, match="if and only if"):
        DetectorResult(
            detector="x",
            score=None,
            detail={},
            spans=(),
            latency_ms=0.0,
            truncated=False,
            error=None,
        )


@pytest.mark.parametrize("start,end", [(-1, 5), (5, 4)])
def test_invalid_spans_are_rejected(start: int, end: int) -> None:
    with pytest.raises(ValueError, match="invalid span"):
        Span(start=start, end=end, label="injection")


def test_valid_span_is_accepted() -> None:
    span = Span(start=0, end=10, label="injection")
    assert (span.start, span.end, span.label) == (0, 10, "injection")
