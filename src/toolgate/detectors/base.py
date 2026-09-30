"""Common contract for every detector adapter.

Each detector (rules, PII, V0, V3) is an interchangeable adapter behind one
interface, so ablation studies are a config change rather than a code change
(PROPOSAL section 9).

The base class owns two things that must never be left to an individual
adapter to remember:

  * timing, so latency is measured identically everywhere (FR-13); and
  * failure containment, so a detector that raises produces a *result marked
    failed* rather than an exception that escapes into the gating path.

Fail-closed (SEC-6) is deliberately NOT decided here. A detector's job is to
report "I have no opinion, and here is why"; translating that into Block or
Escalate is the policy engine's job. Keeping that split means the fail-closed
policy is configurable and testable in one place.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class Span:
    """A half-open character range `[start, end)` in the scanned text.

    Spans are what makes Redact (FR-5) possible: they let the policy engine
    mask only the offending region and preserve the rest of the tool result.
    """

    start: int
    end: int
    label: str

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span [{self.start}, {self.end})")


@dataclass(frozen=True, slots=True)
class RawScore:
    """What a concrete adapter returns from `_score`."""

    score: float
    detail: dict[str, float] = field(default_factory=dict)
    spans: tuple[Span, ...] = ()
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class DetectorResult:
    """One detector's verdict on one piece of text.

    `score` is None if and only if `error` is set. A sentinel None is used
    rather than NaN or 0.0 so that a failed detector cannot be silently
    averaged into a fusion score as if it were a confident "benign" vote --
    the type system forces every consumer to handle the failure case.
    """

    detector: str
    score: float | None
    detail: dict[str, float]
    spans: tuple[Span, ...]
    latency_ms: float
    truncated: bool
    error: str | None

    def __post_init__(self) -> None:
        if (self.score is None) != (self.error is not None):
            raise ValueError("score is None if and only if error is set")
        if self.score is not None and not 0.0 <= self.score <= 1.0:
            raise ValueError(f"score {self.score} outside [0, 1]")

    @property
    def failed(self) -> bool:
        return self.error is not None


class Detector(ABC):
    """Base adapter. Subclasses implement `_score` and nothing else."""

    name: ClassVar[str]

    @abstractmethod
    def _score(self, text: str) -> RawScore:
        """Score `text`, higher meaning more likely to be an injection.

        May raise; the base class contains the failure.
        """

    def score(self, text: str) -> DetectorResult:
        start = time.perf_counter()
        try:
            raw = self._score(text)
        except Exception as exc:  # noqa: BLE001 -- containment is the point
            return DetectorResult(
                detector=self.name,
                score=None,
                detail={},
                spans=(),
                latency_ms=(time.perf_counter() - start) * 1000.0,
                truncated=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        return DetectorResult(
            detector=self.name,
            score=raw.score,
            detail=raw.detail,
            spans=raw.spans,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            truncated=raw.truncated,
            error=None,
        )
