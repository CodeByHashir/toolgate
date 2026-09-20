"""Dilution benchmark primitives (M12 companion).

Context dilution is the dominant failure mode documented in
`docs/M0-OBSERVATIONS.md §1`: a payload scoring P(injection)=0.998 in
isolation drops to 0.052 when surrounded by ×5 benign filler -- within a
**single** 512-token window, nothing truncated.  This module provides the
text-construction and scoring primitives that turn that single observation
into a systematic, reproducible benchmark.

What 'dilution ratio' means here
---------------------------------
Given a payload P and a block of benign filler words F, the dilution ratio r
is the fraction of *filler* words in the combined text:

    r = |F| / (|F| + |P|)           (word count, not character count)

So r=0.0 means the payload alone; r=0.9 means 90% filler, 10% payload.

Filler is tiled from a single benign paragraph so the text length scales
predictably with the requested ratio.  The ratio is approximate rather than
exact because word-count arithmetic doesn't hit round numbers, and rounding to
the nearest word is more honest than padding with NUL bytes.

Filler neutrality requirement
------------------------------
Filler text MUST score 0.0 on all detectors before use.  The reason is
experimentally necessary: if the filler itself triggers a rule, a rule-based
detector may fire on the combined text at a particular dilution ratio purely
because the tiled filler produced a cross-word match with the rule pattern,
not because the adversarial payload is more detectable.  Use
``load_neutral_filler()`` to construct verified-neutral filler rather than
taking arbitrary lines from ``corpus.sources.load_benign()``, which includes
files such as ``CLAUDE.md`` that contain system-prompt vocabulary.

What this module deliberately does NOT do
------------------------------------------
- No random generation.  Every call to `build_diluted_text` is deterministic
  given the same arguments so the benchmark is reproducible without a seed.
- No ML.  Rules and PII only; the documented V3 dilution collapse (0.998→0.052
  from M0) was already measured.
- No new detector logic.  Detectors are used exactly as-is; we are measuring
  what happens to their existing scores, not changing them.
- No policy changes.  No editing of config/policy.yaml.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence

from llmshield_mcp.detectors.base import Detector, DetectorResult
from llmshield_mcp.detectors.normalise import scan_normalised


# ---------------------------------------------------------------------------
# Text construction
# ---------------------------------------------------------------------------


def build_diluted_text(
    payload: str,
    filler: str,
    ratio: float,
    position: str = "middle",
) -> str:
    """Embed `payload` in `filler` text at the given dilution `ratio`.

    Parameters
    ----------
    payload:
        The adversarial text to embed.
    filler:
        Benign carrier text.  Tiled as needed to reach the target ratio.
    ratio:
        Fraction of filler *words* in the combined text.  0.0 = payload
        alone; 1.0 would be all filler (not permitted as it produces no
        payload signal at all; raises ValueError).
    position:
        Where the payload sits within the filler block:
        - "start"  → payload, then all filler
        - "middle" → half filler, payload, half filler
        - "end"    → all filler, then payload
        - "isolated" → payload alone regardless of ratio (ratio is ignored)

    Returns
    -------
    str
        The combined text as a single whitespace-joined string.
    """
    if position == "isolated":
        return payload.strip()
    if not 0.0 <= ratio < 1.0:
        raise ValueError(f"ratio must be in [0, 1), got {ratio!r}")

    payload_words = payload.strip().split()
    n_payload = len(payload_words)

    if ratio == 0.0:
        return " ".join(payload_words)

    # Compute how many filler words we need:
    #   ratio = n_filler / (n_filler + n_payload)
    #   → n_filler = ratio * n_payload / (1 - ratio)
    n_filler = max(1, round(ratio * n_payload / (1.0 - ratio)))
    filler_words = _tile_words(filler.strip().split(), n_filler)

    half = n_filler // 2
    if position == "start":
        parts = payload_words + filler_words
    elif position == "end":
        parts = filler_words + payload_words
    else:  # middle (default)
        parts = filler_words[:half] + payload_words + filler_words[half:]

    return " ".join(parts)


def _tile_words(word_pool: list[str], n: int) -> list[str]:
    """Repeat `word_pool` as many times as needed to produce exactly `n` words."""
    if not word_pool:
        return []
    result: list[str] = []
    while len(result) < n:
        result.extend(word_pool)
    return result[:n]


# ---------------------------------------------------------------------------
# Verified-neutral filler construction
# ---------------------------------------------------------------------------


def load_neutral_filler(
    detectors: "dict[str, Detector]",
    min_words: int = 60,
) -> str:
    """Build a filler paragraph from repository prose that scores 0.0 on all detectors.

    Benign filler used in dilution experiments MUST score zero on all detectors
    before use.  Without this check, the filler itself can trigger a rule (e.g.
    ``CLAUDE.md`` contains ``provide ... your answer``-style command text that
    causes MCP-002 to fire on a filler+payload cross-word combination at certain
    dilution ratios, falsely inflating recall).

    This function collects lines from Python source docstrings / comments (which
    are factual descriptions, not imperatives), screens each line through every
    detector in `detectors`, and concatenates only those that score 0.0 on all.

    Parameters
    ----------
    detectors:
        The detector dict to screen against.  Typically the same
        ``build_light_detectors()`` dict used by the benchmark.
    min_words:
        Minimum word count for the returned filler paragraph.

    Raises
    ------
    ValueError
        If fewer than `min_words` words of neutral content can be found.
    """
    from pathlib import Path
    try:
        from llmshield_mcp.config import REPO_ROOT
    except ImportError:
        raise ImportError("load_neutral_filler requires the llmshield_mcp package")

    # Candidate lines: Python source docstring / comment prose.
    # Exclude lines with code characters or import/def/class keywords that are
    # not prose and would look odd in a filler paragraph.
    candidate_lines: list[str] = []
    for path in sorted(REPO_ROOT.glob("src/**/*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for ln in text.splitlines():
            ln = ln.strip()
            if (
                len(ln) >= 40
                and not ln.startswith(("from ", "import ", "def ", "class ", "@", "#"))
                and not any(c in ln for c in "()=<>[]{}|")
            ):
                candidate_lines.append(ln)

    # Screen: only keep lines that score 0.0 on all provided detectors.
    neutral_lines: list[str] = []
    for ln in candidate_lines:
        if all(
            (det.score(ln).score or 0.0) == 0.0
            for det in detectors.values()
        ):
            neutral_lines.append(ln)
        if len(" ".join(neutral_lines).split()) >= min_words * 2:
            break  # Enough to tile from; stop early for speed

    filler = " ".join(neutral_lines)
    if len(filler.split()) < min_words:
        raise ValueError(
            f"load_neutral_filler: only found {len(filler.split())} neutral words, "
            f"need >= {min_words}."
        )
    return filler



def actual_dilution_ratio(text: str, payload: str) -> float:
    """Measure the actual filler fraction in `text` given the original `payload`.

    The payload may not appear verbatim in multi-position texts (it always
    does here, but this helper works for any text/payload pair).  We estimate
    the payload word count from the payload string directly.
    """
    total = len(text.split())
    payload_words = len(payload.strip().split())
    if total == 0:
        return 0.0
    filler_words = max(0, total - payload_words)
    return filler_words / total


# ---------------------------------------------------------------------------
# Single-call dilution result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DilutionResult:
    """Detector score for one payload × dilution × position combination."""

    payload_id: str
    """Opaque identifier for the payload (e.g. source + index)."""

    detector: str
    """Detector name (rules_mcp, rules_inj, pii, ...)."""

    ratio: float
    """Requested dilution ratio (filler fraction)."""

    actual_ratio: float
    """Achieved dilution ratio, computed from word counts."""

    position: str
    """Payload position within the filler block."""

    n_filler_words: int
    """Number of filler words in the combined text."""

    n_payload_words: int
    """Number of payload words."""

    n_total_words: int
    """Total words in the combined text."""

    score: float | None
    """Raw detector score, or None if the detector failed."""

    latency_ms: float
    """Time taken for this single detection call."""

    @property
    def flagged(self) -> bool:
        """True when the detector returned a non-zero score.

        Binary threshold at 0.0 is honest for rules/PII: they are binary
        detectors (1.0 = pattern present, 0.0 = pattern absent). Any
        positive score means the detector fired.
        """
        return self.score is not None and self.score > 0.0


# ---------------------------------------------------------------------------
# Scoring helper
# ---------------------------------------------------------------------------


def score_diluted(
    detector: Detector,
    detector_name: str,
    payload: str,
    payload_id: str,
    filler: str,
    ratio: float,
    position: str,
) -> DilutionResult:
    """Build the diluted text and score it, returning a DilutionResult."""
    text = build_diluted_text(payload, filler, ratio, position)
    payload_words = len(payload.strip().split())
    total_words = len(text.split())
    n_filler = max(0, total_words - payload_words)

    t0 = time.perf_counter()
    result: DetectorResult = scan_normalised(detector, text)
    latency_ms = (time.perf_counter() - t0) * 1000.0

    return DilutionResult(
        payload_id=payload_id,
        detector=detector_name,
        ratio=ratio,
        actual_ratio=actual_dilution_ratio(text, payload),
        position=position,
        n_filler_words=n_filler,
        n_payload_words=payload_words,
        n_total_words=total_words,
        score=result.score,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Sequence-level experiment
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SequenceCall:
    """One call in a synthetic session sequence."""

    kind: str
    """'benign' or 'adversarial'."""

    text: str
    """The exact text presented to the detector."""

    payload_id: str | None
    """Set for adversarial calls; None for benign calls."""

    ratio: float
    """Dilution ratio (0.0 for isolated, >0 for diluted, irrelevant for benign)."""

    position: str
    """Payload position within filler (irrelevant for benign calls)."""


def build_dilution_sequence(
    payloads: Sequence[tuple[str, str]],  # (payload_id, payload_text)
    filler: str,
    ratios: Sequence[float],
    positions: Sequence[str],
    n_benign_calls: int,
    benign_texts: Sequence[str],
) -> list[SequenceCall]:
    """Build a synthetic multi-call session for session-accumulator testing.

    The returned sequence interleaves benign calls with adversarial calls at
    the given dilution levels.  Intended for feeding into a SessionAccumulator
    to check what session-level signals the repeated/diluted payload triggers.

    Structure of the returned sequence
    -----------------------------------
    For each payload in `payloads`, for each (ratio, position) pair:
      - `n_benign_calls // 2` benign calls (drawn round-robin from `benign_texts`)
      - 1 adversarial call at (ratio, position)
      - `n_benign_calls // 2` more benign calls

    This ensures adversarial calls are surrounded by benign ones, which
    is the realistic scenario (a poisoned tool result in a normal session).
    """
    calls: list[SequenceCall] = []
    benign_pool = list(benign_texts)
    benign_idx = 0

    def next_benign() -> SequenceCall:
        nonlocal benign_idx
        text = benign_pool[benign_idx % len(benign_pool)]
        benign_idx += 1
        return SequenceCall(kind="benign", text=text, payload_id=None, ratio=0.0, position="n/a")

    half = n_benign_calls // 2
    for pid, ptext in payloads:
        for ratio in ratios:
            for pos in positions:
                diluted = build_diluted_text(ptext, filler, ratio, pos)
                # Benign calls before
                for _ in range(half):
                    calls.append(next_benign())
                # Adversarial call
                calls.append(
                    SequenceCall(
                        kind="adversarial",
                        text=diluted,
                        payload_id=pid,
                        ratio=ratio,
                        position=pos,
                    )
                )
                # Benign calls after
                for _ in range(n_benign_calls - half):
                    calls.append(next_benign())

    return calls


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------


def recall_at_ratio(
    results: list[DilutionResult], ratio: float, detector: str
) -> tuple[int, int]:
    """Return (detected, total) for the given dilution ratio and detector."""
    matching = [r for r in results if r.detector == detector and abs(r.ratio - ratio) < 1e-9]
    detected = sum(1 for r in matching if r.flagged)
    return detected, len(matching)


def mean_score_at_ratio(results: list[DilutionResult], ratio: float, detector: str) -> float | None:
    """Mean score at a given dilution level, or None if no data."""
    scores = [
        r.score
        for r in results
        if r.detector == detector and abs(r.ratio - ratio) < 1e-9 and r.score is not None
    ]
    if not scores:
        return None
    return sum(scores) / len(scores)


__all__ = [
    "DilutionResult",
    "SequenceCall",
    "actual_dilution_ratio",
    "build_diluted_text",
    "build_dilution_sequence",
    "load_neutral_filler",
    "mean_score_at_ratio",
    "recall_at_ratio",
    "score_diluted",
]
