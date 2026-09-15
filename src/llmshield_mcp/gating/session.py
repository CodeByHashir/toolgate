"""Session-level observation accumulator (M12: cross-call correlation).

This module is **observation only**.  It never produces a Decision, never
blocks a tool result, and never escalates.  Every gating decision on any
individual result is made by `PolicyEngine` against that result alone and is
unchanged by this module.

What this module adds
---------------------
A `SessionAccumulator` observes completed `DecisionRecord`s as they are
written, maintains bounded session state, and:

1. Detects **hash recurrence** (the same sha256 seen twice in one session).
   The theoretically significant case is when the *same payload* reappears
   with diverging detector scores — the dilution probe described in
   `docs/M0-OBSERVATIONS.md` section 1 (P(injection)=0.998 in isolation →
   0.052 at 5× dilution, same 512-token window, nothing truncated).
   A single-call gate cannot see this.  The accumulator can, using only the
   hashes the gate already computes.

2. Tracks **detector score drift** across calls.  A monotonically rising
   injection signal across a session is observable from `detector_scores`
   entries already written to the log.  Context is appended as a ``note``
   on the triggering call row.

3. Writes a **session summary row** when ``finish()`` is called.  This turns
   25 individual rows into a single reviewer-facing narrative:
   "25 calls, 2 non-ALLOW decisions, 3 hash recurrences, score rising on v0."

Threat model for hash recurrence
---------------------------------
Legitimate recurrence is common: the M9 benchmark chain includes three
example.com / example.org / example.net fetches that all return the same
"Example Domain" page, giving the same sha256 on calls 0, 1, and 2.  Hash
recurrence is therefore a note, never an alert by itself.  The *additional*
signal is score divergence: if the same content scored 0.8 on call 3 and 0.05
on call 12, that divergence is the meaningful observation.

What is deliberately NOT in this module
----------------------------------------
- No content storage — only sha256 hashes (already computed by `content.py`)
- No new Decision values (ALLOW / REDACT / BLOCK / ESCALATE are unchanged)
- No ML, no cross-session state, no content lineage
- No blocking or escalating based on sequence patterns
- No PII stored (sha256 of content is not reversible to content; server/tool
  names are not PII)

State bounds (NFR-5)
--------------------
``call_sequence`` is capped at ``MAX_SEQUENCE`` entries (100).  ``score_history``
stores the last ``SCORE_WINDOW`` values per detector (20).  Everything else is
a counter or a small dict keyed by tool/server name.  None of these grow
without bound: a session with 10,000 calls stays under a fixed memory ceiling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from llmshield_mcp.gating.audit import Decision, DecisionRecord, Outcome

# ---------------------------------------------------------------------------
# Bounds — all enforced; none can be overridden at runtime to avoid unbounded
# growth (NFR-5).
# ---------------------------------------------------------------------------

#: Maximum entries in ``call_sequence``.  Older entries are dropped.
MAX_SEQUENCE: int = 100

#: Rolling window depth for per-detector score history.
SCORE_WINDOW: int = 20

#: Minimum number of score samples before a trend is declared.  Two points
#: define any line; three provide a signal worth reporting.
TREND_MIN_SAMPLES: int = 3

#: Minimum score change across the window to declare a trend.
#: Prevents flagging sub-noise oscillation as "rising".
TREND_MIN_DELTA: float = 0.15


# ---------------------------------------------------------------------------
# Per-call observation emitted by observe()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CallObservation:
    """What the accumulator noticed about a single completed call.

    All fields are informational.  None trigger a decision.
    """

    call_index: int
    """Zero-based position of this call in the session."""

    hash_recurrence: bool
    """True when this call's sha256 has been seen before in this session."""

    first_seen_at: int | None
    """Call index where this hash was first seen, or None if not recurrent."""

    score_trends: dict[str, str]
    """For each detector with a trend, 'rising' or 'falling'.  Empty when no
    trend is detectable yet."""

    score_divergence: dict[str, float]
    """For recurrent hashes: the gap between the previous score and this score
    for each detector.  Negative means the score dropped (possible dilution).
    Only populated when hash_recurrence is True and both scores are not None."""

    def is_notable(self) -> bool:
        """True when any signal is worth including in a note."""
        return (
            (self.hash_recurrence and bool(self.score_divergence))
            or bool(self.score_trends)
        )

    def to_note(self) -> str | None:
        """Return a compact note string, or None when nothing notable."""
        if not self.is_notable():
            return None
        parts: list[str] = []
        if self.hash_recurrence and self.score_divergence:
            parts.append(
                f"session:hash_recurrence(first_at={self.first_seen_at},"
                + ",".join(
                    f"{k}:{v:+.3f}" for k, v in sorted(self.score_divergence.items())
                )
                + ")"
            )
        for det, direction in sorted(self.score_trends.items()):
            parts.append(f"session:score_{direction}({det})")
        return "; ".join(parts) if parts else None


# ---------------------------------------------------------------------------
# Session summary (written once at finish())
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SessionSummary:
    """High-level narrative of the completed session.

    Written as a single ``session_summary`` row in the decision log by
    ``SessionAccumulator.finish()``.  A reviewer can read this one row instead
    of scanning all individual call rows.
    """

    total_calls: int
    distinct_tools: int
    distinct_servers: int
    non_allow_calls: int
    """Calls where ``fused_decision`` was not ALLOW."""

    hash_recurrence_count: int
    """Total number of calls where the sha256 had been seen before."""

    hash_divergence_count: int
    """Subset of recurrences where at least one detector score diverged."""

    score_trend_detectors: list[str]
    """Detectors for which a rising or falling trend was observed."""

    def to_note(self) -> str:
        return json.dumps(
            {
                "total_calls": self.total_calls,
                "distinct_tools": self.distinct_tools,
                "distinct_servers": self.distinct_servers,
                "non_allow_calls": self.non_allow_calls,
                "hash_recurrence_count": self.hash_recurrence_count,
                "hash_divergence_count": self.hash_divergence_count,
                "score_trend_detectors": self.score_trend_detectors,
            },
            sort_keys=True,
        )


# ---------------------------------------------------------------------------
# The accumulator
# ---------------------------------------------------------------------------


class SessionAccumulator:
    """Bounded in-memory accumulator for one session's gating observations.

    Create one instance per session and pass it to every Gate serving that
    session alongside the shared DecisionLog.  Call ``observe(record)`` after
    each record is written to the log; call ``finish(log)`` when the session
    ends to write the summary row.

    Thread safety: not required — the reference agent is single-threaded and
    the Gate is called synchronously in the async receive path.

    No I/O on the hot path: ``observe()`` is pure in-memory dict lookups and
    list appends.  The only I/O is ``finish()``, which writes one row.
    """

    def __init__(self) -> None:
        self._call_count: int = 0

        # Bounded sequence of (server, tool, correlation_id) tuples.
        # Capped at MAX_SEQUENCE; oldest entries are dropped.
        self._call_sequence: list[tuple[str, str, str]] = []

        # Per-detector rolling score window, bounded at SCORE_WINDOW.
        self._score_history: dict[str, list[float]] = {}

        # Counters (never bounded — they are scalars, not lists).
        self._server_counts: dict[str, int] = {}
        self._tool_counts: dict[str, int] = {}
        self._non_allow: int = 0

        # Hash tracking: sha256 → list of call indices where it appeared.
        # Bounded because sha256 is a fixed-length string and each entry is
        # one int — even 10,000 unique hashes is trivial memory.
        self._hash_seen: dict[str, list[int]] = {}

        # Previous scores for each hash, for divergence computation.
        # sha256 → {detector: last_score}
        self._hash_prev_scores: dict[str, dict[str, float]] = {}

        # Cumulative stats for the summary.
        self._hash_recurrence_count: int = 0
        self._hash_divergence_count: int = 0
        self._trend_detectors_seen: set[str] = set()

        self._finished: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def call_count(self) -> int:
        return self._call_count

    def observe(self, record: DecisionRecord) -> CallObservation:
        """Observe one completed DecisionRecord and return a CallObservation.

        The caller (Gate) may append ``observation.to_note()`` to the record's
        ``note`` field before writing it to the log, or may ignore the
        observation entirely.  The accumulator does not write to the log.

        Must not be called after ``finish()``.
        """
        if self._finished:
            raise RuntimeError("observe() called after finish()")

        call_index = self._call_count
        self._call_count += 1

        server = record.mcp_server_id
        tool = record.tool_name or "unknown"
        cid = record.correlation_id

        # --- sequence (bounded) ------------------------------------------
        if len(self._call_sequence) >= MAX_SEQUENCE:
            self._call_sequence.pop(0)
        self._call_sequence.append((server, tool, cid))

        # --- counters -------------------------------------------------------
        self._server_counts[server] = self._server_counts.get(server, 0) + 1
        self._tool_counts[tool] = self._tool_counts.get(tool, 0) + 1
        if record.fused_decision is not Decision.ALLOW:
            self._non_allow += 1

        # --- score history (bounded per detector) ---------------------------
        scores: dict[str, Any] = record.detector_scores or {}
        for det, raw in scores.items():
            score = _to_float(raw)
            if score is None:
                continue
            window = self._score_history.setdefault(det, [])
            if len(window) >= SCORE_WINDOW:
                window.pop(0)
            window.append(score)

        # --- hash tracking --------------------------------------------------
        sha = record.raw_result_hash
        hash_recurrence = sha in self._hash_seen
        first_seen_at: int | None = None
        score_divergence: dict[str, float] = {}

        if hash_recurrence:
            self._hash_recurrence_count += 1
            first_seen_at = self._hash_seen[sha][0]
            prev = self._hash_prev_scores.get(sha, {})
            for det, raw in scores.items():
                s = _to_float(raw)
                if s is None:
                    continue
                p = prev.get(det)
                if p is not None:
                    delta = s - p
                    # Only report meaningful divergence.
                    if abs(delta) >= 0.05:
                        score_divergence[det] = round(delta, 4)
            if score_divergence:
                self._hash_divergence_count += 1

        # Update tracking regardless of recurrence.
        self._hash_seen.setdefault(sha, []).append(call_index)
        current_float_scores = {
            det: v
            for det, raw in scores.items()
            if (v := _to_float(raw)) is not None
        }
        self._hash_prev_scores[sha] = current_float_scores

        # --- score trends ---------------------------------------------------
        score_trends: dict[str, str] = {}
        for det, window in self._score_history.items():
            if len(window) < TREND_MIN_SAMPLES:
                continue
            direction = _detect_trend(window)
            if direction:
                score_trends[det] = direction
                self._trend_detectors_seen.add(det)

        return CallObservation(
            call_index=call_index,
            hash_recurrence=hash_recurrence,
            first_seen_at=first_seen_at,
            score_trends=score_trends,
            score_divergence=score_divergence,
        )

    def finish(self, log: Any) -> SessionSummary:
        """Write a session summary row to `log` and return the summary.

        `log` must have an `append(DecisionRecord)` method (i.e. a
        `DecisionLog`).  Calling ``finish`` twice raises RuntimeError.
        """
        if self._finished:
            raise RuntimeError("finish() called twice on the same SessionAccumulator")
        self._finished = True

        summary = SessionSummary(
            total_calls=self._call_count,
            distinct_tools=len(self._tool_counts),
            distinct_servers=len(self._server_counts),
            non_allow_calls=self._non_allow,
            hash_recurrence_count=self._hash_recurrence_count,
            hash_divergence_count=self._hash_divergence_count,
            score_trend_detectors=sorted(self._trend_detectors_seen),
        )

        # The summary row reuses the DecisionRecord schema.  Fields that carry
        # per-call semantics are set to sentinel values that do not look like
        # real decisions (correlation_id is empty, hash is all-zeros, latency
        # is 0.0, decision is ALLOW since no blocking occurred at session level).
        log.append(
            DecisionRecord(
                correlation_id="",
                mcp_server_id="__session__",
                tool_name=None,
                raw_result_hash="0" * 64,
                fused_decision=Decision.ALLOW,
                latency_ms=0.0,
                outcome=Outcome.SESSION_SUMMARY,
                note=summary.to_note(),
            )
        )
        return summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_float(value: Any) -> float | None:
    """Coerce a detector score to float, or return None if not numeric."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f


def _detect_trend(window: list[float]) -> str | None:
    """Return 'rising', 'falling', or None for a bounded score window.

    A trend is declared only when:
    - There are at least TREND_MIN_SAMPLES values.
    - The last value minus the first value exceeds TREND_MIN_DELTA in magnitude.
    - The direction is consistent (more than half the consecutive pairs move
      in the same direction).

    This is deliberately conservative: a spike followed by normal scores should
    not register as "rising".
    """
    n = len(window)
    if n < TREND_MIN_SAMPLES:
        return None

    delta = window[-1] - window[0]
    if abs(delta) < TREND_MIN_DELTA:
        return None

    # Count consecutive pairs moving in the claimed direction.
    claimed = "rising" if delta > 0 else "falling"
    moves_in_direction = sum(
        1 for i in range(n - 1) if (window[i + 1] - window[i]) * delta > 0
    )
    # Require at least half the consecutive pairs to agree.
    if moves_in_direction < (n - 1) / 2:
        return None

    return claimed


__all__ = [
    "CallObservation",
    "MAX_SEQUENCE",
    "SCORE_WINDOW",
    "TREND_MIN_DELTA",
    "TREND_MIN_SAMPLES",
    "SessionAccumulator",
    "SessionSummary",
]
