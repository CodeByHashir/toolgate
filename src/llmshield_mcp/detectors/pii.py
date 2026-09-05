"""PII scanner adapter (FR-2, NFR-4, SEC-3).

Ported from the LLMShield dissertation's `PiiScanner`
(`src/llmshield/pre_llm/pii_scanner.py`). Patterns and per-entity confidence
values are carried across verbatim; the surrounding plumbing is reimplemented
behind this project's `Detector` contract for the reasons given in `rules.py`.

The dissertation's own note on why this is regex rather than Presidio is worth
preserving: Presidio 2.2.x depends on spaCy, which depends on the pydantic v1
compatibility shim, which does not work on recent Python. The regex
implementation covers every one of Presidio's *pattern-based* recognisers.
NER-only entities (PERSON, LOCATION, ORG, ...) are not detectable this way and
are skipped rather than silently reported as absent -- a stated limitation, not
an oversight.

**Nothing matched is ever returned as text.** `detail` is numeric by the
contract's type and `Span` carries offsets only, so a PII value cannot reach
the decision log through this detector (SEC-3, NFR-4). `redact()` is provided
for callers that need to mask the original.
"""

from __future__ import annotations

import re
from typing import ClassVar

from llmshield_mcp.detectors.base import Detector, RawScore, Span

#: Entity patterns with the fixed confidence of each, from the dissertation.
#: The values reflect per-pattern precision rather than per-match certainty --
#: a regex match is binary, so the number expresses trust in the pattern:
#:   EMAIL_ADDRESS 0.85, PHONE_NUMBER 0.75, CREDIT_CARD 0.90 (+ Luhn),
#:   US_SSN 0.85, IBAN_CODE 0.80, IP_ADDRESS 0.75.
PATTERNS: dict[str, tuple[re.Pattern[str], float]] = {
    "EMAIL_ADDRESS": (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE),
        0.85,
    ),
    "PHONE_NUMBER": (
        re.compile(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}", re.IGNORECASE),
        0.75,
    ),
    "CREDIT_CARD": (
        re.compile(
            r"\b(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"  # Visa (13 or 16 digits)
            r"|5[1-5][0-9]{14}"  # Mastercard
            r"|3[47][0-9]{13}"  # Amex
            r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"  # Diners Club
            r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
            r"|(?:2131|1800|35\d{3})\d{11}"  # JCB
            r")\b",
            re.IGNORECASE,
        ),
        0.90,
    ),
    "US_SSN": (
        # Excludes 000, 666, 900-999 area codes; 00 group; 0000 serial.
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b"),
        0.85,
    ),
    "IBAN_CODE": (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"),
        0.80,
    ),
    "IP_ADDRESS": (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        0.75,
    ),
}

#: Entities that need a running NER model. Skipped rather than errored, so a
#: policy listing them does not fail; the gap is documented, not hidden.
NER_ONLY_ENTITIES: frozenset[str] = frozenset(
    {"PERSON", "ORG", "ORGANISATION", "LOCATION", "NRP", "DATE_TIME", "GPE"}
)

DEFAULT_ENABLED_ENTITIES: tuple[str, ...] = tuple(PATTERNS)

DEFAULT_CONFIDENCE_THRESHOLD = 0.7

REDACTION_PLACEHOLDER = "[REDACTED:{label}]"


def luhn_valid(number: str) -> bool:
    """Luhn checksum, used to cut false positives on long digit runs."""
    digits = [int(c) for c in number if c.isdigit()]
    if not digits:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact(text: str, spans: tuple[Span, ...]) -> str:
    """Mask every span, preserving everything else (FR-5, SEC-3).

    Spans are applied right to left so earlier offsets stay valid, and
    overlapping spans are collapsed rather than producing nested placeholders.
    """
    if not spans:
        return text

    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[Span] = []
    for span in ordered:
        if merged and span.start < merged[-1].end:
            previous = merged[-1]
            if span.end > previous.end:
                merged[-1] = Span(
                    start=previous.start,
                    end=span.end,
                    label=previous.label if previous.label == span.label else "OVERLAP",
                )
            continue
        merged.append(span)

    out = text
    for span in reversed(merged):
        out = out[: span.start] + REDACTION_PLACEHOLDER.format(label=span.label) + out[span.end :]
    return out


class PiiDetector(Detector):
    """Regex PII detector over the dissertation's pattern set."""

    name: ClassVar[str] = "pii"

    def __init__(
        self,
        enabled_entities: tuple[str, ...] = DEFAULT_ENABLED_ENTITIES,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError(f"confidence_threshold {confidence_threshold} outside [0, 1]")
        self._entities = enabled_entities
        self._threshold = confidence_threshold

    @property
    def supported_entities(self) -> tuple[str, ...]:
        """Entities this detector can actually find, in configuration order."""
        return tuple(e for e in self._entities if e in PATTERNS)

    @property
    def skipped_entities(self) -> tuple[str, ...]:
        """Configured entities that need NER and are therefore not detected."""
        return tuple(e for e in self._entities if e in NER_ONLY_ENTITIES)

    def _score(self, text: str) -> RawScore:
        if not text:
            return RawScore(score=0.0)

        spans: list[Span] = []
        detail: dict[str, float] = {}

        for entity_type in self._entities:
            entry = PATTERNS.get(entity_type)
            if entry is None:
                # Either an NER-only entity or an unknown one. Both are skipped
                # rather than raising, so a policy naming them still runs.
                continue
            pattern, confidence = entry
            if confidence < self._threshold:
                continue

            for match in pattern.finditer(text):
                if entity_type == "CREDIT_CARD" and not luhn_valid(match.group()):
                    continue
                spans.append(Span(start=match.start(), end=match.end(), label=entity_type))
                detail[entity_type] = confidence

        # max(confidence), as in the dissertation: the strongest single piece
        # of evidence, not an average that many weak matches could inflate.
        return RawScore(
            score=max(detail.values()) if detail else 0.0,
            detail=detail,
            spans=tuple(spans),
        )
