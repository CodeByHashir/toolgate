"""Tests for the ported PII scanner, its redaction, and SEC-3 leakage."""

from __future__ import annotations

import json
import re

import pytest

from llmshield_mcp.detectors.base import Span
from llmshield_mcp.detectors.pii import (
    NER_ONLY_ENTITIES,
    PATTERNS,
    PiiDetector,
    luhn_valid,
    redact,
)

# Synthetic values only. The card numbers are the standard test numbers that
# satisfy Luhn but belong to nobody.
EMAIL = "priya.shah@example.com"
PHONE = "555-123-4567"
VISA = "4111111111111111"
SSN = "123-45-6789"
IP = "192.168.1.42"


@pytest.fixture(scope="module")
def detector() -> PiiDetector:
    return PiiDetector()


# --- detection ------------------------------------------------------------


@pytest.mark.parametrize(
    "text,entity",
    [
        (f"write to {EMAIL} please", "EMAIL_ADDRESS"),
        (f"call {PHONE} today", "PHONE_NUMBER"),
        (f"card {VISA} on file", "CREDIT_CARD"),
        (f"ssn {SSN} on record", "US_SSN"),
        (f"host {IP} is down", "IP_ADDRESS"),
    ],
)
def test_each_entity_type_is_detected(detector: PiiDetector, text: str, entity: str) -> None:
    result = detector.score(text)

    assert entity in result.detail
    assert result.score == PATTERNS[entity][1]


def test_score_is_the_maximum_confidence_not_a_sum(detector: PiiDetector) -> None:
    # As in the dissertation: the strongest single piece of evidence. A sum or
    # mean would let many weak matches outrank one strong one.
    result = detector.score(f"{EMAIL} and {PHONE} and {VISA}")

    assert result.score == 0.90  # CREDIT_CARD, the highest of the three
    assert len(result.detail) == 3


def test_benign_text_scores_zero(detector: PiiDetector) -> None:
    assert detector.score("The quarterly report is attached.").score == 0.0


def test_empty_text_scores_zero(detector: PiiDetector) -> None:
    result = detector.score("")

    assert result.score == 0.0
    assert result.spans == ()


def test_every_occurrence_becomes_a_span(detector: PiiDetector) -> None:
    result = detector.score(f"{EMAIL} then dev@other.org then {EMAIL}")

    assert len([s for s in result.spans if s.label == "EMAIL_ADDRESS"]) == 3


def test_spans_point_at_the_matched_value(detector: PiiDetector) -> None:
    text = f"reach me on {EMAIL} anytime"

    span = detector.score(text).spans[0]

    assert text[span.start : span.end] == EMAIL


# --- Luhn -----------------------------------------------------------------


def test_luhn_accepts_valid_card_numbers() -> None:
    assert luhn_valid(VISA)
    assert luhn_valid("5500005555555559")


def test_luhn_rejects_an_invalid_number() -> None:
    assert not luhn_valid("4111111111111112")


def test_luhn_rejects_an_empty_string() -> None:
    assert not luhn_valid("no digits here")


def test_card_shaped_number_failing_luhn_is_not_reported(detector: PiiDetector) -> None:
    # The whole point of the Luhn check: long digit runs are common in logs.
    result = detector.score("order reference 4111111111111112 shipped")

    assert "CREDIT_CARD" not in result.detail


# --- configuration --------------------------------------------------------


def test_only_enabled_entities_are_scanned() -> None:
    detector = PiiDetector(enabled_entities=("EMAIL_ADDRESS",))

    result = detector.score(f"{EMAIL} and {PHONE}")

    assert set(result.detail) == {"EMAIL_ADDRESS"}


def test_ner_only_entities_are_skipped_not_fatal() -> None:
    # A policy naming PERSON must still run; the gap is documented, not hidden.
    detector = PiiDetector(enabled_entities=("PERSON", "LOCATION", "EMAIL_ADDRESS"))

    assert detector.skipped_entities == ("PERSON", "LOCATION")
    assert detector.supported_entities == ("EMAIL_ADDRESS",)
    assert detector.score(f"Priya lives in Leeds, {EMAIL}").score == 0.85


def test_unknown_entity_names_are_skipped() -> None:
    detector = PiiDetector(enabled_entities=("NOT_A_THING", "EMAIL_ADDRESS"))

    assert detector.score(EMAIL).score == 0.85


def test_threshold_filters_out_lower_confidence_patterns() -> None:
    # PHONE_NUMBER and IP_ADDRESS sit at 0.75; a 0.8 threshold drops them.
    detector = PiiDetector(confidence_threshold=0.8)

    assert detector.score(PHONE).score == 0.0
    assert detector.score(EMAIL).score == 0.85


def test_out_of_range_threshold_is_rejected() -> None:
    with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
        PiiDetector(confidence_threshold=1.5)


def test_ner_only_set_and_pattern_set_do_not_overlap() -> None:
    assert not (set(PATTERNS) & NER_ONLY_ENTITIES)


# --- SEC-3 / NFR-4: nothing sensitive escapes -----------------------------


def test_detected_values_never_appear_in_detail(detector: PiiDetector) -> None:
    """The decision log serialises `detail`; a PII value there would be a leak."""
    result = detector.score(f"{EMAIL} {PHONE} {VISA} {SSN}")

    serialised = json.dumps(result.detail)
    for value in (EMAIL, PHONE, VISA, SSN):
        assert value not in serialised


def test_spans_carry_offsets_not_content(detector: PiiDetector) -> None:
    result = detector.score(f"{EMAIL} and {VISA}")

    for span in result.spans:
        assert isinstance(span.start, int)
        assert isinstance(span.end, int)
        # `label` is an entity type, never the value itself.
        assert span.label in PATTERNS


def test_a_full_result_can_be_serialised_without_leaking(detector: PiiDetector) -> None:
    result = detector.score(f"contact {EMAIL} or {PHONE}")

    payload = json.dumps(
        {
            "detector": result.detector,
            "score": result.score,
            "detail": result.detail,
            "spans": [[s.start, s.end, s.label] for s in result.spans],
        }
    )

    assert EMAIL not in payload
    assert PHONE not in payload


# --- redaction (FR-5) -----------------------------------------------------


def test_redact_masks_the_value_and_keeps_the_rest(detector: PiiDetector) -> None:
    text = f"Please email {EMAIL} before Friday."

    out = redact(text, detector.score(text).spans)

    assert EMAIL not in out
    assert out.startswith("Please email ")
    assert out.endswith(" before Friday.")
    assert "[REDACTED:EMAIL_ADDRESS]" in out


def test_redact_handles_several_spans(detector: PiiDetector) -> None:
    text = f"{EMAIL} / {PHONE} / {VISA}"

    out = redact(text, detector.score(text).spans)

    assert not any(v in out for v in (EMAIL, PHONE, VISA))
    assert out.count("[REDACTED:") == 3


def test_redact_with_no_spans_returns_the_input_unchanged() -> None:
    assert redact("nothing to hide", ()) == "nothing to hide"


def test_redact_collapses_overlapping_spans() -> None:
    # Overlaps would otherwise produce nested or corrupted placeholders.
    text = "abcdefghij"
    spans = (Span(start=2, end=6, label="A"), Span(start=4, end=8, label="B"))

    out = redact(text, spans)

    assert out == "ab[REDACTED:OVERLAP]ij"


def test_redact_keeps_identical_labels_when_merging() -> None:
    text = "abcdefghij"
    spans = (
        Span(start=2, end=6, label="EMAIL_ADDRESS"),
        Span(start=4, end=8, label="EMAIL_ADDRESS"),
    )

    assert redact(text, spans) == "ab[REDACTED:EMAIL_ADDRESS]ij"


def test_redact_is_order_independent(detector: PiiDetector) -> None:
    text = f"{EMAIL} and {PHONE}"
    spans = detector.score(text).spans

    assert redact(text, spans) == redact(text, tuple(reversed(spans)))


# --- SEC-6 fail-closed ----------------------------------------------------


class _ExplodingPattern:
    def finditer(self, text: str) -> object:
        raise RuntimeError("regex engine exploded")


def test_pii_detector_failure_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    """SEC-6, as for the rule engine: a failure is a result, not an exception."""
    monkeypatch.setitem(
        PATTERNS,
        "EMAIL_ADDRESS",
        (_ExplodingPattern(), 0.85),  # type: ignore[arg-type]
    )

    result = PiiDetector(enabled_entities=("EMAIL_ADDRESS",)).score("anything")

    assert result.failed
    assert result.score is None
    assert "regex engine exploded" in (result.error or "")


def test_patterns_are_restored_after_the_failure_test() -> None:
    # Guards against the monkeypatch above leaking into later tests.
    assert isinstance(PATTERNS["EMAIL_ADDRESS"][0], re.Pattern)
