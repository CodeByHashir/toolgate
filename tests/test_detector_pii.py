"""Tests for the ported PII scanner, its redaction, and SEC-3 leakage."""

from __future__ import annotations

import json
import random
import re
import time

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


# --- M18-0: quadratic EMAIL_ADDRESS regex fixed --------------------------
#
# docs/PII-REPRESENTATION-DESIGN.md section 1: the old, unbounded
# `[a-zA-Z0-9._%+\-]+@...` let `finditer` retry the same doomed backtrack
# from every position inside a long local-part run with no reachable "@",
# which is O(n^2) (measured ~206s at 200k chars, the gate's own
# `max_result_chars`). Reconstructed here, unchanged, purely as the
# equivalence baseline -- it is never used at runtime.
_OLD_EMAIL_ADDRESS_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
)

#: Below this local-part length the new pattern must be byte-for-byte
#: equivalent to the old one. At and above it, the two are known and
#: accepted to differ (RFC 5321 caps a real local part at 64 octets) --
#: see `test_local_part_over_64_chars_is_a_documented_exception`.
_RFC5321_LOCAL_PART_LIMIT = 64


def _spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group()) for m in pattern.finditer(text)]


def _assert_equivalent(text: str) -> None:
    assert _spans(PATTERNS["EMAIL_ADDRESS"][0], text) == _spans(_OLD_EMAIL_ADDRESS_PATTERN, text)


# --- equivalence: current test cases --------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"write to {EMAIL} please",
        f"{EMAIL} and {PHONE} and {VISA}",
        "The quarterly report is attached.",
        "",
        f"{EMAIL} then dev@other.org then {EMAIL}",
        f"reach me on {EMAIL} anytime",
        f"contact {EMAIL} or {PHONE}",
        f"{EMAIL} {PHONE} {VISA} {SSN}",
        "UPPER@UPPER.COM",
        "MiXeD.CaSe+tag@Example-Domain.CO.uk",
        "no email here",
        "@nohost.com",
        "trailing@dot.",
        "a@b",
        "a@b.c",
        "mailto:foo@bar.com?subject=hi&cc=baz@qux.io",
    ],
)
def test_email_pattern_matches_the_old_pattern_on_existing_cases(text: str) -> None:
    _assert_equivalent(text)


def test_email_pattern_agrees_with_the_old_pattern_through_the_detector(
    detector: PiiDetector,
) -> None:
    text = f"{EMAIL} and {PHONE} and dev@other.org"

    result = detector.score(text)

    assert result.detail.get("EMAIL_ADDRESS") == 0.85
    assert sorted(
        text[s.start : s.end] for s in result.spans if s.label == "EMAIL_ADDRESS"
    ) == sorted([EMAIL, "dev@other.org"])


# --- equivalence: seeded generated corpus ---------------------------------

_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_LOCAL_EXTRA = "._%+-"
_DOMAIN_EXTRA = ".-"
_GLUE = ["", " ", ",", ";", "\n", "\t", ".", "-", "_", "%", "+", "a", "Z", "0"]


def _rand_token(rng: random.Random, alphabet: str, lo: int, hi: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(lo, hi)))


def _rand_email(rng: random.Random) -> str:
    local = _rand_token(rng, _LETTERS + _LOCAL_EXTRA, 1, 8).strip("@")
    dom1 = _rand_token(rng, _LETTERS + _DOMAIN_EXTRA, 1, 8).strip(".")
    dom2 = _rand_token(rng, _LETTERS + _DOMAIN_EXTRA, 1, 8).strip(".")
    tld = _rand_token(rng, _LETTERS, 2, 5)
    if rng.random() < 0.5:
        return f"{local}@{dom1}.{dom2}.{tld}"
    return f"{local}@{dom1}.{tld}"


def test_email_pattern_matches_the_old_pattern_on_a_seeded_corpus_of_addresses() -> None:
    # Includes the case that broke an earlier, rejected fix (a lookbehind):
    # two valid addresses back to back with no separator between them, e.g.
    # "a@b.comX@y.com" -- see the comment above PATTERNS["EMAIL_ADDRESS"].
    rng = random.Random(20260922)
    for _ in range(3000):
        first, second = _rand_email(rng), _rand_email(rng)
        glue = rng.choice(_GLUE)
        _assert_equivalent(f"prefix {first}{glue}{second} suffix")


def test_email_pattern_matches_the_old_pattern_on_seeded_noise_text() -> None:
    rng = random.Random(4243)
    noise_chars = _LETTERS + " .,;:!?-_@%+()[]{}\n\t/'\""
    for _ in range(3000):
        parts: list[str] = []
        for _ in range(rng.randint(1, 4)):
            parts.append(_rand_token(rng, noise_chars, 0, 15))
            if rng.random() < 0.7:
                parts.append(_rand_email(rng))
        _assert_equivalent("".join(parts))


def test_email_pattern_matches_the_old_pattern_on_invalid_email_like_strings() -> None:
    invalid = [
        "@missing-local.com",
        "missing-at.example.com",
        "double@@at.com",
        "no-tld@example",
        "one-letter-tld@example.c",
        "trailing-dot@example.com.",
        "space in local@example.com",
        "@.com",
        "a@.com",
        "a@b..com",
        "a@-b.com",
    ]
    for text in invalid:
        _assert_equivalent(text)


# --- equivalence: long adversarial strings --------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a" * 4000,
        "deadbeef" * 500,
        "." * 4000,
        ("a" * 50 + "@") * 60,
        ("x.y.z" * 20 + " ") * 60,
        "a@" + "1" * 4000,  # single "@", domain has no "." at all
        ("a" * 60 + "@" + "1" * 200 + " ") * 15,  # near-boundary local runs, no-dot domains
    ],
)
def test_email_pattern_matches_the_old_pattern_on_long_adversarial_strings(text: str) -> None:
    _assert_equivalent(text)


# --- the one documented, deliberate difference ----------------------------


@pytest.mark.parametrize("length", [_RFC5321_LOCAL_PART_LIMIT + 1, 70, 100, 300])
def test_local_part_over_64_chars_is_a_documented_exception(length: int) -> None:
    """RFC 5321 caps a local part at 64 octets; the old pattern had no cap.

    The new pattern still finds an address here (never a missed detection) --
    it just matches the last 64 characters of the run, not the whole thing.
    """
    text = f"prefix {'a' * length}@example.com suffix"

    old_span = _OLD_EMAIL_ADDRESS_PATTERN.search(text)
    new_span = PATTERNS["EMAIL_ADDRESS"][0].search(text)

    assert old_span is not None and new_span is not None
    assert old_span.start() == 7  # the old pattern matches the whole run
    assert new_span.start() == 7 + length - _RFC5321_LOCAL_PART_LIMIT  # new: last 64 chars
    assert old_span.end() == new_span.end()  # both still find the same address


def test_local_part_at_the_64_char_limit_is_not_affected() -> None:
    text = f"prefix {'a' * _RFC5321_LOCAL_PART_LIMIT}@example.com suffix"

    _assert_equivalent(text)


# --- performance / regression ----------------------------------------------


def _time_ms(pattern: re.Pattern[str], text: str) -> float:
    start = time.perf_counter()
    pattern.findall(text)
    return (time.perf_counter() - start) * 1000.0


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200_000,
        "deadbeef" * 25_000,
        "." * 200_000,
        "a@" + "1" * 199_998,  # one "@", a 200k-char domain with no "."
        ("a" * 60 + "@" + "1" * 2000 + " ") * 96,  # many near-boundary local runs
    ],
    ids=["letters", "hex", "dots", "single-at-no-dot-domain", "repeated-near-boundary"],
)
def test_email_pattern_is_fast_on_200k_char_adversarial_input(text: str) -> None:
    """The M18 target: a 200k-char worst case completes within 100ms.

    The old pattern took roughly 206 SECONDS on the plain "letters" case; this
    guards against ever reintroducing that regression. Uses the raw pattern,
    not `PiiDetector.score`, so a slow *other* entity pattern cannot mask a
    regression here.
    """
    elapsed_ms = _time_ms(PATTERNS["EMAIL_ADDRESS"][0], text)

    assert elapsed_ms < 100.0, f"{elapsed_ms:.1f}ms exceeds the 100ms target"


def test_email_pattern_time_scales_linearly_not_quadratically() -> None:
    # A quadratic implementation would take ~4x longer at 4x the input; a
    # linear one takes ~4x. Generous bound (8x) keeps this stable across
    # hardware while still catching an O(n^2) regression (which would be
    # ~16x at this ratio).
    small = _time_ms(PATTERNS["EMAIL_ADDRESS"][0], "a" * 50_000)
    large = _time_ms(PATTERNS["EMAIL_ADDRESS"][0], "a" * 200_000)

    assert large < max(small * 8.0, 20.0), (
        f"200k took {large:.1f}ms vs 50k's {small:.1f}ms -- looks quadratic again"
    )


def test_pii_detector_is_fast_on_a_200k_char_no_at_result(detector: PiiDetector) -> None:
    """End-to-end through `PiiDetector.score`, the actual gate call path."""
    text = "a" * 200_000

    start = time.perf_counter()
    result = detector.score(text)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    assert result.score == 0.0
    assert elapsed_ms < 500.0  # generous: covers every entity pattern, not just EMAIL_ADDRESS
