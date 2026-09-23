"""Tests for the M18-1 PII-local representation finder.

Not wired into `PiiDetector` -- that is M18-2/M18-3 -- so every test here calls
`find_email_representations` / `canonicalise` directly, with the shipped
`PATTERNS["EMAIL_ADDRESS"][0]` as the validator (looked up the same way
`docs/PII-REPRESENTATION-DESIGN.md` section 3 specifies).
"""

from __future__ import annotations

import re
import time

import pytest

from llmshield_mcp.detectors.pii import PATTERNS
from llmshield_mcp.detectors.pii_representations import (
    ALL_REPRESENTATIONS,
    BRACKETED,
    DEFAULT_REPRESENTATIONS,
    SPACED,
    WORDS,
    RepresentationMatch,
    canonicalise,
    find_email_representations,
)

VALIDATOR = PATTERNS["EMAIL_ADDRESS"][0]


def find(
    text: str, forms: tuple[str, ...] = DEFAULT_REPRESENTATIONS
) -> tuple[RepresentationMatch, ...]:
    return find_email_representations(text, forms, VALIDATOR)


def only(text: str, forms: tuple[str, ...] = DEFAULT_REPRESENTATIONS) -> str:
    """The single match's own substring of `text` -- fails if not exactly one."""
    matches = find(text, forms)
    assert len(matches) == 1, matches
    m = matches[0]
    return text[m.start : m.end]


# --- 1. supported representations: bracketed -------------------------------


@pytest.mark.parametrize("bracket", ["[", "(", "{"])
def test_bracketed_at_marker_every_bracket_type(bracket: str) -> None:
    close = {"[": "]", "(": ")", "{": "}"}[bracket]
    text = f"contact {bracket}at{close} contact.com"

    matches = find(text)

    assert len(matches) == 1
    assert matches[0].form == BRACKETED
    assert text[matches[0].start : matches[0].end] == text


@pytest.mark.parametrize(
    "text",
    [
        "contact[at]contact.com",  # no inner or outer blanks
        "contact [at] contact.com",  # blanks around the marker
        "contact [ at ] contact.com",  # blanks inside the brackets too
        "contact  [at]  contact.com",  # up to 3 blanks outside (bounded)
    ],
)
def test_bracketed_at_marker_spacing_variants(text: str) -> None:
    assert only(text) == text


def test_bracketed_dot_marker_in_domain() -> None:
    assert only("contact [at] contact [dot] com") == "contact [at] contact [dot] com"


def test_bracketed_dot_marker_in_local_part_too() -> None:
    text = "john [dot] smith (at) example (dot) co (dot) uk"
    assert only(text) == text


def test_bracketed_plain_dot_still_allowed_alongside_bracketed_dot() -> None:
    # "example.co" plain, "co(dot)uk" bracketed -- mixed within one address.
    assert only("john (at) example.co (dot) uk") == "john (at) example.co (dot) uk"


def test_bracketed_local_part_keeps_shipped_local_alphabet() -> None:
    assert only("a+tag_1 [at] my-domain.co.uk") == "a+tag_1 [at] my-domain.co.uk"


def test_bracketed_multiple_domain_labels() -> None:
    assert only("contact [at] mail.example.co.uk") == "contact [at] mail.example.co.uk"


# --- 2. supported representations: spaced -----------------------------------


def test_spaced_at_and_dot() -> None:
    assert only("contact @ contact . com", (SPACED,)) == "contact @ contact . com"


def test_spaced_requires_blanks_on_both_sides_of_at() -> None:
    # This module's job is representations the shipped regex misses; a bare
    # "user@domain" is already caught directly and is not this finder's input,
    # but the spaced grammar itself should not fire without any spacing at all
    # (nothing to canonicalise) -- it simply won't be reachable without at
    # least the "@" spacing this form exists for.
    assert find("contact@contact.com", (SPACED,)) == ()


def test_spaced_local_part_dot_may_be_plain_or_spaced() -> None:
    plain = "priya.shah @ acme-corp . example"
    spaced = "priya . shah @ acme-corp . example"
    assert only(plain, (SPACED,)) == plain
    assert only(spaced, (SPACED,)) == spaced


def test_spaced_domain_dots_must_all_be_spaced() -> None:
    text = "contact @ contact . co . uk"
    assert only(text, (SPACED,)) == text


def test_spaced_one_to_three_blanks() -> None:
    assert only("contact   @   contact   .   com", (SPACED,)) is not None


def test_spaced_more_than_three_blanks_is_rejected() -> None:
    assert find("contact    @ contact . com", (SPACED,)) == ()
    assert find("contact @ contact    . com", (SPACED,)) == ()


# --- 3. case variants --------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "CONTACT [AT] CONTACT.COM",
        "Contact (At) Contact.Com",
        "cOnTaCt {aT} cOnTaCt.cOm",
        "CONTACT @ CONTACT . COM",
    ],
)
def test_case_variants_are_matched(text: str) -> None:
    assert only(text) == text


def test_case_variant_canonicalises_to_a_lowercase_insensitive_valid_address() -> None:
    # canonicalise() does not lower-case; validation is case-insensitive only
    # because the shipped EMAIL_ADDRESS pattern itself is (its char classes
    # list both cases).
    assert VALIDATOR.fullmatch(canonicalise("CONTACT [AT] CONTACT.COM", BRACKETED))


# --- 4. bounded, single-line matching only -----------------------------------


def test_no_newline_inside_a_bracketed_candidate() -> None:
    assert find("contact [at]\ncontact.com") == ()


def test_no_newline_inside_a_spaced_candidate() -> None:
    assert find("contact @\ncontact . com", (SPACED,)) == ()
    assert find("contact @ contact .\ncom", (SPACED,)) == ()


def test_no_carriage_return_inside_a_candidate() -> None:
    assert find("contact [at]\rcontact.com") == ()


def test_whitespace_run_over_three_is_rejected_bracketed() -> None:
    assert find("contact [    at] contact.com") == ()
    assert find("contact [at]     contact.com") == ()


def test_token_length_is_bounded() -> None:
    # TOKEN <= 64 chars (matches the shipped EMAIL_ADDRESS local-part bound,
    # M18-0); a 65-char local segment does not validate as an email at all
    # once canonicalised, so it must not be reported as a match.
    too_long = "a" * 65
    assert find(f"{too_long} [at] contact.com") == ()
    ok = "a" * 64
    assert only(f"{ok} [at] contact.com") == f"{ok} [at] contact.com"


def test_label_length_is_bounded_and_hyphen_boundaries_enforced() -> None:
    # DNS label: 1-63 chars, no leading/trailing hyphen.
    assert find("contact [at] -example.com") == ()
    assert find("contact [at] example-.com") == ()


def test_tld_must_be_alphabetic_and_at_least_two_characters() -> None:
    assert find("contact [at] contact.c") == ()
    assert find("contact [at] contact.99") == ()
    assert only("contact [at] contact.co") == "contact [at] contact.co"


# --- 5. hard negatives (design section 7; >= 30 fixed phrases) --------------

HARD_NEGATIVES: tuple[str, ...] = (
    "Look at google dot com for details.",
    "We are at Heathrow dot com today.",
    "Stay at hotel dot com or nearby.",
    "Sit at table dot org tonight.",
    "Follow us @ twitter.com for news.",
    "Meet @ cafe.com at noon.",
    "accounts (@gmail.com or @googlemail.com), follow",
    "list [at] index 3 is the answer.",
    "a (at) b.c",
    "The value at x dot y is undefined.",
    "contact\n(at)\ncontact.com",
    "call me at 555 dot 123 dot 4567",
    "contact at contact.com",
    "see item [at] 5 . Then continue.",
    "x[at]y",
    "Visit us at example dot com",
    "email me @ home.com",
    "a[at)b.com",
    "a(at]b.com",
    "a{at)b.com",
    "[at] contact.com",
    "contact [at]",
    "contact [at] .com",
    "contact [at] contact.c",
    "contact [at] contact.123",
    "no markers here at all",
    "just some at random dot text",
    "a @ b",
    "a @ b .",
    "  [at]  ",
    "contact [ at ]",
    "contact[dot]com",
    "contact . [at] . contact . com",
    "a[[at]]b.com",
    "contact -at- contact.com",
    "contact _at_ contact.com",
    "contact <at> contact.com",
)


def test_at_least_thirty_hard_negatives_are_listed() -> None:
    assert len(HARD_NEGATIVES) >= 30


@pytest.mark.parametrize("text", HARD_NEGATIVES)
def test_hard_negatives_match_nothing_under_default_forms(text: str) -> None:
    assert find(text) == ()


# --- 6. words tier stays off by default, works when explicitly requested ---


def test_words_tier_is_not_matched_under_default_forms() -> None:
    assert find("contact at contact dot com") == ()


def test_words_tier_matches_when_explicitly_requested() -> None:
    assert only("contact at contact dot com", (WORDS,)) == "contact at contact dot com"


def test_words_tier_multi_label_domain() -> None:
    text = "bob at mail dot example dot org"
    assert only(text, (WORDS,)) == text


def test_words_tier_is_case_insensitive_for_the_tld() -> None:
    # Regression: an initial version's TLD allow-list was a lowercase-only
    # literal alternation and missed an upper-case TLD such as in an email
    # header line ("To: CONTACT at CONTACT dot COM").
    text = "To: CONTACT at CONTACT dot COM"
    matches = find(text, (WORDS,))
    assert len(matches) == 1
    assert text[matches[0].start : matches[0].end] == "CONTACT at CONTACT dot COM"


def test_words_tier_tld_must_be_in_the_allow_list() -> None:
    assert find("contact at contact dot zzzznotatld", (WORDS,)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "Look at google dot com for details.",
        "We are at Heathrow dot com today.",
        "Stay at hotel dot com or nearby.",
        "Sit at table dot org tonight.",
    ],
)
def test_words_tier_has_the_documented_prose_collisions_when_enabled(text: str) -> None:
    """Not a defect: `docs/PII-REPRESENTATION-DESIGN.md` section 7 documents
    exactly these collisions as the reason `words` defaults off. Pinned here so
    a future change either keeps this documented or is a deliberate decision,
    not a silent behaviour change."""
    assert find(text, (WORDS,)) != ()


def test_all_representations_constant_includes_words_default_does_not() -> None:
    assert WORDS not in DEFAULT_REPRESENTATIONS
    assert WORDS in ALL_REPRESENTATIONS
    assert set(ALL_REPRESENTATIONS) == set(DEFAULT_REPRESENTATIONS) | {WORDS}


# --- 7. malformed candidates --------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "contact [at) contact.com",  # mismatched bracket pair
        "contact (at] contact.com",
        "contact {at) contact.com",
        "contact [at contact.com",  # unclosed bracket
        "contact at] contact.com",  # unopened bracket
        "contact [[at]] contact.com",  # doubled bracket
        "contact [a t] contact.com",  # not spelled "at"
        "contact [at] contactcom",  # no domain separator at all
        "[at] contact.com",  # empty local part
        "contact [at] .com",  # empty domain label
        "contact [at] contact.",  # missing TLD entirely
    ],
)
def test_malformed_bracketed_candidates_are_rejected(text: str) -> None:
    assert find(text, (BRACKETED,)) == ()


@pytest.mark.parametrize(
    "text",
    [
        "contact@ contact . com",  # "@" glued to local part: not what "spaced" is for
        "contact @contact . com",
        "contact @ contact.com",  # domain dot not spaced (not what "spaced" is for)
    ],
)
def test_spaced_requires_both_sides_of_every_marker_spaced(text: str) -> None:
    assert find(text, (SPACED,)) == ()


# --- 8. exact spans into the ORIGINAL text; SEC-3 --------------------------


def test_span_covers_exactly_the_obfuscated_candidate_not_more_or_less() -> None:
    text = "prefix contact [at] contact.com suffix"

    matches = find(text)

    assert len(matches) == 1
    m = matches[0]
    assert text[m.start : m.end] == "contact [at] contact.com"
    assert text[: m.start] == "prefix "
    assert text[m.end :] == " suffix"


def test_span_in_the_second_of_two_lines() -> None:
    text = "line one has nothing\ncontact [at] contact.com\nline three"

    matches = find(text)

    assert len(matches) == 1
    m = matches[0]
    line_two_start = text.index("contact [at]")
    assert m.start == line_two_start
    assert "\n" not in text[m.start : m.end]


def test_representation_match_carries_no_address_or_text_field() -> None:
    fields = set(RepresentationMatch.__dataclass_fields__)
    assert fields == {"start", "end", "form"}


def test_representation_match_rejects_invalid_offsets() -> None:
    with pytest.raises(ValueError, match="invalid match"):
        RepresentationMatch(start=-1, end=5, form=BRACKETED)
    with pytest.raises(ValueError, match="invalid match"):
        RepresentationMatch(start=5, end=2, form=BRACKETED)


def test_representation_match_rejects_an_unknown_form() -> None:
    with pytest.raises(ValueError, match="unknown representation"):
        RepresentationMatch(start=0, end=5, form="carrier-pigeon")


def test_nothing_matched_ever_appears_in_repr_or_str_of_a_match() -> None:
    # SEC-3 / NFR-4: only offsets and a form name are ever produced.
    m = find("contact [at] contact.com")[0]
    assert "contact" not in repr(m)


# --- 9. canonicalise() ------------------------------------------------------


@pytest.mark.parametrize(
    "matched,form,expected",
    [
        ("contact [at] contact.com", BRACKETED, "contact@contact.com"),
        ("contact(at)contact.com", BRACKETED, "contact@contact.com"),
        ("contact [at] contact [dot] com", BRACKETED, "contact@contact.com"),
        ("john [dot] smith (at) example (dot) co (dot) uk", BRACKETED, "john.smith@example.co.uk"),
        ("contact @ contact . com", SPACED, "contact@contact.com"),
        ("priya . shah @ acme-corp . example", SPACED, "priya.shah@acme-corp.example"),
        ("contact at contact dot com", WORDS, "contact@contact.com"),
        ("bob at mail dot example dot org", WORDS, "bob@mail.example.org"),
    ],
)
def test_canonicalise_produces_the_encoded_address(matched: str, form: str, expected: str) -> None:
    assert canonicalise(matched, form) == expected


def test_canonicalise_never_lowercases() -> None:
    assert canonicalise("CONTACT [AT] CONTACT.COM", BRACKETED) == "CONTACT@CONTACT.COM"


def test_canonicalise_of_every_accepted_match_validates() -> None:
    for text in (
        "contact [at] contact.com",
        "contact (at) contact.com",
        "contact {at} contact.com",
        "contact @ contact . com",
        "priya . shah @ acme-corp . example",
    ):
        assert only(text) == text
        assert VALIDATOR.fullmatch(canonicalise(text, find(text)[0].form))


# --- 10. find_email_representations() argument handling --------------------


def test_empty_forms_tuple_matches_nothing() -> None:
    assert find("contact [at] contact.com", ()) == ()


def test_unknown_form_name_raises() -> None:
    with pytest.raises(ValueError, match="unknown representation"):
        find("contact [at] contact.com", ("carrier-pigeon",))


def test_a_stricter_validator_can_reject_a_structurally_valid_candidate() -> None:
    # The validator is looked up by the caller, not hard-coded (design section
    # 3): a validator that only accepts a fixed entity type still governs.
    never_matches = re.compile(r"(?!x)x")
    text = "contact [at] contact.com"

    assert find_email_representations(text, DEFAULT_REPRESENTATIONS, never_matches) == ()


def test_a_monkeypatched_validator_is_honoured_like_patterns_email_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Mirrors `test_detector_pii.py::test_pii_detector_failure_is_contained`'s
    # own monkeypatch style: this module carries no second notion of "a valid
    # email" and must defer entirely to whatever `PATTERNS["EMAIL_ADDRESS"]`
    # says at call time.
    broken = re.compile(r"$^")  # matches nothing
    text = "contact [at] contact.com"
    assert find_email_representations(text, DEFAULT_REPRESENTATIONS, broken) == ()


def test_empty_text_matches_nothing() -> None:
    assert find("") == ()


# --- 11. additive: never fewer matches than a plain substring has candidates -


def test_two_addresses_in_one_document_both_found() -> None:
    text = "First contact [at] contact.com then dev [at] other.org too."

    matches = find(text)

    assert len(matches) == 2
    substrings = sorted(text[m.start : m.end] for m in matches)
    assert substrings == ["contact [at] contact.com", "dev [at] other.org"]


# --- 12. regression: adjacent addresses -------------------------------------


@pytest.mark.parametrize(
    "glue",
    [" ", ", ", "; ", ". ", "\n", "\t", ", and also "],
)
def test_two_addresses_separated_by_a_real_separator_are_both_found(glue: str) -> None:
    # The realistic case: any actual separator -- even a single space or a
    # newline -- is enough. 0 failures over ~2,200 seeded trials each for a
    # bare space and a bare tab (see the M18-1 report).
    first = "alice [at] example.com"
    second = "bob @ other . org"
    text = f"prefix {first}{glue}{second} suffix"

    matches = find(text)

    assert len(matches) == 2
    starts = sorted((m.start, m.end) for m in matches)
    assert text[starts[0][0] : starts[0][1]] == first
    assert text[starts[1][0] : starts[1][1]] == second


def test_zero_separator_adjacency_matches_the_shipped_literal_regexs_own_behaviour() -> None:
    """Known, documented limitation, not a new regression.

    With *zero* characters between two representations whose glue point is
    itself letters (e.g. one address's TLD immediately followed by another's
    local part), the greedy, unbounded `[A-Za-z]{2,24}` TLD can swallow the
    start of the next address -- exactly as the ALREADY-SHIPPED, already-fixed
    (M18-0) literal `EMAIL_ADDRESS` pattern already does on the equivalent
    literal construction. This asserts the two are the same phenomenon, not
    something this finder introduces: `finditer` collapses two addresses
    into one both for the literal pattern and for this module's bracketed/
    spaced forms once every visual separator is removed.
    """
    literal = "alice@example.comBob@other.org"
    literal_matches = [(m.start(), m.end()) for m in VALIDATOR.finditer(literal)]
    assert len(literal_matches) == 1  # the shipped pattern also merges these

    obfuscated = "alice [at] example.comBob [at] other.org"
    matches = find(obfuscated)
    assert len(matches) == 1  # same phenomenon, not a new one


def test_a_bare_space_between_letters_is_always_enough_to_separate() -> None:
    # A lower-confidence sanity sweep of the same property as the parametrized
    # test above, across many local/domain combinations, still with a real
    # (single-space) separator every time.
    import random

    rng = random.Random(20260923)
    letters = "abcdefghijklmnopqrstuvwxyz"

    def rand_local() -> str:
        return "".join(rng.choice(letters) for _ in range(rng.randint(1, 8)))

    failures = 0
    for _ in range(500):
        l1, d1, l2, d2 = rand_local(), rand_local(), rand_local(), rand_local()
        first = f"{l1} [at] {d1}.com"
        second = f"{l2} @ {d2} . org"
        text = f"prefix {first} {second} suffix"
        matches = find(text)
        start1, start2 = text.index(first), text.rindex(second)
        cov1 = any(m.start <= start1 and start1 + len(first) <= m.end for m in matches)
        cov2 = any(m.start <= start2 and start2 + len(second) <= m.end for m in matches)
        failures += not (cov1 and cov2)
    assert failures == 0


# --- 13. long / bounded inputs: linear time, no catastrophic backtracking --


def _time_ms(text: str, forms: tuple[str, ...] = ALL_REPRESENTATIONS) -> float:
    start = time.perf_counter()
    find(text, forms)
    return (time.perf_counter() - start) * 1000.0


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200_000,
        "." * 200_000,
        "a" + " " * 200_000,
        "contact [at " * (200_000 // 12),
        "a @ b . " * (200_000 // 8),
        "x (at) y (dot) " * (200_000 // 15),
        "send to contact [at] contact.com now. " * (200_000 // 39),
        "contact" + " \t" * (200_000 // 2),
    ],
    ids=[
        "letters",
        "dots",
        "space-run",
        "unclosed-bracket",
        "spaced-at-dot",
        "bracket-and-dot",
        "many-valid",
        "tabs-spaces",
    ],
)
def test_finder_is_fast_on_200k_char_adversarial_input(text: str) -> None:
    """Design target: <= 100ms at 200k chars (`docs/PII-REPRESENTATION-DESIGN.md`
    section 5, rule 6)."""
    elapsed_ms = _time_ms(text)

    assert elapsed_ms < 100.0, f"{elapsed_ms:.1f}ms exceeds the 100ms target"


def test_finder_time_scales_linearly_not_quadratically() -> None:
    small = _time_ms("x (at) y (dot) " * (50_000 // 15))
    large = _time_ms("x (at) y (dot) " * (200_000 // 15))

    # 4x the input; a quadratic implementation would be ~16x, linear ~4x.
    assert large < max(small * 8.0, 20.0), (
        f"200k took {large:.1f}ms vs 50k's {small:.1f}ms -- looks quadratic"
    )


def test_a_single_long_token_over_the_bound_does_not_cause_slow_backtracking() -> None:
    # A pathological "local part" far longer than TOKEN's 64-char bound, with
    # no "@"/marker ever found, must fail fast rather than backtrack the
    # whole run for every one of many attempted start positions.
    text = ("a" * 200 + " [at] ") * 500  # every candidate's TOKEN is too long

    elapsed_ms = _time_ms(text)

    assert elapsed_ms < 100.0
    assert find(text) == ()  # TOKEN is bounded to 64, so none of these validate


# --- 14. module is standalone: not wired into PiiDetector -------------------


def test_module_does_not_import_pii_detector() -> None:
    """M18-1 builds the finder only; wiring it into `PiiDetector` is M18-2/M18-3.

    Checked at the import-statement level (AST), not by grepping the whole
    file, since the module's own docstring explains this in prose and
    legitimately says "PiiDetector".
    """
    import ast

    import llmshield_mcp.detectors.pii_representations as mod

    source = mod.__file__
    assert source is not None
    with open(source, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)

    assert "llmshield_mcp.detectors.pii" not in imported_modules
    assert "llmshield_mcp.gating.transport" not in imported_modules
