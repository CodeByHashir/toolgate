"""PII-local finder for attacker-controlled email-address representations (M18-1).

M17 (`docs/REPRESENTATION-EVALUATION.md`) showed the shipped PII detector recognises
`contact@contact.com` and its case variant and nothing else: `contact [at]
contact.com`, `contact (at) contact.com`, `contact at contact dot com` and
`contact @ contact . com` all pass the gate byte-for-byte unchanged.

This module is the finder only (`docs/PII-REPRESENTATION-DESIGN.md` section 3,
option O3): it matches an obfuscated address **in the original text**, builds a
canonical string from the matched substring alone, and reports the match only if
that canonical string is itself a valid email per the shipped pattern. It is not
wired into `PiiDetector` and does not change any detector, policy or gate
behaviour -- that is M18-2/M18-3. It never rewrites a document, never returns
matched text (SEC-3, NFR-4 -- only offsets and a form name), and never spans a
newline (so a match can never straddle the block-join `apply_redaction` uses,
`gating/content.py`).

Two forms are on by default; `words` is implemented but off (design section 7:
real collisions with ordinary prose -- "Look at google dot com", "Follow us @
twitter.com" -- and no benign email corpus exists locally to set a false-positive
ceiling for it).

* `bracketed`: `[at]`/`(at)`/`{at}` (matching pair) for `@`; optionally
  `[dot]`/`(dot)`/`{dot}` for `.`. Example: `contact [at] contact.com`.
* `spaced`: 1-3 blanks on both sides of `@` and of every domain `.`.
  Example: `contact @ contact . com`.
* `words` (off by default): bare `at`/`dot`, TLD from a fixed allow-list.
  Example: `contact at contact dot com`.

Every whitespace run is `[ \\t]` only -- never `\\n`/`\\r` -- bounded to at most 3,
and every token/label is length-bounded, matching
`docs/PII-REPRESENTATION-DESIGN.md` section 4's grammar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Representation names this module knows. Order matches the design doc's table.
BRACKETED = "bracketed"
SPACED = "spaced"
WORDS = "words"

#: On by default in the design (`_build_pii`, M18-3, will pass this).
DEFAULT_REPRESENTATIONS: tuple[str, ...] = (BRACKETED, SPACED)
#: Every representation this module implements, including the off-by-default one.
ALL_REPRESENTATIONS: tuple[str, ...] = (*DEFAULT_REPRESENTATIONS, WORDS)

# --- grammar building blocks (docs/PII-REPRESENTATION-DESIGN.md section 4) ------
#
# `[ \t]` only, never `\s`: `\s` matches `\n`/`\r`, which would let a match cross
# the "\n" `gating/content.py` uses to join content blocks (F5/I2).
_W0 = r"[ \t]{0,3}"
_W1 = r"[ \t]{1,3}"
#: The shipped local-part alphabet minus ".": dots are handled by `_SEP_*` so a
#: bracketed/spaced dot marker can stand in for them.
_TOKEN = r"[A-Za-z0-9_%+\-]{1,64}"
#: A DNS label: alnum, interior hyphens only, 1-63 characters (RFC 1035).
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
_TLD = r"[A-Za-z]{2,24}"
#: Common TLDs, used only by `words` (design section 4: "TLD from an allow-list"),
#: since that form's bare "at"/"dot" collides with ordinary prose too easily to
#: accept an arbitrary letters-only TLD (section 7).
_WORDS_TLD = (
    "com|org|net|edu|gov|mil|int|io|co|ai|app|dev|info|biz|us|uk|de|fr|nl|ca|au|jp|"
    "cn|in|ru|br|es|it|se|ch|xyz|me|tv|cc|ly|sh|gg|eu|no|dk|fi|pl|pt|be|nz|za|mx|ar|"
    "kr|tw|hk|sg|example"
)
#: A local part or label boundary: not glued to another local/domain character.
_BEFORE = r"(?<![A-Za-z0-9._%+\-@])"
_AFTER = r"(?![A-Za-z0-9\-@_])"


def _bracket_marker(word: str) -> str:
    """`[<w0>word<w0>]` / `(...)` / `{...}`, matching bracket pairs only."""
    at = r"[aA][tT]" if word == "at" else r"[dD][oO][tT]"
    return rf"(?:\[{_W0}{at}{_W0}\]|\({_W0}{at}{_W0}\)|\{{{_W0}{at}{_W0}\}})"


_AT_BRACKET = _bracket_marker("at")
_DOT_BRACKET = _bracket_marker("dot")
#: A domain/local separator: a literal "." or a spaced-out bracketed "[dot]".
_SEP_BRACKET = rf"(?:\.|{_W0}{_DOT_BRACKET}{_W0})"

_BRACKETED_RE = re.compile(
    rf"{_BEFORE}{_TOKEN}(?:{_SEP_BRACKET}{_TOKEN})*{_W0}{_AT_BRACKET}{_W0}"
    rf"{_LABEL}(?:{_SEP_BRACKET}{_LABEL})*{_SEP_BRACKET}{_TLD}{_AFTER}"
)

#: Local-part separator for `spaced`: a plain "." or one spaced with 1-3 blanks
#: on both sides (design: "local-part dots plain or spaced").
_SEP_SPACED_LOCAL = rf"(?:\.|{_W1}\.{_W1})"
_SPACED_RE = re.compile(
    rf"{_BEFORE}{_TOKEN}(?:{_SEP_SPACED_LOCAL}{_TOKEN})*{_W1}@{_W1}"
    rf"{_LABEL}(?:{_W1}\.{_W1}{_LABEL})*{_W1}\.{_W1}{_TLD}{_AFTER}"
)

_AT_WORD = r"[aA][tT]"
_DOT_WORD = r"[dD][oO][tT]"
#: Scoped case-insensitivity (Python 3.6+), not a whole-pattern `re.IGNORECASE`:
#: `_WORDS_TLD` is a literal-string alternation (unlike `_TLD`, which already
#: spells both cases via `[A-Za-z]`), and an upper-case TLD is not unusual in
#: an email header line (e.g. "To: CONTACT at CONTACT dot COM").
_WORDS_RE = re.compile(
    rf"{_BEFORE}{_TOKEN}{_W1}{_AT_WORD}{_W1}{_LABEL}(?:{_W1}{_DOT_WORD}{_W1}{_LABEL})*"
    rf"{_W1}{_DOT_WORD}{_W1}(?i:{_WORDS_TLD}){_AFTER}"
)

_PATTERNS: dict[str, re.Pattern[str]] = {
    BRACKETED: _BRACKETED_RE,
    SPACED: _SPACED_RE,
    WORDS: _WORDS_RE,
}


@dataclass(frozen=True, slots=True)
class RepresentationMatch:
    """One accepted obfuscated address, as offsets into the text that was scanned.

    Never carries the matched text or the address it decodes to (SEC-3, NFR-4);
    `text[start:end]` recovers it if a caller needs to, exactly like `Span`.
    """

    start: int
    end: int
    form: str

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid match [{self.start}, {self.end})")
        if self.form not in _PATTERNS:
            raise ValueError(f"unknown representation {self.form!r}")


def canonicalise(matched: str, form: str) -> str:
    """Rewrite one matched candidate's OWN text to the address it encodes.

    For validation only (`find_email_representations` feeds the result to the
    shipped `EMAIL_ADDRESS` pattern) -- never applied to a document, and never
    returned to a caller as data. Blank runs are `[ \\t]` only, so this cannot
    silently absorb a newline; whitespace is simply dropped, matching the
    bracket/spacing grammar's own whitespace-only tolerance.
    """
    if form == BRACKETED:
        text = re.sub(_AT_BRACKET, "@", matched, count=1)
        text = re.sub(_DOT_BRACKET, ".", text)
    elif form == WORDS:
        text = re.sub(rf"{_W1}{_AT_WORD}{_W1}", "@", matched, count=1)
        text = re.sub(rf"{_W1}{_DOT_WORD}{_W1}", ".", text)
    else:  # SPACED: "@" and "." are already literal; only blanks need removing
        text = matched
    return re.sub(r"[ \t]", "", text)


def find_email_representations(
    text: str, forms: tuple[str, ...], validator: re.Pattern[str]
) -> tuple[RepresentationMatch, ...]:
    """Every obfuscated address `forms` can find in `text`, offset-valid in `text`.

    `validator` is looked up by the caller at call time (the shipped
    `PATTERNS["EMAIL_ADDRESS"][0]`, `detectors/pii.py`) so this module carries no
    second notion of "a valid email" and a monkeypatched validator (as
    `test_detector_pii.py`'s failure-containment test does) is honoured here too.
    A match is accepted only when `validator.fullmatch` accepts the *canonical*
    string built from the matched substring alone (design section 5, rule 2).

    Raises `ValueError` for an unknown form name, exactly like
    `PiiDetector.__init__`'s threshold check -- a typo must fail loudly, not
    silently scan nothing.
    """
    unknown = set(forms) - set(_PATTERNS)
    if unknown:
        raise ValueError(f"unknown representation(s): {sorted(unknown)}")

    matches: list[RepresentationMatch] = []
    for form in forms:
        for found in _PATTERNS[form].finditer(text):
            candidate = canonicalise(found.group(), form)
            if validator.fullmatch(candidate):
                matches.append(RepresentationMatch(start=found.start(), end=found.end(), form=form))
    return tuple(matches)


__all__ = [
    "ALL_REPRESENTATIONS",
    "BRACKETED",
    "DEFAULT_REPRESENTATIONS",
    "RepresentationMatch",
    "SPACED",
    "WORDS",
    "canonicalise",
    "find_email_representations",
]
