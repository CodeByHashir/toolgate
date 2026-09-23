"""Canonicalisation applied before detection (pipeline step 1).

Ported from LLMShield's `RequestNormaliser`, whose docstring states it "runs
before any detection component". M3 ported the detectors but not this stage;
`docs/POLICY-AUDIT.md` measured the cost of that omission.

Five transforms, in order:

1. Unicode NFKC -- collapses fullwidth forms, ligatures and compatibility chars.
2. TAG-block decoding -- decodes runs of Unicode TAG characters back to ASCII
   and *appends* the plaintext rather than replacing it.
3. Invisible-character stripping -- every codepoint Unicode marks
   `Default_Ignorable_Code_Point`: zero-width spaces and joiners, directional
   overrides, variation selectors, fillers, BOM, and the TAG block.
4. Homoglyph folding -- Cyrillic and Greek lookalikes to their ASCII twins.
5. Base64 decoding -- decodes long base64-looking runs and *appends* the
   plaintext rather than replacing it.

Why appending rather than replacing for base64 and TAG: replacing would destroy
the offsets of everything after it, and the encoded form is itself evidence. The
decoded text is added so a rule can match on it.

## Why concealment is decoded before it is stripped

Stripping and decoding answer two different attacks, and applying the wrong one
is worse than applying nothing.

*Separator* concealment splits a visible keyword with invisible characters --
`Ig<ZWSP>nore all previous instructions`. The payload is the visible text;
the invisible characters only break the match. Stripping them reassembles
`Ignore all previous instructions` and the rule fires. This is what step 3 has
always done.

*Payload* concealment puts the entire instruction in codepoints that render as
nothing. Unicode's TAG block (U+E0000-U+E007F) is the documented case: every
ASCII byte maps to `0xE0000 + (b & 0x7F)`, which no mainstream terminal, chat
client or IDE has a glyph for, while a tokenizer decodes it like any other
text. The visible remainder is a short, truthful label.

Stripping that would delete the instruction and leave the label, so the
normalised text a detector sees would be benign -- the attack would become
invisible to detection exactly as it is already invisible to the reviewer, and
the pipeline would report a clean result with more confidence than before. The
transform has to be a *decode*: recover the ASCII, append it, and only then
strip the now-redundant TAG characters.

The stripping set is Unicode's own `Default_Ignorable_Code_Point` property,
whose definition is that a conforming renderer displays nothing for it. That is
the property this threat class turns on, so it is the right set to name rather
than an ad-hoc list of the ranges seen so far.

## What this stage does and does not close

It closes concealment -- encodings that make attacker text unreadable to a
human or unmatchable by a rule. It does not make a rule detector recognise an
instruction it would have missed in plain ASCII: a decoded payload still has to
match something. `docs/REPORT.md` measures how often that happens and the
answer is "not often".

## Spans and why detection runs twice

Normalisation changes offsets. A span found in normalised text does not point
at the same characters in the original, so redacting the original using it
would mask the wrong region -- silently corrupting a tool result.

`scan_normalised` therefore runs the detector over **both** forms:

* the original, whose spans are offset-valid and safe to redact (FR-5);
* the normalised form, which contributes detection signal only.

The score is the higher of the two. Spans come only from the original pass.
When the normalised pass finds something the original did not, that is recorded
in `detail` as `normalisation_only` so the policy engine can see that a
detection exists with no redactable span -- which is a Block, not a Redact.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

from llmshield_mcp.detectors.base import Detector, DetectorResult, Span

#: Unicode's `Default_Ignorable_Code_Point` set, from DerivedCoreProperties.txt.
#:
#: Named as a property rather than enumerated by hand because the property's
#: definition is precisely the thing being defended against: a conforming
#: renderer shows nothing for these, so any of them can carry bytes to the model
#: that never reach the reviewer's eye. The previous list here covered
#: U+200B-200F, U+202A-202E and U+FEFF only, which is a fraction of it.
#:
#: The ranges are stable across Unicode 14-16; `test_detector_normalise.py`
#: pins the ones that matter against `unicodedata` rather than trusting this
#: transcription.
DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x034F, 0x034F),  # COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x115F, 0x1160),  # HANGUL CHOSEONG/JUNGSEONG FILLER
    (0x17B4, 0x17B5),  # KHMER VOWEL INHERENT AQ/AA
    (0x180B, 0x180F),  # MONGOLIAN free variation selectors, vowel separator
    (0x200B, 0x200F),  # zero-width space/non-joiner/joiner, LRM, RLM
    (0x202A, 0x202E),  # bidi embedding and override
    (0x2060, 0x206F),  # word joiner, invisible operators, deprecated formats
    (0x3164, 0x3164),  # HANGUL FILLER
    (0xFE00, 0xFE0F),  # VARIATION SELECTOR-1..16
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE / BOM
    (0xFFA0, 0xFFA0),  # HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),  # reserved, ignorable by property
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical format controls
    (0xE0000, 0xE0FFF),  # TAG block and VARIATION SELECTOR SUPPLEMENT
)


def _char_class(ranges: tuple[tuple[int, int], ...]) -> str:
    parts = [
        rf"\U{low:08X}" if low == high else rf"\U{low:08X}-\U{high:08X}" for low, high in ranges
    ]
    return "[" + "".join(parts) + "]"


#: Characters that render as nothing and so can differ between what a reviewer
#: reads and what the model receives.
INVISIBLE_RE: re.Pattern[str] = re.compile(_char_class(DEFAULT_IGNORABLE_RANGES))

#: Unicode TAG block. `tag_encode(s) == "".join(chr(0xE0000 + (ord(c) & 0x7F)))`
#: is the published encoder; decoding is the same arithmetic inverted.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

#: Runs of two or more TAG characters. One is not a payload, and the threshold
#: is deliberately this low: the only legitimate use of TAG characters in text
#: is the three RGI emoji tag sequences (the England, Scotland and Wales flags),
#: which are 6-7 characters long. A threshold set to exclude them would also
#: hand an attacker a length under which concealment is not inspected, so they
#: are allowed to decode to harmless noise instead.
TAG_RUN_RE: re.Pattern[str] = re.compile(rf"[\U{TAG_BLOCK_START:08X}-\U{TAG_BLOCK_END:08X}]{{2,}}")

#: Base64-looking runs. 20+ characters keeps ordinary identifiers and short
#: hex tokens out; shorter runs are far too common in code and logs.
BASE64_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

#: Cyrillic and Greek characters that render like ASCII letters.
HOMOGLYPHS: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "ј": "j",
    "һ": "h",
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Х": "X",
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "υ": "u",
    "ι": "i",
    "Ο": "O",
    "Α": "A",
    "Ε": "E",
}

_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)

#: Cap on how much decoded base64 may be appended, so a large encoded blob
#: cannot multiply the text handed to a detector (SEC-2).
MAX_DECODED_CHARS = 4096


@dataclass(frozen=True, slots=True)
class Normalised:
    text: str
    transforms: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return bool(self.transforms)


def _decode_segment(match: re.Match[str]) -> str:
    segment = match.group()
    try:
        raw = base64.b64decode(segment + "==", validate=False)
        decoded = raw.decode("utf-8")
    except Exception:  # noqa: BLE001 -- any decode failure means "not base64"
        return segment
    if not decoded.isprintable() or len(decoded) > MAX_DECODED_CHARS:
        return segment
    # Append rather than replace: preserves following offsets, and the encoded
    # form is itself a signal worth keeping.
    return f"{segment} {decoded}"


def _decode_tag_run(match: re.Match[str]) -> str:
    """Recover the ASCII a TAG-block run encodes, and append it to the run.

    Control characters are dropped from the *decoded* text rather than the whole
    run being rejected when any appear. Rejecting would be an evasion: appending
    a single CANCEL TAG (U+E007F, which decodes to DEL) would make the payload
    unprintable and so exempt it from decoding entirely.
    """
    run = match.group()
    decoded = "".join(
        char for char in (chr(ord(tag) - TAG_BLOCK_START) for tag in run) if char.isprintable()
    )
    if len(decoded) < 2:
        return run
    # Truncated rather than rejected past the cap, for the same reason: a
    # length-based rejection is a length-based bypass. The cap still bounds the
    # text handed to a detector (SEC-2), so a payload can be pushed past it by
    # padding -- a known bound, not a silent one.
    return f"{run} {decoded[:MAX_DECODED_CHARS]}"


def normalise(text: str) -> Normalised:
    """Canonicalise `text`, reporting which transforms actually changed it."""
    applied: list[str] = []

    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        applied.append("nfkc")

    # Before stripping, not after: stripping a TAG-encoded payload would delete
    # it and leave only the attacker's benign-looking visible label.
    untagged = TAG_RUN_RE.sub(_decode_tag_run, folded)
    if untagged != folded:
        applied.append("tag")

    stripped = INVISIBLE_RE.sub("", untagged)
    if stripped != untagged:
        applied.append("invisible")

    unfolded = stripped.translate(_HOMOGLYPH_TABLE)
    if unfolded != stripped:
        applied.append("homoglyph")

    decoded = BASE64_RE.sub(_decode_segment, unfolded)
    if decoded != unfolded:
        applied.append("base64")

    return Normalised(text=decoded, transforms=tuple(applied))


def scan_normalised(detector: Detector, text: str) -> DetectorResult:
    """Score `text` both as-is and canonicalised, keeping offset-valid spans.

    Returns the original result unchanged when normalisation is a no-op or
    finds nothing extra, so the common path costs one extra regex sweep and
    nothing else.
    """
    direct = detector.score(text)
    canonical = normalise(text)
    if not canonical.changed or direct.failed:
        return direct

    shadow = detector.score(canonical.text)
    if shadow.failed:
        # A failure on the canonical form is still a failure to report; the
        # policy engine decides what a no-opinion detector means (SEC-6).
        return shadow

    direct_score = direct.score or 0.0
    shadow_score = shadow.score or 0.0
    if shadow_score <= direct_score:
        return direct

    # The canonical form scored higher, so obfuscation was hiding something.
    # Spans from the shadow pass are NOT offset-valid against the original and
    # are deliberately dropped; `normalisation_only` tells the policy engine a
    # detection exists that cannot be redacted precisely.
    detail = dict(direct.detail)
    detail.update(shadow.detail)
    detail["normalisation_only"] = 1.0

    return DetectorResult(
        detector=direct.detector,
        score=shadow_score,
        detail=detail,
        spans=direct.spans,
        latency_ms=direct.latency_ms + shadow.latency_ms,
        truncated=direct.truncated or shadow.truncated,
        error=None,
    )


__all__ = [
    "BASE64_RE",
    "DEFAULT_IGNORABLE_RANGES",
    "HOMOGLYPHS",
    "INVISIBLE_RE",
    "MAX_DECODED_CHARS",
    "TAG_BLOCK_END",
    "TAG_BLOCK_START",
    "TAG_RUN_RE",
    "Normalised",
    "Span",
    "normalise",
    "scan_normalised",
]
