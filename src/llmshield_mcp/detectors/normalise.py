"""Canonicalisation applied before detection (pipeline step 1).

Ported from LLMShield's `RequestNormaliser`, whose docstring states it "runs
before any detection component". M3 ported the detectors but not this stage;
`docs/POLICY-AUDIT.md` measured the cost of that omission.

Four transforms, in order:

1. Unicode NFKC -- collapses fullwidth forms, ligatures and compatibility chars.
2. Invisible-character stripping -- zero-width spaces and joiners, directional
   overrides, BOM.
3. Homoglyph folding -- Cyrillic and Greek lookalikes to their ASCII twins.
4. Base64 decoding -- decodes long base64-looking runs and *appends* the
   plaintext rather than replacing it.

Why appending rather than replacing for base64: replacing would destroy the
offsets of everything after it, and the encoded form is itself evidence. The
decoded text is added so a rule can match on it.

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

#: Zero-width and bidirectional control characters used to break up keywords.
INVISIBLE_RE: re.Pattern[str] = re.compile(r"[​-‏‪-‮﻿]")

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


def normalise(text: str) -> Normalised:
    """Canonicalise `text`, reporting which transforms actually changed it."""
    applied: list[str] = []

    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        applied.append("nfkc")

    stripped = INVISIBLE_RE.sub("", folded)
    if stripped != folded:
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
    "HOMOGLYPHS",
    "INVISIBLE_RE",
    "MAX_DECODED_CHARS",
    "Normalised",
    "Span",
    "normalise",
    "scan_normalised",
]
