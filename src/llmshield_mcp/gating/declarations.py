"""Canonicalisation of MCP tool declarations (step 1 of the declaration plan).

`docs/PLAN-DECLARATION-INTEGRITY.md` calls this the load-bearing decision:
everything downstream -- the pin store, the verification verdicts, the churn
measurement -- is only as trustworthy as the answer to "are these two
declarations the same bytes?". A canonicaliser that folds away a difference
makes the pin blind to it, and a canonicaliser that invents differences buries
the operator in alerts until they switch the control off.

## Hash the raw bytes

The rule that matters, and it is the opposite of what the rest of this package
does to text. `detectors/normalise.py` exists to fold concealment away before a
detector sees it. Doing that here would be exactly backwards: the pin is the
one control that does not depend on recognising an attack, and a fold makes it
report `unchanged` for a declaration that was poisoned.

Measured rather than asserted, against this project's own normaliser: of six
concealment forms, five -- zero-width splitting, homoglyph substitution, NFKC
compatibility forms, bidi override, and variation selectors -- normalise a
poisoned description to byte-identical text with the clean one. Hashing that
output would have hidden all five from the pin.

The sixth, TAG-block concealment, survives only because step 0 of this plan
made `normalise` *decode* that payload rather than strip it. That is a narrow
escape from a general rule, not a reason to relax it:
`test_gating_declarations.py` pins the five collapsing cases so this
justification stays executable.

So: no NFC, no NFKC, no stripping, no case folding, no whitespace collapsing
inside string values. The only canonicalisation applied is to the *JSON
encoding* -- sorted object keys and no insignificant separator whitespace --
because that is transport framing rather than content. Two declarations that
differ in any character differ in their hash.

NFC has one legitimate use here and it is `render_for_review`, which produces
text for a human to read. That output is never hashed.

### What that costs, stated rather than hidden

A server that re-encodes its own description from NFC to NFD changes no visible
character and still trips the pin. That is a false positive in the sense the
operator cares about, and it is accepted deliberately: the alternative is a
canonicaliser that cannot see a concealment payload. §3.1 of the plan measures
how often real servers do this instead of guessing.

## Array order is significant

Object keys are sorted; JSON arrays are not reordered. Array order carries
meaning in a JSON Schema -- `enum` is the documented case, where the first
entry is what an agent filling in a value tends to reach for, and a
dangerous-default coercion works by putting the dangerous value there. A
canonicaliser that sorted arrays would report that rearrangement as
`unchanged`.

## Per-field hashes

A single blob hash answers "something changed" and leaves a human to diff a
2KB schema by eye, which is the failure this control exists to prevent. Each
field is hashed separately as well, so a verdict can name the field that moved.

## The field list

`HASHED_FIELDS` is explicit rather than "whatever the model has", so that a
new field appearing in a future SDK is a deliberate decision and a version
bump, not a silent change in what integrity means.

`meta` is excluded: it carries transport and tracing values that legitimately
differ per connection, and pinning it would produce a mutation on every
reconnect.

Everything else the SDK models is included, which is two fields more than the
plan's §2.1 list named -- that list predates the pinned `mcp==2.1.1` and misses
`execution` and `icons`. Both are server-controlled and both are worth pinning:
`icons[].src` is a server-supplied URL, and `annotations.read_only_hint` and
`destructive_hint` are precisely the fields an attacker would flip to make a
destructive tool read as safe to a reviewer or to a policy that trusts them.

## Known limitation: this hashes the parsed object

`mcp_types.Tool` does not retain unknown fields -- a server sending a field the
SDK does not model has it dropped before this code runs, so such a field cannot
be pinned. The functions here therefore take a plain mapping, so step 3 can
feed them a raw `tools/list` frame instead if interception at that layer proves
to be the better place. `declaration_fields` is the adapter, not the contract.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

import mcp_types

from llmshield_mcp.detectors.normalise import INVISIBLE_RE

#: Bumped whenever `HASHED_FIELDS` or the encoding below changes. It is bound
#: into `DeclarationHashes.combined`, so a pin written by an older version can
#: never compare equal to one written by a newer one.
CANONICALISER_VERSION = 1

#: The declaration surface that gets pinned, in a fixed order.
HASHED_FIELDS: tuple[str, ...] = (
    "name",
    "title",
    "description",
    "input_schema",
    "output_schema",
    "annotations",
    "execution",
    "icons",
)

#: Excluded, with the reason, so the omission is reviewable.
EXCLUDED_FIELDS: Mapping[str, str] = {
    "meta": "transport and tracing values that legitimately differ per connection",
}


class CanonicaliserVersionMismatch(Exception):
    """Raised when hashes from different canonicaliser versions are compared.

    Silently reinterpreting an old pin under new rules would mean the operator
    could not tell a genuine `unchanged` from an artifact of the upgrade.
    """


@dataclass(frozen=True, slots=True)
class DeclarationHashes:
    """Per-field and combined digests over one tool declaration."""

    version: int
    fields: Mapping[str, str]
    combined: str
    concealed: tuple[str, ...]

    @property
    def has_concealment(self) -> bool:
        """True when some field carries characters that render as nothing.

        Orthogonal to whether the declaration changed: concealment is a
        property of a single declaration, so unlike mutation it is detectable
        the first time a tool is ever seen.
        """
        return bool(self.concealed)


def canonical_bytes(value: object) -> bytes:
    """Serialise `value` to the exact bytes that get hashed.

    Sorted keys and tight separators make the encoding deterministic. Nothing
    else is touched: `ensure_ascii=False` keeps the real UTF-8 bytes rather
    than `\\uXXXX` escapes, so "the bytes hashed" and "the bytes the model
    receives" are the same string.
    """
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    # A server can put a lone surrogate in a JSON string. Refusing to encode it
    # would turn a malformed declaration into an exception at hashing time;
    # passing it through keeps it pinnable, which is the useful behaviour.
    return text.encode("utf-8", errors="surrogatepass")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def declaration_fields(tool: mcp_types.Tool) -> Mapping[str, Any]:
    """Project an SDK `Tool` onto the pinned field list.

    `exclude_none` means an absent field and an explicitly null one hash alike,
    which is correct -- they carry the same declaration -- while an empty
    string stays distinct from an absent field.
    """
    dumped = tool.model_dump(mode="json", by_alias=False, exclude_none=True)
    return {field: dumped[field] for field in HASHED_FIELDS if field in dumped}


def _iter_strings(value: object) -> Iterator[str]:
    """Every string anywhere in a declaration field, including object keys.

    Keys are walked too: a JSON Schema property *name* is model-visible text
    and can carry a concealed payload as readily as a description can.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def concealed_fields(fields: Mapping[str, Any]) -> tuple[str, ...]:
    """Which fields carry characters that a conforming renderer will not draw.

    Uses the same ignorable set as `detectors/normalise.py`, so the two layers
    cannot disagree about what counts as invisible.
    """
    return tuple(
        field
        for field in HASHED_FIELDS
        if field in fields
        and any(INVISIBLE_RE.search(text) for text in _iter_strings(fields[field]))
    )


def hash_fields(fields: Mapping[str, Any]) -> DeclarationHashes:
    """Hash an already-projected declaration mapping."""
    per_field = {field: _digest(fields[field]) for field in HASHED_FIELDS if field in fields}
    combined = _digest({"version": CANONICALISER_VERSION, "fields": per_field})
    return DeclarationHashes(
        version=CANONICALISER_VERSION,
        fields=per_field,
        combined=combined,
        concealed=concealed_fields(fields),
    )


def hash_declaration(tool: mcp_types.Tool) -> DeclarationHashes:
    """Hash one SDK `Tool`."""
    return hash_fields(declaration_fields(tool))


def changed_fields(before: DeclarationHashes, after: DeclarationHashes) -> tuple[str, ...]:
    """Field names whose hash differs, including fields added or removed.

    Returned in `HASHED_FIELDS` order so a log line reads the same way twice.
    """
    if before.version != after.version:
        raise CanonicaliserVersionMismatch(
            f"pin was written by canonicaliser v{before.version}, "
            f"this is v{after.version}; the comparison would be meaningless"
        )
    return tuple(
        field for field in HASHED_FIELDS if before.fields.get(field) != after.fields.get(field)
    )


def render_for_review(text: str) -> str:
    """Text for a human to read in a diff. Never hashed.

    Two things happen here that must never happen to hashed bytes. NFC folds
    the composed and decomposed spellings of a character together, so a diff
    does not show two identical-looking lines as different. And every codepoint
    that renders as nothing is replaced by a visible `<U+XXXX>` marker.

    The second is the point. The gap this whole plan addresses is that nothing
    in MCP requires the bytes a reviewer is shown and the bytes the model
    receives to match; a review render that silently drops the concealed
    payload reproduces that gap inside the tool meant to close it.
    """
    return INVISIBLE_RE.sub(
        lambda match: f"<U+{ord(match.group()):04X}>",
        unicodedata.normalize("NFC", text),
    )


__all__ = [
    "CANONICALISER_VERSION",
    "EXCLUDED_FIELDS",
    "HASHED_FIELDS",
    "CanonicaliserVersionMismatch",
    "DeclarationHashes",
    "canonical_bytes",
    "changed_fields",
    "concealed_fields",
    "declaration_fields",
    "hash_declaration",
    "hash_fields",
    "render_for_review",
]
