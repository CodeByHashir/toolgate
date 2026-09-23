"""Turning a raw tool result into the text the gating layer would scan.

Separated from the transport because the awkward cases all live here, and they
are the ones PROPOSAL.md section 19 requires defined behaviour for: oversized
results, malformed payloads, binary content, and empty results. None of them
may crash the gating path.

M2 runs no detectors. This module still exists in full because the size policy
(FR-16 / SEC-2) and the content-type policy are decisions about *what would be
scanned*, and they have to be settled and logged before detection is added --
otherwise the first detector silently inherits whatever fell out.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from llmshield_mcp.detectors.base import Span
from llmshield_mcp.detectors.pii import redact

#: Block types whose payload is never concatenated into scannable text.
#: Images, audio and binary resources are recorded by type and passed through
#: unscanned -- an explicit policy choice, not an oversight (section 19).
NON_TEXT_BLOCK_TYPES = frozenset({"image", "audio", "resource_link"})

#: FR-6: what a Block decision replaces a tool result with. Deliberately
#: plain text with no markup that could itself be mistaken for content -- the
#: whole point is that nothing from the original result survives.
BLOCK_MESSAGE = (
    "[BLOCKED: potential prompt injection detected in this tool result -- "
    "content withheld by toolgate]"
)


@dataclass(frozen=True, slots=True)
class ExtractedContent:
    """What the detectors would receive, plus how it was derived."""

    #: Scannable text, already subject to the size policy.
    text: str
    #: Every content block type present, in order.
    block_types: tuple[str, ...]
    #: The server's own tool-level failure flag (CallToolResult.isError).
    #: Distinct from a JSON-RPC protocol error, which never reaches here.
    is_error: bool
    #: True when the size policy dropped text that would otherwise be scanned.
    truncated: bool
    #: Character count before truncation.
    original_chars: int
    #: SHA-256 of the full pre-truncation text. PROPOSAL.md section 12 stores a
    #: hash rather than the content, so the audit store does not become a
    #: repository of adversarial text.
    sha256: str
    #: Set when the result could not be interpreted as a tool result at all.
    malformed: str | None = None

    @property
    def is_empty(self) -> bool:
        return not self.text


def _digest(text: str) -> str:
    # `errors="surrogatepass"` keeps lone surrogates from a malformed payload
    # from raising during hashing. A hash that cannot be computed would force a
    # decision about unhashable content in the middle of the gating path.
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


@dataclass(frozen=True, slots=True)
class _TextBlock:
    """Where one content-list block's text landed in the joined string.

    Shared by `extract()` and `apply_redaction()` so both walk the block list
    identically -- a `Span` computed against `extract()`'s joined text can
    only be translated back to its originating block if the offsets were
    produced by the exact same walk.
    """

    index: int
    start: int
    end: int


def _walk_blocks(blocks: list[Any]) -> tuple[str, tuple[str, ...], tuple[_TextBlock, ...]]:
    parts: list[str] = []
    types: list[str] = []
    contributing: list[_TextBlock] = []
    cursor = 0

    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            types.append(type(block).__name__)
            continue
        block_type = str(block.get("type", "unknown"))
        types.append(block_type)

        if block_type in NON_TEXT_BLOCK_TYPES:
            continue

        text: str | None = None
        if block_type == "text":
            candidate = block.get("text")
            if isinstance(candidate, str):
                text = candidate
        elif block_type == "resource":
            # An embedded resource carries text only when it is a text
            # resource; a blob is binary and is not scanned.
            resource = block.get("resource")
            if isinstance(resource, dict) and isinstance(resource.get("text"), str):
                text = resource["text"]

        if text is None:
            continue
        if parts:
            cursor += 1  # the "\n" that will join this part to the previous one
        start = cursor
        parts.append(text)
        cursor += len(text)
        contributing.append(_TextBlock(index=index, start=start, end=cursor))

    return "\n".join(parts), tuple(types), tuple(contributing)


def extract(result: Any, max_chars: int) -> ExtractedContent:
    """Reduce a raw `tools/call` result payload to scannable text.

    `result` is the decoded JSON-RPC `result` member, not a validated model:
    the point of this layer is that a server may send something unexpected and
    the gate still has to behave.
    """
    if max_chars < 1:
        raise ValueError(f"max_chars must be at least 1, got {max_chars}")

    if not isinstance(result, dict):
        return ExtractedContent(
            text="",
            block_types=(),
            is_error=False,
            truncated=False,
            original_chars=0,
            sha256=_digest(""),
            malformed=f"result is {type(result).__name__}, expected object",
        )

    # Accept both the wire spelling and the Python attribute spelling; the
    # transport sees raw JSON, but tests and future callers may pass either.
    is_error = bool(result.get("isError") or result.get("is_error") or False)
    blocks = result.get("content")
    if blocks is None:
        blocks = []
    if not isinstance(blocks, list):
        return ExtractedContent(
            text="",
            block_types=(),
            is_error=is_error,
            truncated=False,
            original_chars=0,
            sha256=_digest(""),
            malformed=f"content is {type(blocks).__name__}, expected array",
        )

    full, types, _contributing = _walk_blocks(blocks)
    truncated = len(full) > max_chars

    return ExtractedContent(
        # Truncation bounds what a detector is asked to process (SEC-2). It
        # does NOT alter what the agent receives -- the gate forwards the
        # original frame untouched.
        text=full[:max_chars] if truncated else full,
        block_types=types,
        is_error=is_error,
        truncated=truncated,
        original_chars=len(full),
        sha256=_digest(full),
    )


def apply_redaction(
    result: dict[str, Any], spans: tuple[Span, ...]
) -> tuple[dict[str, Any], tuple[Span, ...]]:
    """Mask `spans` in `result`, returning the copy and any span it could not apply.

    `spans` must be offsets into the joined text `extract()` would produce for
    this same `result` -- that is the contract every detector relies on, since
    they were scored against exactly that text. Non-text blocks are returned
    unchanged. Masking only ever shortens text, so it cannot push an
    already-accepted result past the size policy.

    **Spans are clipped per block, not required to sit inside one.** An earlier
    version masked a span only when a single block contained it end to end
    (`block.start <= span.start and span.end <= block.end`) and dropped it
    otherwise -- silently, with the decision still recorded as `redacted=True`.
    That was reachable and it leaked: `extract()` joins blocks with `"\\n"`, and
    several detector patterns match across one. `PHONE_NUMBER`'s separator
    class is `[-.\\s]` and `US_SSN`'s is `[-\\s]`, both of which match a
    newline, so a result whose blocks split as `"Call 555"` / `"123 4567"`
    produced a PHONE_NUMBER span across the join, masked nothing, and wrote an
    audit row claiming the redaction had happened. The number reached the model
    intact while the log said otherwise -- the worst combination available,
    because it also destroys the evidence that anything went wrong.

    Each span is now intersected with each contributing block and the overlap
    masked, so a straddling match becomes a placeholder in every block it
    touches. The output is slightly uglier than a single placeholder would be;
    it does not leak.

    The second return value is every span that still could not be applied
    anywhere -- a span outside all contributing text, which a caller passing
    offsets from some other string could produce. The `Gate` records it rather
    than discarding it (`gating/transport.py`), because "redaction was asked
    for and did not fully happen" must never again be invisible.
    """
    if not spans:
        return result, ()
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return result, spans

    _, _, contributing = _walk_blocks(blocks)
    new_blocks = list(blocks)
    applied: set[Span] = set()
    for block in contributing:
        local: list[Span] = []
        for span in spans:
            # Half-open intersection of [span.start, span.end) with this block.
            start = max(span.start, block.start)
            end = min(span.end, block.end)
            if start >= end:
                continue
            local.append(Span(start=start - block.start, end=end - block.start, label=span.label))
            applied.add(span)
        local_spans = tuple(local)
        if not local_spans:
            continue

        original = new_blocks[block.index]
        if not isinstance(original, dict):
            continue
        updated = dict(original)
        if updated.get("type") == "text" and isinstance(updated.get("text"), str):
            updated["text"] = redact(updated["text"], local_spans)
        elif updated.get("type") == "resource" and isinstance(updated.get("resource"), dict):
            resource = dict(updated["resource"])
            if isinstance(resource.get("text"), str):
                resource["text"] = redact(resource["text"], local_spans)
            updated["resource"] = resource
        new_blocks[block.index] = updated

    unapplied = tuple(span for span in spans if span not in applied)
    return {**result, "content": new_blocks}, unapplied


def build_block_result(is_error: bool = True) -> dict[str, Any]:
    """FR-6: the safe, clearly-labelled replacement for a Block decision.

    Deliberately does not carry any field from the original result forward --
    the point of Block is that nothing from the original survives.
    """
    return {
        "content": [{"type": "text", "text": BLOCK_MESSAGE}],
        "isError": is_error,
    }
