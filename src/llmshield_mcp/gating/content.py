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

#: Block types whose payload is never concatenated into scannable text.
#: Images, audio and binary resources are recorded by type and passed through
#: unscanned -- an explicit policy choice, not an oversight (section 19).
NON_TEXT_BLOCK_TYPES = frozenset({"image", "audio", "resource_link"})


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

    parts: list[str] = []
    types: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            types.append(type(block).__name__)
            continue
        block_type = str(block.get("type", "unknown"))
        types.append(block_type)

        if block_type in NON_TEXT_BLOCK_TYPES:
            continue
        if block_type == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        elif block_type == "resource":
            # An embedded resource carries text only when it is a text
            # resource; a blob is binary and is not scanned.
            resource = block.get("resource")
            if isinstance(resource, dict) and isinstance(resource.get("text"), str):
                parts.append(resource["text"])

    full = "\n".join(parts)
    truncated = len(full) > max_chars

    return ExtractedContent(
        # Truncation bounds what a detector is asked to process (SEC-2). It
        # does NOT alter what the agent receives -- the gate forwards the
        # original frame untouched.
        text=full[:max_chars] if truncated else full,
        block_types=tuple(types),
        is_error=is_error,
        truncated=truncated,
        original_chars=len(full),
        sha256=_digest(full),
    )
