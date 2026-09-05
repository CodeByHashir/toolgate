"""Tests for tool-result content extraction and the size policy.

Every awkward case PROPOSAL.md section 19 lists gets a test here, because the
requirement is *defined behaviour*, not merely "does not crash".
"""

from __future__ import annotations

import pytest

from llmshield_mcp.detectors.base import Span
from llmshield_mcp.gating.content import BLOCK_MESSAGE, apply_redaction, build_block_result, extract


def _text_result(*texts: str, is_error: bool = False) -> dict[str, object]:
    return {
        "content": [{"type": "text", "text": t} for t in texts],
        "isError": is_error,
    }


def test_text_blocks_are_concatenated() -> None:
    content = extract(_text_result("first", "second"), max_chars=1000)

    assert content.text == "first\nsecond"
    assert content.block_types == ("text", "text")
    assert not content.truncated
    assert content.malformed is None


def test_empty_result_is_benign_not_an_error() -> None:
    # Section 19: "Empty tool result -- treated as benign; no error."
    content = extract({"content": []}, max_chars=1000)

    assert content.text == ""
    assert content.is_empty
    assert content.malformed is None
    assert content.sha256  # a hash is still computed, so the row is complete


def test_missing_content_key_is_treated_as_empty() -> None:
    content = extract({}, max_chars=1000)

    assert content.text == ""
    assert content.malformed is None


def test_tool_error_flag_is_carried_through() -> None:
    # A tool-level failure, distinct from a JSON-RPC protocol error.
    content = extract(_text_result("boom", is_error=True), max_chars=1000)

    assert content.is_error


def test_snake_case_error_flag_is_also_accepted() -> None:
    content = extract({"content": [], "is_error": True}, max_chars=1000)

    assert content.is_error


# --- size policy (FR-16 / SEC-2) -----------------------------------------


def test_oversized_result_is_truncated_and_flagged() -> None:
    content = extract(_text_result("x" * 500), max_chars=100)

    assert len(content.text) == 100
    assert content.truncated
    assert content.original_chars == 500


def test_hash_covers_the_full_text_not_the_truncated_text() -> None:
    """Otherwise two different oversized results sharing a prefix would collide."""
    a = extract(_text_result("x" * 100 + "AAA"), max_chars=50)
    b = extract(_text_result("x" * 100 + "BBB"), max_chars=50)

    assert a.text == b.text
    assert a.sha256 != b.sha256


def test_result_at_exactly_the_limit_is_not_truncated() -> None:
    content = extract(_text_result("x" * 100), max_chars=100)

    assert not content.truncated


def test_non_positive_max_chars_is_rejected() -> None:
    # A zero limit would silently disable detection entirely (SEC-2).
    with pytest.raises(ValueError, match="at least 1"):
        extract(_text_result("hi"), max_chars=0)


# --- binary and non-text content -----------------------------------------


def test_binary_blocks_are_typed_but_never_scanned() -> None:
    result = {
        "content": [
            {"type": "text", "text": "caption"},
            {"type": "image", "data": "AAAA", "mimeType": "image/png"},
            {"type": "audio", "data": "BBBB", "mimeType": "audio/wav"},
        ]
    }

    content = extract(result, max_chars=1000)

    assert content.text == "caption"
    assert content.block_types == ("text", "image", "audio")


def test_embedded_text_resource_is_scanned() -> None:
    result = {
        "content": [{"type": "resource", "resource": {"uri": "file:///a", "text": "inner text"}}]
    }

    assert extract(result, max_chars=1000).text == "inner text"


def test_embedded_binary_resource_is_not_scanned() -> None:
    result = {"content": [{"type": "resource", "resource": {"uri": "file:///a", "blob": "AAAA"}}]}

    content = extract(result, max_chars=1000)

    assert content.text == ""
    assert content.block_types == ("resource",)


# --- malformed payloads ---------------------------------------------------


def test_non_object_result_is_reported_not_raised() -> None:
    content = extract("not an object", max_chars=1000)

    assert content.malformed is not None
    assert "expected object" in content.malformed
    assert content.text == ""


def test_non_array_content_is_reported_not_raised() -> None:
    content = extract({"content": "oops"}, max_chars=1000)

    assert content.malformed is not None
    assert "expected array" in content.malformed


def test_non_object_block_is_skipped_not_fatal() -> None:
    content = extract({"content": ["bare string", {"type": "text", "text": "ok"}]}, max_chars=1000)

    assert content.text == "ok"
    assert content.block_types == ("str", "text")


def test_text_block_with_non_string_text_is_skipped() -> None:
    content = extract({"content": [{"type": "text", "text": 42}]}, max_chars=1000)

    assert content.text == ""
    assert content.malformed is None


def test_lone_surrogate_does_not_break_hashing() -> None:
    # A malformed payload can carry an unpaired surrogate; a hash that raises
    # would force an unhandled decision inside the gating path.
    content = extract(_text_result("bad \ud800 char"), max_chars=1000)

    assert len(content.sha256) == 64


def test_unknown_block_type_is_recorded_and_not_scanned() -> None:
    content = extract({"content": [{"type": "future_thing", "payload": "x"}]}, max_chars=1000)

    assert content.block_types == ("future_thing",)
    assert content.text == ""


# --- FR-5: redaction mirrors extract()'s own block walk --------------------


def test_apply_redaction_masks_a_span_in_a_single_text_block() -> None:
    result = _text_result("call me at 555-123-4567 please")
    span = Span(start=11, end=23, label="PHONE_NUMBER")

    redacted = apply_redaction(result, (span,))

    assert redacted["content"][0]["text"] == "call me at [REDACTED:PHONE_NUMBER] please"
    # The original is never mutated in place.
    assert result["content"][0]["text"] == "call me at 555-123-4567 please"


def test_apply_redaction_targets_only_the_block_the_span_falls_in() -> None:
    # extract() would join these as "first block\nsecond block with a@b.com".
    # The span's offset lands inside the second block once the "\n" separator
    # is accounted for -- that accounting is exactly what _walk_blocks shares
    # between extract() and apply_redaction().
    result = _text_result("first block", "second block with a@b.com")
    joined = extract(result, max_chars=1000).text
    start = joined.index("a@b.com")
    span = Span(start=start, end=start + len("a@b.com"), label="EMAIL_ADDRESS")

    redacted = apply_redaction(result, (span,))

    assert redacted["content"][0]["text"] == "first block"
    assert redacted["content"][1]["text"] == "second block with [REDACTED:EMAIL_ADDRESS]"


def test_apply_redaction_leaves_non_text_blocks_alone() -> None:
    result = {
        "content": [
            {"type": "text", "text": "secret@example.com"},
            {"type": "image", "data": "AAAA", "mimeType": "image/png"},
        ]
    }
    span = Span(start=0, end=len("secret@example.com"), label="EMAIL_ADDRESS")

    redacted = apply_redaction(result, (span,))

    assert redacted["content"][1] == {"type": "image", "data": "AAAA", "mimeType": "image/png"}


def test_apply_redaction_masks_an_embedded_text_resource() -> None:
    result = {
        "content": [{"type": "resource", "resource": {"uri": "file:///a", "text": "call 555-0100"}}]
    }
    span = Span(start=5, end=13, label="PHONE_NUMBER")

    redacted = apply_redaction(result, (span,))

    assert redacted["content"][0]["resource"]["text"] == "call [REDACTED:PHONE_NUMBER]"


def test_apply_redaction_with_no_spans_returns_the_same_object() -> None:
    result = _text_result("nothing to see here")

    assert apply_redaction(result, ()) is result


# --- FR-6: Block replaces the whole result ----------------------------------


def test_build_block_result_replaces_content_with_the_block_message() -> None:
    blocked = build_block_result()

    assert blocked["content"] == [{"type": "text", "text": BLOCK_MESSAGE}]
    assert blocked["isError"] is True
