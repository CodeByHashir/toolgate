"""Redaction of `resources/read` results in the stdio proxy.

Until v0.3 the proxy inspected `tools/call` results only, and the README
listed `resources/read` as passing unredacted: a server that exposes files
as resources (server-filesystem among them) could hand the model the same
personal data a tool result would have had masked. These tests pin the new
behaviour: with detectors configured, a `resources/read` reply goes through
the same detectors, policy and span-clipped redaction as a tool result.
Text contents are inspected; a `blob` is binary and passes unscanned, the
same rule as an embedded blob resource in a tool result.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.test_proxy_pump import EGRESS, EMAIL, core, line, redacting_core, replies
from toolgate.gating.audit import Decision, Outcome
from toolgate.proxy.pump import ProxyCore

URI = "file:///ws/notes/contacts.md"


def read_request(request_id: Any, uri: str = URI) -> bytes:
    return line(
        {"jsonrpc": "2.0", "id": request_id, "method": "resources/read", "params": {"uri": uri}}
    )


def read_reply(request_id: Any, *contents: dict[str, Any]) -> bytes:
    return line({"jsonrpc": "2.0", "id": request_id, "result": {"contents": list(contents)}})


def text_item(text: str, uri: str = URI) -> dict[str, Any]:
    return {"uri": uri, "mimeType": "text/markdown", "text": text}


def tracked_read(proxy: ProxyCore, request_id: Any = 1) -> None:
    effects = proxy.client_line(read_request(request_id))
    assert effects.to_server, "the request itself is always forwarded"


class TestRedaction:
    def test_pii_in_a_text_resource_is_redacted(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        effects = proxy.server_line(read_reply(1, text_item(f"Write to {EMAIL} today.")))
        (item,) = replies(effects)[0]["result"]["contents"]
        assert EMAIL not in item["text"]
        assert item["uri"] == URI and item["mimeType"] == "text/markdown"
        (record,) = effects.records
        assert record.redacted and record.outcome is Outcome.RESULT
        assert record.tool_name == "resources/read"
        assert EMAIL not in str(record)

    def test_the_uri_is_never_logged(self) -> None:
        proxy = redacting_core()
        secret_uri = "file:///home/alice/private/diary.md"
        proxy.client_line(read_request(1, secret_uri))
        effects = proxy.server_line(read_reply(1, text_item(EMAIL, secret_uri)))
        assert all("diary" not in str(r) for r in effects.records)
        assert all("diary" not in m for m in effects.messages)

    def test_a_clean_resource_is_forwarded_byte_identical_and_logged(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        raw = read_reply(1, text_item("Nothing personal here."))
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw]
        (record,) = effects.records
        assert record.fused_decision is Decision.ALLOW and record.raw_result_hash

    def test_several_items_are_each_redacted_and_blobs_pass(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        blob = {"uri": "file:///ws/logo.png", "mimeType": "image/png", "blob": "iVBORw0KGgo="}
        effects = proxy.server_line(
            read_reply(1, text_item(f"a {EMAIL}"), blob, text_item(f"b {EMAIL}", "file:///ws/b"))
        )
        contents = replies(effects)[0]["result"]["contents"]
        assert contents[1] == blob
        assert EMAIL not in contents[0]["text"] and EMAIL not in contents[2]["text"]
        assert contents[2]["uri"] == "file:///ws/b"

    def test_unknown_fields_survive(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        raw = line(
            {"jsonrpc": "2.0", "id": 1,
             "result": {"contents": [{**text_item(EMAIL), "_meta": {"k": 1}}], "_meta": {"x": 2}}}
        )  # fmt: skip
        result = replies(proxy.server_line(raw))[0]["result"]
        assert result["_meta"] == {"x": 2}
        assert result["contents"][0]["_meta"] == {"k": 1}


class TestFailClosed:
    def test_unreadable_contents_are_not_forwarded_when_redaction_is_on(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        raw = line({"jsonrpc": "2.0", "id": 1, "result": {"contents": EMAIL}})
        effects = proxy.server_line(raw)
        (reply,) = replies(effects)
        assert "error" in reply and reply["id"] == 1
        assert EMAIL.encode() not in b"".join(effects.to_client)
        assert effects.records[0].fused_decision is Decision.BLOCK

    def test_a_reply_that_fails_strict_parsing_is_not_forwarded(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        raw = (
            b'{"jsonrpc": "2.0", "id": 1, "id": 1, "result": {"contents": [{"uri": "x", '
            b'"text": "' + EMAIL.encode() + b'"}]}}\n'
        )
        effects = proxy.server_line(raw)
        assert EMAIL.encode() not in b"".join(effects.to_client)
        assert "error" in replies(effects)[0]

    def test_a_jsonrpc_error_is_forwarded(self) -> None:
        proxy = redacting_core()
        tracked_read(proxy)
        raw = line({"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": "nf"}})
        assert proxy.server_line(raw).to_client == [raw]


class TestOff:
    def test_without_detectors_resources_pass_untracked(self) -> None:
        proxy = ProxyCore(core(EGRESS).settings, detectors={})
        request = read_request(1)
        assert proxy.client_line(request).to_server == [request]
        assert proxy.pending == {}
        raw = read_reply(1, text_item(EMAIL))
        effects = proxy.server_line(raw)
        assert effects.to_client == [raw] and effects.records == []


def test_reply_json_is_valid() -> None:
    proxy = redacting_core()
    tracked_read(proxy)
    out = proxy.server_line(read_reply(1, text_item(EMAIL))).to_client[0]
    assert json.loads(out)["jsonrpc"] == "2.0"


def test_a_blocked_resource_becomes_an_error_and_nothing_of_it_is_forwarded() -> None:
    from tests.test_gating_transport import _FixedDetector
    from toolgate.detectors.base import RawScore
    from toolgate.detectors.pii import PiiDetector
    from toolgate.gating.policy import PolicyConfig
    from toolgate.proxy.pump import ProxySettings

    policy = PolicyConfig(
        calibrated=True,
        on_detector_failure=Decision.ESCALATE,
        injection_detectors=frozenset({"rules_mcp"}),
        redaction_detectors=frozenset({"pii"}),
        inert_detectors=frozenset(),
        thresholds={"rules_mcp": {"escalate": 1.0, "block": 1.0}, "pii": {"redact": 0.7}},
        max_result_chars=200_000,
    )
    fixed = _FixedDetector(RawScore(score=1.0, detail={"normalisation_only": 1.0}))
    proxy = ProxyCore(
        ProxySettings(name="fs", policy=policy),
        detectors={"rules_mcp": fixed, "pii": PiiDetector()},
    )
    tracked_read(proxy)
    effects = proxy.server_line(read_reply(1, text_item("payload text")))
    (reply,) = replies(effects)
    assert reply["error"]["message"] == "Blocked by toolgate policy"
    assert b"payload text" not in b"".join(effects.to_client)
    assert effects.records[0].fused_decision is Decision.BLOCK


EVERYTHING = ("npx", "-y", "@modelcontextprotocol/server-everything@2026.8.31", "stdio")


@pytest.mark.live_servers
@pytest.mark.skipif(shutil.which("npx") is None, reason="npx is needed for the real server")
def test_a_real_servers_resource_reads_through_wrap(tmp_path: Path) -> None:
    """End to end with a reference server that exposes resources.

    server-filesystem does not implement `resources/*`; server-everything
    does. Its static documents carry no personal data, so this shows the
    path works on real replies (shape kept, one audit row, URI not logged),
    not that anything was masked; masking is pinned by the unit tests above.
    """
    from tests.fixtures.demo.mcp_client import StdioMcpClient
    from tests.test_proxy_wrap import POLICY

    state = tmp_path / "state"
    config = tmp_path / "everything.yaml"
    config.write_text(
        POLICY.replace('state_dir: "state"', f'state_dir: "{state.as_posix()}"'),
        encoding="utf-8",
    )
    command = [sys.executable, "-m", "toolgate", "wrap", "--name", "everything",
               "--config", str(config), "--", *EVERYTHING]  # fmt: skip
    with StdioMcpClient(command, timeout=300) as client:
        client.initialize()
        listed = client.request("resources/list")["result"]["resources"]
        uri = next(r["uri"] for r in listed if r.get("mimeType") == "text/markdown")
        read = client.request("resources/read", {"uri": uri})
    (item,) = read["result"]["contents"]
    assert item["uri"] == uri and isinstance(item["text"], str) and item["text"]
    with sqlite3.connect(state / "audit" / "everything.sqlite") as db:
        rows = db.execute(
            "SELECT tool_name, note FROM decision_log WHERE tool_name = 'resources/read'"
        ).fetchall()
    assert len(rows) == 1
    assert all(uri not in str(row) for row in rows)
