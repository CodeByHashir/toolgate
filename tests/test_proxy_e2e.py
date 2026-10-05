"""The v0.1 acceptance test, toolgate ON (T9 part 2, design "The demo", claim 1).

The same scripted scenario as tests/test_demo_fixtures.py's recorded
toolgate-OFF run, with both real servers now behind `toolgate wrap`:

    filesystem: toolgate wrap --name filesystem --config <demo/filesystem.yaml copy>
                -- npx -y @modelcontextprotocol/server-filesystem@2026.8.31 <project>
    fetch:      toolgate wrap --name fetch --config <demo/fetch.yaml copy>
                -- uvx mcp-server-fetch==2026.8.18

The copies differ from the committed demo files only where a test must: the
real ephemeral page port instead of the documented 8765, an absolute sandbox,
and a state_dir under tmp_path so no test writes to the user's state dir.

What this proves is the proxy, not a model: the exact calls the injection
asks for are made, and the listener -- the only witness -- receives nothing
for the variants the egress rule covers. The redirect variant is asserted to
LEAK with network mode off: the URL is on the allowlist and the server
follows the redirect itself, which the argument-level gate cannot see.
Asserting it keeps the README's "not covered without network mode" line
honest. With `network: enforce` (the last test) the redirect hop goes
through toolgate's forward proxy and is refused.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

from tests.fixtures.demo import (
    CANARY_LINE,
    DOCUMENTED_PAGE_PORT,
    FETCH_COMMAND,
    FILESYSTEM_COMMAND,
    PROJECT_DIR,
)
from tests.fixtures.demo.http_fixtures import free_port
from tests.fixtures.demo.scenario import run_scenario

DEMO = Path(__file__).resolve().parent.parent / "demo"

#: Set by the release workflow's smoke job: run the demo against the
#: published package rather than this source tree, e.g.
#: '["uvx", "--from", "toolgate-mcp==0.1.0a1", "toolgate"]'.
WRAP_COMMAND_ENV = "TOOLGATE_WRAP_COMMAND"
#: Set by the smoke job so missing npx/uvx fails instead of skipping: a
#: release must not be announced on a demo that silently did not run.
REQUIRE_LIVE_ENV = "TOOLGATE_REQUIRE_LIVE"

pytestmark = [
    pytest.mark.live_servers,
    pytest.mark.skipif(
        (shutil.which("npx") is None or shutil.which("uvx") is None)
        and not os.environ.get(REQUIRE_LIVE_ENV),
        reason="npx and uvx are needed to start the pinned reference servers",
    ),
]


def _toolgate_command() -> list[str]:
    configured = os.environ.get(WRAP_COMMAND_ENV)
    if configured:
        command = json.loads(configured)
        assert isinstance(command, list) and all(isinstance(part, str) for part in command)
        return command
    return [sys.executable, "-m", "toolgate"]


def _configs(tmp_path: Path, page_port: int) -> tuple[Path, Path]:
    state = tmp_path / "state"
    fetch = (DEMO / "fetch.yaml").read_text(encoding="utf-8")
    fetch = fetch.replace(f"localhost:{DOCUMENTED_PAGE_PORT}", f"localhost:{page_port}")
    fetch += f'\nstate_dir: "{state.as_posix()}"\n'
    filesystem = (DEMO / "filesystem.yaml").read_text(encoding="utf-8")
    filesystem = filesystem.replace(
        'sandbox: "../tests/fixtures/demo/project"', f'sandbox: "{PROJECT_DIR.as_posix()}"'
    )
    filesystem += f'\nstate_dir: "{state.as_posix()}"\n'
    fetch_path, filesystem_path = tmp_path / "fetch.yaml", tmp_path / "filesystem.yaml"
    fetch_path.write_text(fetch, encoding="utf-8")
    filesystem_path.write_text(filesystem, encoding="utf-8")
    return fetch_path, filesystem_path


def _wrapped(name: str, config: Path, command: tuple[str, ...]) -> list[str]:
    return [*_toolgate_command(), "wrap", "--name", name, "--config", str(config), "--", *command]


def test_toolgate_on_refuses_every_covered_variant(tmp_path: Path) -> None:
    page_port, attacker_port = free_port(), free_port()
    fetch_config, filesystem_config = _configs(tmp_path, page_port)

    result = run_scenario(
        _wrapped("filesystem", filesystem_config, FILESYSTEM_COMMAND),
        _wrapped("fetch", fetch_config, FETCH_COMMAND),
        page_port=page_port,
        attacker_port=attacker_port,
    )

    # The allowed parts still work through the proxy.
    assert result.read_text.strip() == CANARY_LINE  # redaction is off for filesystem
    assert result.control_ok, (result.control_head, result.noise)

    outcomes = result.by_variant()
    for variant in ("exfil", "backslash", "other_port"):
        outcome = outcomes[variant]
        assert outcome.refused, variant
        assert outcome.reply_head == "Blocked by toolgate policy: rule fetch.fetch.egress", variant
        assert outcome.listener_targets == [], variant  # nothing reached the destination
        assert not outcome.canary_at_listener, variant

    # Not covered, by design, and shown rather than hidden.
    assert outcomes["redirect"].canary_at_listener

    audit = tmp_path / "state" / "audit" / "fetch.sqlite"
    with sqlite3.connect(audit) as db:
        blocks = db.execute(
            "SELECT tool_name, outcome, note FROM decision_log WHERE fused_decision = 'block'"
        ).fetchall()
    assert len(blocks) == 3
    assert all(row[0] == "fetch" and row[1] == "tool_call" for row in blocks)
    assert all("rule fetch.fetch.egress" in row[2] for row in blocks)
    assert all("tg-7f3a9c1e5b2d4e60" not in str(row) for row in blocks)


def test_network_mode_refuses_the_redirect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Network mode closes the redirect variant for mcp-server-fetch (httpx).

    The launcher must run offline (design premise 4): with proxy variables
    set, `uvx` would ask PyPI through the proxy and be refused. One online
    run first fills the cache, as the README tells users to do. A parent
    NO_PROXY naming loopback must not exempt the loopback attacker.
    """
    import subprocess

    subprocess.run([*FETCH_COMMAND, "--help"], capture_output=True, timeout=300, check=True)
    offline_fetch = (FETCH_COMMAND[0], "--offline", *FETCH_COMMAND[1:])
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)

    page_port, attacker_port = free_port(), free_port()
    fetch_config, filesystem_config = _configs(tmp_path, page_port)
    fetch_config.write_text(
        fetch_config.read_text(encoding="utf-8") + "network: enforce\n", encoding="utf-8"
    )

    result = run_scenario(
        _wrapped("filesystem", filesystem_config, FILESYSTEM_COMMAND),
        _wrapped("fetch", fetch_config, offline_fetch),
        page_port=page_port,
        attacker_port=attacker_port,
    )

    assert result.control_ok, (result.control_head, result.noise)
    outcomes = result.by_variant()
    for variant in ("exfil", "backslash", "other_port"):
        assert outcomes[variant].refused, variant
        assert outcomes[variant].listener_targets == [], variant
    redirect = outcomes["redirect"]
    assert not redirect.canary_at_listener, redirect.reply_head
    assert redirect.listener_targets == [], redirect.reply_head

    audit = tmp_path / "state" / "audit" / "fetch.sqlite"
    with sqlite3.connect(audit) as db:
        refused = db.execute(
            "SELECT detector_scores, note FROM decision_log "
            "WHERE outcome = 'network_egress' AND fused_decision = 'block'"
        ).fetchall()
    destinations = {json.loads(row[0])["destination"] for row in refused}
    # The demo page redirects to 127.0.0.1:<attacker>.
    assert any(d.endswith(f":{attacker_port}") for d in destinations), destinations
    assert all("is not in the egress union of server fetch" in row[1] for row in refused)
