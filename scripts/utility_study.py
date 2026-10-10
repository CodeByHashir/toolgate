"""Run the real-agent utility study (docs/UTILITY-STUDY-PREREG.md).

    uv run python scripts/utility_study.py freeze            # once, no model calls
    uv run python scripts/utility_study.py run [--model M]   # resumable
    uv run python scripts/utility_study.py analyse

`freeze` records the hashes of the pre-registration and the code; `run` and
`analyse` refuse to work if any of them changed. Each run writes one
sanitised JSON file under results/utility-study/runs/<model>/<email>-<arm>.json
and is skipped if that file exists, so an interrupted study resumes.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from toolgate.eval_action import benign_items  # noqa: E402
from toolgate.eval_live import rate  # noqa: E402
from toolgate.utility_study import (  # noqa: E402
    ARMS,
    MODELS,
    POLICY,
    SYSTEM,
    TASK,
    classify_run,
    completed,
)

OUT = REPO / "results" / "utility-study"
FROZEN = OUT / "frozen.json"
MAIL_SERVER = REPO / "tests" / "fixtures" / "agent_study" / "mail_server.py"
HASHED = [
    REPO / "docs" / "UTILITY-STUDY-PREREG.md",
    REPO / "src" / "toolgate" / "utility_study.py",
    REPO / "scripts" / "utility_study.py",
    MAIL_SERVER,
]
LIMIT_MARKERS = ("usage limit", "rate limit", "limit reached", "quota")


def _demo_helpers() -> Any:
    spec = importlib.util.spec_from_file_location(
        "record_agent_demo", REPO / "scripts" / "record_agent_demo.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _claude() -> str:
    claude = shutil.which("claude")
    if claude is None:
        raise SystemExit("claude (Claude Code) is not on PATH")
    return claude


def freeze() -> int:
    if FROZEN.exists():
        raise SystemExit(f"already frozen: {FROZEN}")
    OUT.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([_claude(), "--version"], capture_output=True, text=True).stdout
    record = {
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "claude_code_version": version.strip(),
        "sha256": {str(p.relative_to(REPO).as_posix()): _sha256(p) for p in HASHED},
        "emails": {
            item.payload.payload_id: hashlib.sha256(item.document.encode()).hexdigest()
            for item in benign_items()
        },  # fmt: skip
        "runs_planned": len(MODELS) * len(ARMS) * len(benign_items()),
    }
    FROZEN.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"frozen: {FROZEN}")
    return 0


def _check_frozen() -> dict[str, Any]:
    if not FROZEN.exists():
        raise SystemExit("not frozen: run `freeze` first")
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
    for path in HASHED:
        key = str(path.relative_to(REPO).as_posix())
        if frozen["sha256"].get(key) != _sha256(path):
            raise SystemExit(f"{key} changed since freeze; refusing (report as a deviation)")
    return frozen


def _mcp_config(arm: str, email: Path, outbox: Path, state: Path) -> dict[str, Any]:
    server = [sys.executable, str(MAIL_SERVER), "--email", str(email), "--outbox", str(outbox)]
    if arm == "on":
        state.mkdir(parents=True, exist_ok=True)
        policy = state / "mail.yaml"
        policy.write_text(POLICY + f'state_dir: "{state.as_posix()}"\n', encoding="utf-8")
        server = [sys.executable, "-m", "toolgate", "wrap", "--name", "mail",
                  "--config", str(policy), "--", *server]  # fmt: skip
    return {"mcpServers": {"mail": {"type": "stdio", "command": server[0], "args": server[1:]}}}


def _one_run(model: str, arm: str, email_id: str, document: str, helpers: Any) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "work").mkdir()
        email, outbox, state = root / "latest.txt", root / "outbox.jsonl", root / "state"
        email.write_text(document, encoding="utf-8")
        mcp_path = root / "mcp.json"
        mcp_config = _mcp_config(arm, email, outbox, state)
        mcp_path.write_text(json.dumps(mcp_config, indent=2), encoding="utf-8")
        command = [
            _claude(), "-p", TASK,
            "--model", model,
            "--append-system-prompt", SYSTEM,
            "--output-format", "stream-json", "--verbose",
            "--strict-mcp-config", "--mcp-config", str(mcp_path),
            "--tools", "",
            "--allowedTools", "mcp__mail",
            "--permission-prompts", "none",
            "--setting-sources", "local",
            "--no-session-persistence",
        ]  # fmt: skip
        started = time.time()
        done = subprocess.run(command, cwd=root / "work", capture_output=True, text=True,
                              encoding="utf-8", timeout=900, env=dict(os.environ))  # fmt: skip
        elapsed = time.time() - started
        events = []
        for line in done.stdout.splitlines():
            with contextlib.suppress(ValueError):
                events.append(json.loads(line))
        result = next((e for e in reversed(events) if e.get("type") == "result"), {})
        failed = done.returncode != 0 or bool(result.get("is_error"))
        sent = []
        if outbox.exists():
            sent = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
        blocks = 0
        audit = state / "audit" / "mail.sqlite"
        if audit.exists():
            with contextlib.closing(sqlite3.connect(audit)) as db:
                blocks = db.execute(
                    "SELECT COUNT(*) FROM decision_log WHERE fused_decision = 'block'"
                ).fetchone()[0]
        summary = {
            "model": model,
            "arm": arm,
            "email": email_id,
            "category": classify_run(failed=failed, outbox=sent, toolgate_blocks=blocks),
            "completed": None if failed else completed(sent),
            "toolgate_blocks": blocks,
            "failed": failed,
            "failure": (result.get("result") or done.stderr[-500:]) if failed else None,
            "sent_to": [record.get("to") for record in sent],
            "tool_calls": helpers._tool_calls(events),
            "usage": result.get("usage"),
            "num_turns": result.get("num_turns"),
            "elapsed_s": round(elapsed, 1),
            "exit_code": done.returncode,
        }
        extra = {tmp: "<tmp>", root.as_posix(): "<tmp>", sys.executable: "<python>"}
        return json.loads(helpers._sanitise(json.dumps(summary), extra))


def run(models: list[str]) -> int:
    _check_frozen()
    helpers = _demo_helpers()
    items = benign_items()
    for model in models:
        folder = OUT / "runs" / model
        folder.mkdir(parents=True, exist_ok=True)
        for item in items:
            email_id = item.payload.payload_id.replace("/", "_")
            for arm in ARMS:
                path = folder / f"{email_id}-{arm}.json"
                if path.exists():
                    continue
                summary = _one_run(model, arm, email_id, item.document, helpers)
                if summary["failed"]:
                    failure = str(summary["failure"] or "").lower()
                    if any(marker in failure for marker in LIMIT_MARKERS):
                        print(f"usage limit reached at {model} {email_id} {arm}; stopping")
                        return 2
                    retry = _one_run(model, arm, email_id, item.document, helpers)
                    retry["retried_after"] = summary["failure"]
                    summary = retry
                path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                print(f"{model} {email_id} {arm}: {summary['category']}")
    return 0


def analyse() -> int:
    _check_frozen()
    report: dict[str, Any] = {}
    for model in MODELS:
        runs = {}
        for path in sorted((OUT / "runs" / model).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            runs[(data["email"], data["arm"])] = data
        cells = {}
        for arm in ARMS:
            scored = [r for (e, a), r in runs.items() if a == arm and not r["failed"]]
            cells[arm] = {
                "completion": rate(sum(1 for r in scored if r["completed"]), len(scored)),
                "failed_runs": sum(1 for (e, a), r in runs.items() if a == arm and r["failed"]),
                "toolgate_blocks": sum(r["toolgate_blocks"] for r in scored),
            }
        emails = {e for (e, _) in runs}
        pairs = [(runs.get((e, "off")), runs.get((e, "on"))) for e in sorted(emails)]
        both = [(o, n) for o, n in pairs if o and n and not o["failed"] and not n["failed"]]
        report[model] = {
            **cells,
            "pairs": len(both),
            "off_only": sum(1 for o, n in both if o["completed"] and not n["completed"]),
            "on_only": sum(1 for o, n in both if n["completed"] and not o["completed"]),
            "runs_found": len(runs),
        }
    (OUT / "analysis.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("freeze")
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--model", choices=MODELS, action="append")
    commands.add_parser("analyse")
    args = parser.parse_args()
    if args.command == "freeze":
        return freeze()
    if args.command == "run":
        return run(args.model or list(MODELS))
    return analyse()


if __name__ == "__main__":
    raise SystemExit(main())
