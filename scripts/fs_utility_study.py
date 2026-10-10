"""Run the filesystem false-refusal study (docs/FS-UTILITY-STUDY-PREREG.md).

    uv run python scripts/fs_utility_study.py freeze            # once, no model calls
    uv run python scripts/fs_utility_study.py run [--model M]   # resumable
    uv run python scripts/fs_utility_study.py analyse

Same mechanics as scripts/utility_study.py: `freeze` hashes the
pre-registration and the code, `run` and `analyse` refuse if any changed,
each run writes one sanitised JSON file and is skipped if it exists. Unlike
that study, every arm-`on` run also records how many rows toolgate wrote to
its audit log, as per-run evidence that the traffic went through `wrap`.
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

from tests.fixtures.demo import FILESYSTEM_COMMAND  # noqa: E402

from toolgate.eval_live import rate  # noqa: E402
from toolgate.fs_utility_study import (  # noqa: E402
    ARMS,
    MODELS,
    SYSTEM,
    TASKS,
    classify_run,
    make_workspace,
    policy_for,
    server_command,
)

OUT = REPO / "results" / "fs-utility-study"
FROZEN = OUT / "frozen.json"
HASHED = [
    REPO / "docs" / "FS-UTILITY-STUDY-PREREG.md",
    REPO / "src" / "toolgate" / "fs_utility_study.py",
    REPO / "scripts" / "fs_utility_study.py",
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
        "filesystem_server": " ".join(FILESYSTEM_COMMAND),
        "sha256": {str(p.relative_to(REPO).as_posix()): _sha256(p) for p in HASHED},
        "tasks": [task.task_id for task in TASKS],
        "runs_planned": len(MODELS) * len(ARMS) * len(TASKS),
    }
    FROZEN.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"frozen: {FROZEN}")
    return 0


def _check_frozen() -> None:
    if not FROZEN.exists():
        raise SystemExit("not frozen: run `freeze` first")
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
    for path in HASHED:
        key = str(path.relative_to(REPO).as_posix())
        if frozen["sha256"].get(key) != _sha256(path):
            raise SystemExit(f"{key} changed since freeze; refusing (report as a deviation)")


def _server(arm: str, workspace: Path, state: Path) -> list[str]:
    server = server_command(FILESYSTEM_COMMAND, workspace)
    if arm == "off":
        return server
    state.mkdir(parents=True, exist_ok=True)
    policy = state / "filesystem.yaml"
    policy.write_text(policy_for(workspace) + f'state_dir: "{state.as_posix()}"\n',
                      encoding="utf-8")  # fmt: skip
    return [sys.executable, "-m", "toolgate", "wrap", "--name", "filesystem",
            "--config", str(policy), "--", *server]  # fmt: skip


def _one_run(model: str, arm: str, task: Any, helpers: Any) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "work").mkdir()
        workspace, state = root / "project", root / "state"
        make_workspace(workspace)
        command_line = _server(arm, workspace, state)
        mcp = {"mcpServers": {"filesystem": {"type": "stdio", "command": command_line[0],
                                             "args": command_line[1:]}}}  # fmt: skip
        mcp_path = root / "mcp.json"
        mcp_path.write_text(json.dumps(mcp, indent=2), encoding="utf-8")
        command = [
            _claude(), "-p", task.prompt,
            "--model", model,
            "--append-system-prompt", SYSTEM,
            "--output-format", "stream-json", "--verbose",
            "--strict-mcp-config", "--mcp-config", str(mcp_path),
            "--tools", "",
            "--allowedTools", "mcp__filesystem",
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
        answer = str(result.get("result") or "")
        task_done = task.check(workspace, answer)
        blocks = withheld = audit_rows = 0
        block_notes: list[str] = []
        audit = state / "audit" / "filesystem.sqlite"
        if audit.exists():
            with contextlib.closing(sqlite3.connect(audit)) as db:
                audit_rows = db.execute("SELECT COUNT(*) FROM decision_log").fetchone()[0]
                for outcome, note in db.execute(
                    "SELECT outcome, note FROM decision_log WHERE fused_decision = 'block'"
                ):
                    if outcome == "tool_declaration":
                        withheld += 1
                    else:
                        blocks += 1
                    block_notes.append(str(note))
        summary = {
            "model": model,
            "arm": arm,
            "task": task.task_id,
            "category": classify_run(
                failed=failed, done=task_done, toolgate_blocks=blocks, withheld=withheld
            ),
            "done": None if failed else task_done,
            "toolgate_blocks": blocks,
            "toolgate_withheld": withheld,
            "toolgate_block_notes": block_notes,
            "toolgate_audit_rows": audit_rows,
            "failed": failed,
            "failure": (result.get("result") or done.stderr[-500:]) if failed else None,
            "final_answer": answer[:500],
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
    for model in models:
        folder = OUT / "runs" / model
        folder.mkdir(parents=True, exist_ok=True)
        for task in TASKS:
            for arm in ARMS:
                path = folder / f"{task.task_id}-{arm}.json"
                if path.exists():
                    continue
                summary = _one_run(model, arm, task, helpers)
                if summary["failed"]:
                    failure = str(summary["failure"] or "").lower()
                    if any(marker in failure for marker in LIMIT_MARKERS):
                        print(f"usage limit reached at {model} {task.task_id} {arm}; stopping")
                        return 2
                    retry = _one_run(model, arm, task, helpers)
                    retry["retried_after"] = summary["failure"]
                    summary = retry
                path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                print(f"{model} {task.task_id} {arm}: {summary['category']}")
    return 0


def analyse() -> int:
    _check_frozen()
    report: dict[str, Any] = {}
    for model in MODELS:
        runs = {}
        for path in sorted((OUT / "runs" / model).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            runs[(data["task"], data["arm"])] = data
        cells: dict[str, Any] = {}
        for arm in ARMS:
            scored = [r for (t, a), r in runs.items() if a == arm and not r["failed"]]
            refused = [r for r in scored if r["toolgate_blocks"] or r["toolgate_withheld"]]
            cells[arm] = {
                "done": rate(sum(1 for r in scored if r["done"]), len(scored)),
                "runs_with_false_refusal": rate(len(refused), len(scored)),
                "false_refusal_rows": sum(
                    r["toolgate_blocks"] + r["toolgate_withheld"] for r in scored
                ),  # fmt: skip
                "failed_runs": sum(1 for (t, a), r in runs.items() if a == arm and r["failed"]),
                "on_runs_without_audit_rows": sum(
                    1 for r in scored if arm == "on" and r["toolgate_audit_rows"] == 0
                ),
            }
        tasks = sorted({t for (t, _) in runs})
        pairs = [(runs.get((t, "off")), runs.get((t, "on"))) for t in tasks]
        both = [(o, n) for o, n in pairs if o and n and not o["failed"] and not n["failed"]]
        report[model] = {
            **cells,
            "pairs": len(both),
            "off_only": sum(1 for o, n in both if o["done"] and not n["done"]),
            "on_only": sum(1 for o, n in both if n["done"] and not o["done"]),
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
