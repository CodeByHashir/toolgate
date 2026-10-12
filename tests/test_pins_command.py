"""`toolgate pins status|accept`: review and accept a declaration change.

Unit tests drive `check_tools` / `accept_tools` on a pin store; the CLI
tests start the fake server, change its `fetch` description between runs
(`--description`) and check that `status` reports the change without
writing, that `accept` re-pins exactly what was asked, and that a pin file
that will not load is refused and left as it was.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from toolgate.gating.pins import PinStore
from toolgate.pins_command import accept_tools, check_tools, format_rows

FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
SCHEMA = {"type": "object", "properties": {"url": {"type": "string"}}}
CHANGED = "Fetch a URL. Updated wording in a new release."


def tool(name: str, description: str = "d") -> dict[str, Any]:
    return {"name": name, "description": description, "inputSchema": SCHEMA}


def pinned(tmp_path: Path, *tools: dict[str, Any]) -> PinStore:
    store = PinStore.load("fake", directory=tmp_path)
    accept_tools(store, list(tools))
    return store


class TestCheck:
    def test_verdicts_and_changed_fields(self, tmp_path: Path) -> None:
        store = pinned(tmp_path, tool("fetch"), tool("old"))
        rows = check_tools(store, [tool("fetch", "new text"), tool("added"), {"name": "bad",
                                   "inputSchema": "x"}])  # fmt: skip
        by_tool = {r.tool: r for r in rows}
        assert by_tool["fetch"].verdict == "mutated"
        assert by_tool["fetch"].changed == ("description",)
        assert by_tool["added"].verdict == "new"
        assert by_tool["bad"].verdict == "unreadable"
        assert by_tool["old"].verdict == "not listed"

    def test_check_never_writes(self, tmp_path: Path) -> None:
        store = PinStore.load("fake", directory=tmp_path)
        check_tools(store, [tool("fetch")])
        assert store.pins == {} and not store.dirty

    def test_output_carries_no_declaration_text(self, tmp_path: Path) -> None:
        store = pinned(tmp_path, tool("fetch"))
        text = format_rows(check_tools(store, [tool("fetch", "SECRET-WORDING")]))
        assert "SECRET-WORDING" not in text and "mutated" in text


class TestAccept:
    def test_accept_repins_changed_and_new_only(self, tmp_path: Path) -> None:
        store = pinned(tmp_path, tool("fetch"), tool("same"))
        before = store.pins["same"]
        accepted = accept_tools(store, [tool("fetch", "v2"), tool("same"), tool("added")])
        assert sorted(accepted) == ["added", "fetch"]
        assert store.pins["same"] == before
        rows = check_tools(store, [tool("fetch", "v2"), tool("same"), tool("added")])
        assert {r.verdict for r in rows} == {"unchanged"}

    def test_accept_only_the_named_tools(self, tmp_path: Path) -> None:
        store = pinned(tmp_path, tool("fetch"), tool("other"))
        accepted = accept_tools(store, [tool("fetch", "v2"), tool("other", "v2")], only=["fetch"])
        assert accepted == ["fetch"]
        rows = {r.tool: r.verdict for r in check_tools(store, [tool("other", "v2")])}
        assert rows["other"] == "mutated"


# --- CLI -----------------------------------------------------------------------------


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "fake.yaml"
    path.write_text(
        'state_dir: "state"\ntool_declarations:\n  default:\n    mutated: block\n',
        encoding="utf-8",
    )
    return path


def _pins(tmp_path: Path, action: str, *extra: str, server: tuple[str, ...] = ()) -> Any:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "toolgate",
            "pins",
            action,
            "--name",
            "fake",
            "--config",
            str(_config(tmp_path)),
            *extra,
            "--",
            sys.executable,
            str(FAKE_SERVER),
            *server,
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=120,
    )


class TestCli:
    def test_status_accept_cycle(self, tmp_path: Path) -> None:
        first = _pins(tmp_path, "accept")
        assert first.returncode == 0, first.stderr
        pin_file = tmp_path / "state" / "pins" / "fake.json"
        assert pin_file.is_file()
        pinned_bytes = pin_file.read_bytes()

        status = _pins(tmp_path, "status", server=("--description", CHANGED))
        assert status.returncode == 0, status.stderr
        assert "fetch\tmutated\tdescription" in status.stdout
        assert "echo\tunchanged" in status.stdout
        assert CHANGED not in status.stdout + status.stderr
        assert pin_file.read_bytes() == pinned_bytes, "status never writes"

        accepted = _pins(tmp_path, "accept", "--tool", "fetch", server=("--description", CHANGED))
        assert accepted.returncode == 0, accepted.stderr
        assert "re-pinned 1 tool(s): fetch" in accepted.stderr
        again = _pins(tmp_path, "status", server=("--description", CHANGED))
        assert "fetch\tunchanged" in again.stdout
        assert CHANGED.encode() not in pin_file.read_bytes()

    def test_a_named_tool_the_server_does_not_declare_is_reported(self, tmp_path: Path) -> None:
        result = _pins(tmp_path, "accept", "--tool", "nosuch")
        assert result.returncode == 1
        assert "nosuch" in result.stderr

    def test_a_corrupt_pin_file_is_refused_and_left_alone(self, tmp_path: Path) -> None:
        pins = tmp_path / "state" / "pins"
        pins.mkdir(parents=True)
        (pins / "fake.json").write_text("{broken", encoding="utf-8")
        result = _pins(tmp_path, "accept")
        assert result.returncode == 1
        assert "could not be read" in result.stderr
        assert (pins / "fake.json").read_text(encoding="utf-8") == "{broken"
