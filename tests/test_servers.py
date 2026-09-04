"""Tests for reference MCP server configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.servers import ServersConfig, ServerSpec, load_servers_config

VALID = """
sandbox: "{sandbox_dir}"
servers:
  filesystem:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "{sandbox}"]
  fetch:
    command: "uvx"
    args: ["mcp-server-fetch==2026.8.18"]
"""


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    directory = tmp_path / "sandbox"
    directory.mkdir()
    return directory


def _write(tmp_path: Path, sandbox: Path, body: str = VALID) -> Path:
    path = tmp_path / "servers.yaml"
    path.write_text(body.replace("{sandbox_dir}", sandbox.as_posix()), encoding="utf-8")
    return path


def test_loads_both_reference_servers(tmp_path: Path, sandbox: Path) -> None:
    config = load_servers_config(_write(tmp_path, sandbox))

    assert set(config.servers) == {"filesystem", "fetch"}
    assert config.sandbox == sandbox.resolve()
    assert config["fetch"].command == "uvx"


def test_sandbox_placeholder_is_substituted(tmp_path: Path, sandbox: Path) -> None:
    # SEC-4: the filesystem server must be confined to the sandbox, so the
    # placeholder has to resolve to a real absolute path before launch.
    config = load_servers_config(_write(tmp_path, sandbox))

    assert str(sandbox.resolve()) in config["filesystem"].args
    assert "{sandbox}" not in " ".join(config["filesystem"].args)


def test_missing_sandbox_directory_is_rejected(tmp_path: Path, sandbox: Path) -> None:
    # Creating it silently would hand the server an empty directory and look
    # like a working run that happens to read nothing.
    body = VALID.replace('sandbox: "{sandbox_dir}"', 'sandbox: "/definitely/not/here"')
    with pytest.raises(NotADirectoryError, match="SEC-4"):
        load_servers_config(_write(tmp_path, sandbox, body))


def test_env_var_overrides_sandbox(
    tmp_path: Path, sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setenv("LLMSHIELD_SANDBOX_ROOT", str(other))

    config = load_servers_config(_write(tmp_path, sandbox))

    assert config.sandbox == other.resolve()


def test_server_without_command_is_rejected(tmp_path: Path, sandbox: Path) -> None:
    body = VALID.replace('    command: "uvx"\n', "")
    with pytest.raises(KeyError, match="command"):
        load_servers_config(_write(tmp_path, sandbox, body))


def test_empty_server_list_is_rejected(tmp_path: Path, sandbox: Path) -> None:
    body = 'sandbox: "{sandbox_dir}"\nservers: {}\n'
    with pytest.raises(ValueError, match="no servers"):
        load_servers_config(_write(tmp_path, sandbox, body))


def test_unknown_server_name_reports_known_ones() -> None:
    config = ServersConfig(
        sandbox=Path("/tmp"),
        servers={"filesystem": ServerSpec(name="filesystem", command="npx", args=())},
    )
    with pytest.raises(KeyError, match="filesystem"):
        config["nope"]


def test_repository_config_is_valid() -> None:
    """The checked-in config must load against the real sandbox directory."""
    config = load_servers_config()

    assert set(config.servers) == {"filesystem", "fetch"}
    assert (config.sandbox / "README.md").is_file()
