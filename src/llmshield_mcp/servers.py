"""Reference MCP server configuration.

Server launch commands live in `config/servers.yaml` rather than in code so
that the set of monitored servers is a configuration concern, matching
PROPOSAL.md section 9 ("transparent to both the MCP client and server --
configuration only").
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from llmshield_mcp.config import REPO_ROOT, SANDBOX_PLACEHOLDER

DEFAULT_SERVERS_CONFIG_PATH = REPO_ROOT / "config" / "servers.yaml"


@dataclass(frozen=True, slots=True)
class ServerSpec:
    """How to launch one reference MCP server over stdio."""

    name: str
    command: str
    args: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServersConfig:
    sandbox: Path
    servers: dict[str, ServerSpec]

    def __getitem__(self, name: str) -> ServerSpec:
        if name not in self.servers:
            raise KeyError(f"unknown server {name!r}; known: {sorted(self.servers)}")
        return self.servers[name]


def load_servers_config(path: Path | None = None) -> ServersConfig:
    """Read and validate `config/servers.yaml`.

    The sandbox directory must already exist. Creating it here would silently
    hand the filesystem server an empty directory when the path is wrong,
    which looks like a working run that reads nothing (SEC-4).
    """
    config_path = path or DEFAULT_SERVERS_CONFIG_PATH
    raw: Any = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} did not parse to a mapping")

    sandbox_raw = os.environ.get("LLMSHIELD_SANDBOX_ROOT") or raw.get("sandbox")
    if not sandbox_raw:
        raise KeyError(f"missing required key 'sandbox' in {config_path}")

    sandbox = Path(sandbox_raw)
    if not sandbox.is_absolute():
        sandbox = REPO_ROOT / sandbox
    sandbox = sandbox.resolve()

    if not sandbox.is_dir():
        raise NotADirectoryError(
            f"sandbox directory {sandbox} does not exist. The filesystem MCP server "
            f"is confined to it (SEC-4); it is not created automatically."
        )

    servers_raw = raw.get("servers")
    if not isinstance(servers_raw, dict) or not servers_raw:
        raise ValueError(f"{config_path} defines no servers")

    servers: dict[str, ServerSpec] = {}
    for name, entry in servers_raw.items():
        if not isinstance(entry, dict):
            raise ValueError(f"server {name!r} is not a mapping")
        if "command" not in entry:
            raise KeyError(f"server {name!r} is missing 'command'")
        args = tuple(
            str(a).replace(SANDBOX_PLACEHOLDER, str(sandbox)) for a in entry.get("args", [])
        )
        servers[str(name)] = ServerSpec(name=str(name), command=str(entry["command"]), args=args)

    return ServersConfig(sandbox=sandbox, servers=servers)
