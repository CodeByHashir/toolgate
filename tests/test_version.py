"""The version a user sees must be the version that was published.

The release workflow (.github/workflows/release.yml) checks that the tag names
the version in pyproject.toml, which is what PyPI receives. `toolgate
--version` prints `toolgate.__version__`, a separate literal, so nothing there
stops a release whose CLI reports the previous version: a user pinning
`toolgate-mcp==0.1.0a1` and running `--version` would be told something else.
These tests tie the three together: pyproject.toml, `__version__` and the
installed distribution's metadata (which `uv sync` builds from pyproject.toml).
"""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
import tomllib
from pathlib import Path

import toolgate

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def test_dunder_version_matches_pyproject() -> None:
    assert toolgate.__version__ == _pyproject_version()


def test_installed_metadata_matches_pyproject() -> None:
    assert importlib.metadata.version("toolgate-mcp") == _pyproject_version()


def test_cli_reports_the_package_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "toolgate", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert result.stdout.strip() == f"toolgate {_pyproject_version()}"
