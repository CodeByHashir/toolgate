"""The proxy path must not import the research stack.

`toolgate wrap` is meant to be a drop-in, installed in seconds by `uvx`. That
only holds if the modules it imports reach none of the scientific stack, the
model runtimes or the Anthropic SDK: those are in the `research` extra, so on a
slim install an accidental import is not merely slow, it is a crash at startup.

Each module is imported in a fresh interpreter. Checking `sys.modules` in the
test process itself would prove nothing, because other tests (and pytest
plugins) have long since imported numpy by the time this file runs.

These tests run in both CI jobs: in the research job they show the import graph
is clean even when everything is installed; in the slim job, where the research
dependencies are absent, they also show the proxy path actually loads.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# The design's list (docs/designs: Success Criteria, "Slim install"), plus the
# two other research-extra modules, so moving either back onto the proxy path
# is caught too.
HEAVY_MODULES = (
    "numpy",
    "scipy",
    "sklearn",
    "joblib",
    "torch",
    "transformers",
    "statsmodels",
    "datasketch",
    "anthropic",
    "sentencepiece",
    "pydantic_settings",
)

PROXY_PATH_MODULES = (
    "toolgate",
    "toolgate.config",
    "toolgate.gating",
    "toolgate.gating.tool_calls",
    "toolgate.gating.policy",
    "toolgate.gating.audit",
    "toolgate.gating.content",
    "toolgate.gating.transport",
    "toolgate.detectors",
    "toolgate.detectors.base",
    "toolgate.detectors.rules",
    "toolgate.detectors.pii",
    "toolgate.detectors.normalise",
    "toolgate.cli",
)

# Distribution names the base install may pull in directly. Anything else
# belongs in an extra.
BASE_ALLOWLIST = {"mcp", "pydantic", "pyyaml", "anyio", "platformdirs"}

# Distribution names of the research stack, as uv.lock spells them.
HEAVY_DISTRIBUTIONS = {
    "numpy",
    "scipy",
    "scikit-learn",
    "joblib",
    "torch",
    "transformers",
    "statsmodels",
    "datasketch",
    "anthropic",
    "sentencepiece",
    "pydantic-settings",
}


def _loaded_heavy_modules(module: str) -> list[str]:
    probe = (
        "import sys\n"
        f"import {module}\n"
        f"heavy = {HEAVY_MODULES!r}\n"
        "print(','.join(sorted(m for m in heavy if m in sys.modules)))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, f"import {module} failed:\n{completed.stderr}"
    output = completed.stdout.strip()
    return output.split(",") if output else []


@pytest.mark.parametrize("module", PROXY_PATH_MODULES)
def test_proxy_path_module_loads_no_research_dependency(module: str) -> None:
    assert _loaded_heavy_modules(module) == []


def test_proxy_package_loads_no_research_dependency() -> None:
    """`toolgate.proxy` is the package `toolgate wrap` runs; it is added by a
    separate change, so this test activates once it exists."""
    if importlib.util.find_spec("toolgate.proxy") is None:
        pytest.skip("toolgate.proxy does not exist yet")
    assert _loaded_heavy_modules("toolgate.proxy") == []


def test_base_dependencies_are_the_allowlist() -> None:
    """`uv pip install .` with no extras installs only what the proxy needs."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = {_requirement_name(r) for r in pyproject["project"]["dependencies"]}
    assert names <= BASE_ALLOWLIST, sorted(names - BASE_ALLOWLIST)


def test_base_install_pulls_in_no_research_distribution_transitively() -> None:
    """The allowlist alone is not enough: a base dependency could itself depend
    on numpy. Walk the locked dependency graph from toolgate's base
    requirements (no extras) and check nothing heavy is reachable."""
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    graph: dict[str, set[str]] = {}
    for package in lock["package"]:
        deps = graph.setdefault(package["name"], set())
        deps.update(d["name"] for d in package.get("dependencies", []))
    reachable: set[str] = set()
    frontier = list(graph["toolgate"])
    while frontier:
        name = frontier.pop()
        if name in reachable:
            continue
        reachable.add(name)
        frontier.extend(graph.get(name, ()))
    assert reachable.isdisjoint(HEAVY_DISTRIBUTIONS), sorted(reachable & HEAVY_DISTRIBUTIONS)


def test_research_subcommand_without_the_extra_names_the_extra() -> None:
    """A research subcommand on a slim install says what to install rather than
    ending in a bare ModuleNotFoundError. Simulated by blocking numpy in a fresh
    interpreter, so it is exercised whether or not the extra is installed."""
    probe = (
        "import sys\n"
        "sys.modules['numpy'] = None\n"
        "from toolgate.cli import main\n"
        "raise SystemExit(main(['gauge-recut', '--scores', 'unused.csv']))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 2, completed.stderr
    assert "toolgate[research]" in completed.stderr
    assert "numpy is not installed" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_unrelated_missing_module_is_not_reported_as_the_research_extra() -> None:
    from toolgate.cli import _missing_research_extra

    assert _missing_research_extra(ModuleNotFoundError(name="sklearn.exceptions"))
    assert not _missing_research_extra(ModuleNotFoundError(name="toolgate.nonexistent"))
    assert not _missing_research_extra(ModuleNotFoundError())


def _requirement_name(requirement: str) -> str:
    for separator in ("==", ">=", "<=", "~=", "!=", "<", ">", "[", ";", " "):
        requirement = requirement.split(separator, 1)[0]
    return requirement.strip().lower()
