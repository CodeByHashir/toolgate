"""Tests for the churn analysis behind `docs/DECLARATION-CHURN.md` (step 5).

The collector itself is a driver like `scripts/benchmark_*.py` and is not unit
tested -- it launches real servers over the network. The *analysis* is a
different matter: its output is a committed document of numbers, and a
miscounted transition would be a published figure that is simply wrong. So the
arithmetic is exercised here against synthetic snapshots whose right answers are
obvious by inspection.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "collect_declarations.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("collect_declarations", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


churn_module = _load()


def tool(
    name: str,
    *,
    description: str = "aaa",
    schema: str = "sss",
    concealed: list[str] | None = None,
    rules_desc: list[str] | None = None,
) -> dict[str, Any]:
    """One measured declaration. Digests stand in for real hashes."""
    fields = {"name": f"n:{name}", "description": f"d:{description}", "input_schema": f"s:{schema}"}
    return {
        "name": name,
        "fields": fields,
        "combined": "|".join(sorted(fields.values())),
        "concealed": concealed or [],
        "description_chars": len(description),
        "schema_chars": len(schema),
        "rules_on_description": rules_desc or [],
        "rules_on_schema": [],
    }


def snapshot(servers: dict[str, list[tuple[str, Any]]]) -> dict[str, Any]:
    return {
        "collected_at": "2026-09-23T00:00:00+00:00",
        "canonicaliser_version": 1,
        "hashed_fields": list(churn_module.HASHED_FIELDS),
        "versions_per_package": 8,
        "servers": {
            name: {
                "package": f"pkg-{name}",
                "ecosystem": "npm",
                "releases": dict(releases),
            }
            for name, releases in servers.items()
        },
    }


# --- churn arithmetic -----------------------------------------------------


def test_an_unchanged_release_counts_no_churn() -> None:
    data = snapshot({"a": [("1.0", {"tools": [tool("x")]}), ("1.1", {"tools": [tool("x")]})]})

    result = churn_module.analyse(data)

    assert result["pooled"].transitions == 1
    assert result["pooled"].tools_compared == 1
    assert result["pooled"].tools_changed == 0


def test_a_changed_description_is_counted_and_the_field_named() -> None:
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x", description="old")]}),
                ("1.1", {"tools": [tool("x", description="new")]}),
            ]
        }
    )

    result = churn_module.analyse(data)

    assert result["pooled"].tools_changed == 1
    assert result["pooled"].field_moves["description"] == 1
    assert result["pooled"].field_moves["input_schema"] == 0


def test_added_and_removed_tools_are_not_counted_as_changes() -> None:
    """They are a different event, and folding them in would inflate churn."""
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x"), tool("gone")]}),
                ("1.1", {"tools": [tool("x"), tool("fresh")]}),
            ]
        }
    )

    result = churn_module.analyse(data)

    assert result["pooled"].tools_compared == 1
    assert result["pooled"].tools_changed == 0
    assert result["pooled"].added == 1
    assert result["pooled"].removed == 1


def test_transitions_are_consecutive_pairs_not_all_pairs() -> None:
    data = snapshot({"a": [(v, {"tools": [tool("x")]}) for v in ("1.0", "1.1", "1.2", "1.3")]})

    assert churn_module.analyse(data)["pooled"].transitions == 3


def test_a_failed_release_is_excluded_from_transitions_and_reported() -> None:
    """A version that will not run is not a version with no churn."""
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x")]}),
                ("1.1", {"error": "would not start"}),
                ("1.2", {"tools": [tool("x")]}),
            ]
        }
    )

    result = churn_module.analyse(data)

    assert result["pooled"].transitions == 1
    assert result["failures"] == ["a@1.1"]


def test_pooling_sums_across_servers() -> None:
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x", description="old")]}),
                ("1.1", {"tools": [tool("x", description="new")]}),
            ],
            "b": [("1.0", {"tools": [tool("y")]}), ("1.1", {"tools": [tool("y")]})],
        }
    )

    result = churn_module.analyse(data)

    assert result["pooled"].transitions == 2
    assert result["pooled"].tools_compared == 2
    assert result["pooled"].tools_changed == 1
    assert result["per_server"]["a"].tools_changed == 1
    assert result["per_server"]["b"].tools_changed == 0


def test_a_single_release_yields_no_transition() -> None:
    data = snapshot({"a": [("1.0", {"tools": [tool("x")]})]})

    assert churn_module.analyse(data)["pooled"].transitions == 0


# --- the other three measurements ----------------------------------------


def test_concealment_is_counted_per_declaration() -> None:
    data = snapshot({"a": [("1.0", {"tools": [tool("x", concealed=["description"]), tool("y")]})]})

    result = churn_module.analyse(data)

    assert result["concealed_total"] == 1
    assert result["tools_total"] == 2


def test_cross_server_collisions_use_the_latest_release_only() -> None:
    data = snapshot(
        {
            "a": [("1.0", {"tools": [tool("read_file")]})],
            "b": [("1.0", {"tools": [tool("read_file")]})],
            "c": [("1.0", {"tools": [tool("unique")]})],
        }
    )

    collisions = churn_module.analyse(data)["collisions"]

    assert collisions == {"read_file": ["a", "b"]}


def test_a_name_reused_across_releases_of_one_server_is_not_a_collision() -> None:
    data = snapshot({"a": [("1.0", {"tools": [tool("x")]}), ("1.1", {"tools": [tool("x")]})]})

    assert churn_module.analyse(data)["collisions"] == {}


def test_rule_hits_on_benign_descriptions_are_counted() -> None:
    data = snapshot(
        {
            "a": [
                (
                    "1.0",
                    {"tools": [tool("x", rules_desc=["MCP-1"]), tool("y")]},
                )
            ]
        }
    )

    result = churn_module.analyse(data)

    assert result["rule_hits_desc"] == 1
    assert result["rule_ids"]["MCP-1"] == 1


# --- the rendered document ------------------------------------------------


def test_the_report_states_its_date_and_the_pooled_rate() -> None:
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x", description="old"), tool("y")]}),
                ("1.1", {"tools": [tool("x", description="new"), tool("y")]}),
            ]
        }
    )

    text = churn_module.render(data, churn_module.analyse(data))

    assert "2026-09-23" in text
    assert "50.0%" in text  # one of two tools changed


def test_the_report_states_that_it_reports_no_recall_number() -> None:
    """Plan 3.2: pinning catches mutation by construction, which is not a result.

    Asserted as the presence of the disclaimer rather than the absence of the
    words. The document has to be free to *discuss* AUROC and recall -- the
    whole point of that paragraph is explaining why neither appears as a
    figure -- so a substring ban would forbid the honest version and permit a
    dishonest one that simply avoided the vocabulary.
    """
    data = snapshot({"a": [("1.0", {"tools": [tool("x")]})]})

    text = churn_module.render(data, churn_module.analyse(data))

    assert "It is not a detection result and no recall number appears here." in text
    assert "by construction" in text


def test_the_report_names_failed_releases_rather_than_hiding_them() -> None:
    data = snapshot(
        {
            "a": [
                ("1.0", {"tools": [tool("x")]}),
                ("1.1", {"error": "boom"}),
            ]
        }
    )

    text = churn_module.render(data, churn_module.analyse(data))

    assert "could not be collected" in text
    assert "`a@1.1`" in text


def test_an_empty_snapshot_renders_without_dividing_by_zero() -> None:
    text = churn_module.render(snapshot({}), churn_module.analyse(snapshot({})))

    assert "n/a" in text


@pytest.mark.parametrize(("num", "den", "expected"), [(1, 2, "50.0%"), (0, 0, "n/a")])
def test_percentage_formatting(num: int, den: int, expected: str) -> None:
    assert churn_module._pct(num, den) == expected
