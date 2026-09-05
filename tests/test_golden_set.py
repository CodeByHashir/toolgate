"""Golden-set regression test (M4 verification bar).

A small, hand-picked and FROZEN set of tool-result texts with their expected
fused decision, run through the real detector set and the shipped
`config/policy.yaml`/`config/rules.yaml`. Unlike `scripts/benchmark_rules.py`
(which measures recall against BIPIA/InjecAgent and must never use
hand-written cases), this file is not a recall claim -- it is a pin on the
*wiring*: rules, PII and the policy engine, exercised together the same way
`Gate.observe_inbound` does, so a future change to fusion, thresholds or the
detector set that silently changes one of these fixed decisions gets caught
here rather than in a live agent run.

`tests/fixtures/golden_set.json` is the fixture. Adding a case is fine;
changing an existing expectation should be a deliberate, reviewed edit, not a
side effect of an unrelated change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.gating.audit import Decision
from llmshield_mcp.gating.policy import PolicyEngine, load_policy_config
from llmshield_mcp.gating.transport import default_detectors

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "golden_set.json"


def _load_cases() -> list[dict[str, Any]]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["id"])
def test_golden_case(case: dict[str, Any]) -> None:
    detectors = default_detectors()
    engine = PolicyEngine(load_policy_config())

    results = {key: scan_normalised(detector, case["text"]) for key, detector in detectors.items()}
    outcome = engine.decide(results)

    assert outcome.decision == Decision(case["decision"]), case["id"]
    assert outcome.redacted == case["redacted"], case["id"]


def test_golden_set_is_not_empty() -> None:
    # A fixture that silently became `[]` would make every case above vacuous.
    assert len(_load_cases()) >= 5
