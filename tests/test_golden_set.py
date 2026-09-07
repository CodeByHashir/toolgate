"""Golden-set regression test (M4 verification bar).

A small, hand-picked and FROZEN set of tool-result texts with their expected
fused decision, run through the decision-relevant detectors and the shipped
`config/policy.yaml`/`config/rules.yaml`. Unlike `scripts/benchmark_rules.py`
(which measures recall against BIPIA/InjecAgent and must never use
hand-written cases), this file is not a recall claim -- it is a pin on the
*wiring*: rules, PII and the policy engine, exercised together the same way
`Gate.observe_inbound` does, so a future change to fusion, thresholds or the
detector set that silently changes one of these fixed decisions gets caught
here rather than in a live agent run.

This uses `light_detectors` (see `conftest.py`), not the full
`build_detectors(load_policy_config())` -- the shipped policy also ships V0
and V3 `inert` (M5), and `PolicyEngine.decide` provably never reads an inert
detector's result, so including them here would only cost the (unpublished,
CI-absent) model weights for zero effect on `outcome.decision`/`.redacted`.
`tests/test_gating_transport_with_models.py` is where V0/V3 are actually
exercised, against real weights.

`tests/fixtures/golden_set.json` is the fixture. Adding a case is fine;
changing an existing expectation should be a deliberate, reviewed edit, not a
side effect of an unrelated change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from llmshield_mcp.detectors.base import Detector
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.gating.audit import Decision
from llmshield_mcp.gating.policy import PolicyEngine, load_policy_config

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "golden_set.json"


def _load_cases() -> list[dict[str, Any]]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["id"])
def test_golden_case(case: dict[str, Any], light_detectors: dict[str, Detector]) -> None:
    engine = PolicyEngine(load_policy_config())

    results = {
        key: scan_normalised(detector, case["text"]) for key, detector in light_detectors.items()
    }
    outcome = engine.decide(results)

    assert outcome.decision == Decision(case["decision"]), case["id"]
    assert outcome.redacted == case["redacted"], case["id"]


def test_golden_set_is_not_empty() -> None:
    # A fixture that silently became `[]` would make every case above vacuous.
    assert len(_load_cases()) >= 5
