"""Shared test fixtures.

`light_detectors` is the decision-relevant, weight-free detector set (rules
split by family, PII) -- everything `PolicyEngine.decide` actually reads with
the shipped `config/policy.yaml`. V0 and V3 ship `inert` there (M5):
`PolicyEngine.decide` never looks up a threshold for a key outside
`injection_detectors`/`redaction_detectors`, so an inert detector's result can
never change a decision. Most of the suite can therefore use this fixture
instead of the real `build_detectors(load_policy_config())`, staying fast and
independent of the reused LLMShield weights, which are not published
(`prd.md` A1) and are not present in CI. Tests that specifically need V0/V3 to
be real live in `tests/test_gating_transport_with_models.py`, marked `models`.
"""

from __future__ import annotations

import pytest

from llmshield_mcp.detectors.base import Detector
from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector


@pytest.fixture
def light_detectors() -> dict[str, Detector]:
    return {
        "rules_mcp": RuleDetector(families=frozenset({"mcp"})),
        "rules_inj": RuleDetector(families=frozenset({"inj"})),
        "pii": PiiDetector(),
    }
