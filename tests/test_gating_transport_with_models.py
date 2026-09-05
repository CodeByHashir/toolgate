"""V0/V3 wired into the live gate, against the real reused weights (M5).

Marked `models`, like `tests/test_adapters_with_models.py`: these need the
LLMShield artifacts on disk (`config/models.yaml`'s `models/`, or
`LLMSHIELD_MODELS_ROOT` pointing at wherever they actually live). They are not
published (`prd.md` A1) and are not present in CI, so this file is deselected
there exactly as the rest of the `models`-marked suite is.

Everything decision-relevant about V0/V3 is already covered without weights:
`tests/test_golden_set.py` and `tests/test_gating_policy.py` prove the shipped
policy (V0/V3 `inert`) never lets them affect a decision, using
`light_detectors`. What can only be proven with the real weights is (a) that
`build_detectors` actually constructs and runs them, and (b) that the
milestone's own verification bar -- "ablation by config alone" -- holds for a
real, graded detector, not just for the binary rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import mcp_types
import pytest
from mcp.shared.message import SessionMessage

from llmshield_mcp.cli import PROBES
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.gating.audit import Decision, DecisionLog
from llmshield_mcp.gating.policy import PolicyEngine, load_policy_config
from llmshield_mcp.gating.transport import Gate, build_detectors

pytestmark = pytest.mark.models


def _call_request(request_id: Any, tool: str = "read_text_file") -> SessionMessage:
    return SessionMessage(
        mcp_types.JSONRPCRequest(
            jsonrpc="2.0",
            id=request_id,
            method="tools/call",
            params={"name": tool, "arguments": {"path": "config_loader.py"}},
        )
    )


def _call_response(request_id: Any, text: str) -> SessionMessage:
    return SessionMessage(
        mcp_types.JSONRPCResponse(
            jsonrpc="2.0",
            id=request_id,
            result={"content": [{"type": "text", "text": text}], "isError": False},
        )
    )


# Benign code that legitimately contains detector trigger words -- the
# false-positive risk PROPOSAL.md section 2 calls out, and the exact text
# docs/POLICY-AUDIT.md section 4.1 measured V0 scoring highly on
# (`not_benign` ~0.94 for this style of content).
BENIGN_TECHNICAL_TEXT = PROBES[1][1]

_ABLATION_POLICY = """
calibrated: false
on_detector_failure: escalate
detectors:
  injection: [rules_mcp, v0]
  redaction: [pii]
  inert: [rules_inj, v3]
thresholds:
  rules_mcp:
    escalate: 1.0
    block: 1.0
  v0:
    escalate: 0.5
  pii:
    redact: 0.7
"""


def test_shipped_default_detectors_include_v0_and_v3_as_inert() -> None:
    config = load_policy_config()
    detectors = build_detectors(config)

    assert "v0" in detectors
    assert "v3" in detectors
    assert "v0" not in config.injection_detectors
    assert "v3" not in config.injection_detectors


def test_v0_and_v3_score_real_text_but_never_escalate() -> None:
    config = load_policy_config()
    detectors = build_detectors(config)
    engine = PolicyEngine(config)

    results = {
        key: scan_normalised(detector, BENIGN_TECHNICAL_TEXT) for key, detector in detectors.items()
    }
    outcome = engine.decide(results)

    assert results["v0"].score is not None
    assert results["v3"].score is not None
    # The documented M3 observation: V0 scores this kind of content highly.
    # Being inert is exactly what stops that from becoming a decision.
    assert results["v0"].score > 0.5
    assert outcome.decision == Decision.ALLOW


def test_v0_and_v3_scores_reach_the_audit_log_through_a_real_gate(
    tmp_path: Path,
) -> None:
    # FR-2/FR-3/FR-8 end to end: a real Gate, a real tool result, and V0/V3's
    # actual scores landing in the decision log -- not just in an in-memory
    # PolicyEngine.decide call.
    log = DecisionLog(tmp_path / "decisions.sqlite")
    gate = Gate("filesystem", log)  # default detectors: the shipped policy, real weights

    gate.observe_outbound(_call_request(1))
    gate.observe_inbound(_call_response(1, BENIGN_TECHNICAL_TEXT))

    row = log.rows()[0]
    scores = json.loads(row["detector_scores"])
    assert scores["v0"] is not None
    assert scores["v3"] is not None
    assert row["fused_decision"] == Decision.ALLOW


def test_shipped_default_does_not_escalate_on_benign_technical_text() -> None:
    config = load_policy_config()
    detectors = build_detectors(config)
    engine = PolicyEngine(config)

    results = {
        key: scan_normalised(detector, BENIGN_TECHNICAL_TEXT) for key, detector in detectors.items()
    }

    assert engine.decide(results).decision == Decision.ALLOW


def test_promoting_v0_to_injection_via_yaml_alone_escalates_the_same_text(
    tmp_path: Path,
) -> None:
    # The milestone's own verification bar: move v0 from `inert` to
    # `injection` and add a threshold, in YAML only -- no code changes -- and
    # the exact same real detector, on the exact same text that just allowed,
    # now escalates.
    policy_path = tmp_path / "policy.ablation.yaml"
    policy_path.write_text(_ABLATION_POLICY, encoding="utf-8")
    config = load_policy_config(policy_path)
    detectors = build_detectors(config)
    engine = PolicyEngine(config)

    results = {
        key: scan_normalised(detector, BENIGN_TECHNICAL_TEXT) for key, detector in detectors.items()
    }

    assert engine.decide(results).decision == Decision.ESCALATE
