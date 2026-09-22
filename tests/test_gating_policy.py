"""Table-driven tests for the fusion and policy engine (FR-4, FR-5, FR-9).

`PolicyEngine.decide` is pure -- no I/O, no gate, no MCP frames -- so every
case here is a `dict[str, DetectorResult]` in, a `FusionOutcome` out. That is
deliberate: fusion correctness should be provable without touching the
transport layer at all.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.detectors.base import DetectorResult, Span
from llmshield_mcp.gating.audit import Decision, Outcome
from llmshield_mcp.gating.policy import PolicyConfig, PolicyEngine, load_policy_config


def _result(
    score: float | None,
    detail: dict[str, float] | None = None,
    spans: tuple[Span, ...] = (),
    error: str | None = None,
) -> DetectorResult:
    return DetectorResult(
        detector="x",
        score=score,
        detail=detail or {},
        spans=spans,
        latency_ms=0.0,
        truncated=False,
        error=error,
    )


CLEAN = _result(0.0)

BASE_CONFIG = PolicyConfig(
    calibrated=False,
    on_detector_failure=Decision.ESCALATE,
    injection_detectors=frozenset({"rules_mcp"}),
    redaction_detectors=frozenset({"pii"}),
    inert_detectors=frozenset({"rules_inj"}),
    thresholds={
        "rules_mcp": {"escalate": 1.0, "block": 1.0},
        "pii": {"redact": 0.7},
    },
    max_result_chars=200_000,
)

CALIBRATED_CONFIG = dataclasses.replace(BASE_CONFIG, calibrated=True)


# --- the decision table ----------------------------------------------------


@pytest.mark.parametrize(
    ("results", "config", "expected"),
    [
        pytest.param(
            {"rules_mcp": CLEAN, "pii": CLEAN},
            BASE_CONFIG,
            Decision.ALLOW,
            id="nothing-fires",
        ),
        pytest.param(
            {"rules_mcp": _result(1.0), "pii": CLEAN},
            BASE_CONFIG,
            Decision.ESCALATE,
            id="mcp-rule-fires-escalates-by-default",
        ),
        pytest.param(
            {"rules_mcp": CLEAN, "pii": _result(0.85, spans=(Span(0, 5, "EMAIL_ADDRESS"),))},
            BASE_CONFIG,
            Decision.REDACT,
            id="pii-alone-redacts",
        ),
        pytest.param(
            {"rules_mcp": CLEAN, "pii": _result(0.5, spans=(Span(0, 5, "EMAIL_ADDRESS"),))},
            BASE_CONFIG,
            Decision.ALLOW,
            id="pii-below-its-threshold-does-not-redact",
        ),
        pytest.param(
            {"rules_mcp": _result(1.0, detail={"normalisation_only": 1.0}), "pii": CLEAN},
            BASE_CONFIG,
            Decision.ESCALATE,
            id="block-eligible-but-uncalibrated-downgrades-to-escalate",
        ),
        pytest.param(
            {"rules_mcp": _result(1.0, detail={"normalisation_only": 1.0}), "pii": CLEAN},
            CALIBRATED_CONFIG,
            Decision.BLOCK,
            id="block-eligible-and-calibrated-blocks",
        ),
        pytest.param(
            {"rules_mcp": _result(1.0), "pii": CLEAN},
            CALIBRATED_CONFIG,
            Decision.ESCALATE,
            id="calibration-alone-is-not-enough-without-normalisation_only",
        ),
        pytest.param(
            {"rules_mcp": _result(1.0), "pii": _result(0.85, spans=(Span(0, 5, "E"),))},
            BASE_CONFIG,
            Decision.ESCALATE,
            id="escalate-outranks-redact-as-the-decision-label",
        ),
        pytest.param(
            {"rules_inj": _result(1.0), "rules_mcp": CLEAN, "pii": CLEAN},
            BASE_CONFIG,
            Decision.ALLOW,
            id="inert-detector-firing-changes-nothing",
        ),
    ],
)
def test_decision_table(
    results: dict[str, DetectorResult], config: PolicyConfig, expected: Decision
) -> None:
    assert PolicyEngine(config).decide(results).decision == expected


def test_redacted_flag_is_independent_of_which_decision_label_wins() -> None:
    # Plan.md 2.15: PII is not an injection signal, so its spans get masked
    # even when a louder injection signal wins the decision label.
    span = Span(0, 5, "EMAIL_ADDRESS")
    outcome = PolicyEngine(BASE_CONFIG).decide(
        {"rules_mcp": _result(1.0), "pii": _result(0.85, spans=(span,))}
    )

    assert outcome.decision == Decision.ESCALATE
    assert outcome.redacted is True
    assert outcome.redact_spans == (span,)


def test_block_never_carries_a_redacted_flag() -> None:
    # BLOCK replaces the whole result, so per-span masking is moot.
    outcome = PolicyEngine(CALIBRATED_CONFIG).decide(
        {
            "rules_mcp": _result(1.0, detail={"normalisation_only": 1.0}),
            "pii": _result(0.85, spans=(Span(0, 5, "EMAIL_ADDRESS"),)),
        }
    )

    assert outcome.decision == Decision.BLOCK
    assert outcome.redacted is False


# --- SEC-6: detector failure is fail-closed, never a benign vote -----------


def test_failed_injection_detector_is_fail_closed() -> None:
    failed = _result(None, error="RuntimeError: boom")
    outcome = PolicyEngine(BASE_CONFIG).decide({"rules_mcp": failed, "pii": CLEAN})

    assert outcome.decision == Decision.ESCALATE
    assert outcome.outcome == Outcome.DETECTOR_FAILURE
    assert outcome.note is not None
    assert "rules_mcp" in outcome.note


def test_failed_redaction_detector_is_also_fail_closed() -> None:
    failed = _result(None, error="RuntimeError: boom")
    outcome = PolicyEngine(BASE_CONFIG).decide({"rules_mcp": CLEAN, "pii": failed})

    assert outcome.outcome == Outcome.DETECTOR_FAILURE
    assert outcome.decision == Decision.ESCALATE


def test_a_failed_inert_detector_does_not_trigger_fail_closed() -> None:
    # rules_inj is scored-but-inert; its failure carries no decision weight
    # either, by symmetry with its score never mattering.
    failed = _result(None, error="RuntimeError: boom")
    outcome = PolicyEngine(BASE_CONFIG).decide(
        {"rules_inj": failed, "rules_mcp": CLEAN, "pii": CLEAN}
    )

    assert outcome.outcome == Outcome.RESULT
    assert outcome.decision == Decision.ALLOW


def test_on_detector_failure_block_is_also_downgraded_while_uncalibrated() -> None:
    config = dataclasses.replace(BASE_CONFIG, on_detector_failure=Decision.BLOCK)
    outcome = PolicyEngine(config).decide({"rules_mcp": _result(None, error="boom"), "pii": CLEAN})

    assert outcome.decision == Decision.ESCALATE


# --- FR-9: policy is configuration, not code --------------------------------


_POLICY_TEMPLATE = """
calibrated: false
on_detector_failure: escalate
detectors:
  injection: [rules_mcp]
  redaction: [pii]
  inert: [rules_inj]
thresholds:
  rules_mcp:
    escalate: {escalate_threshold}
    block: 1.0
  pii:
    redact: 0.7
"""


def test_changing_a_threshold_in_the_policy_file_flips_the_decision(tmp_path: Path) -> None:
    # PolicyEngine's threshold mechanism is generic (it will carry V0/V3's
    # graded scores in M5); a synthetic 0.6 score exercises that mechanism
    # directly, since the real MCP-* rules are binary today.
    strict_path = tmp_path / "strict.yaml"
    strict_path.write_text(_POLICY_TEMPLATE.format(escalate_threshold=1.0), encoding="utf-8")
    lenient_path = tmp_path / "lenient.yaml"
    lenient_path.write_text(_POLICY_TEMPLATE.format(escalate_threshold=0.5), encoding="utf-8")

    maybe = _result(0.6)

    strict_engine = PolicyEngine(load_policy_config(strict_path))
    assert strict_engine.decide({"rules_mcp": maybe, "pii": CLEAN}).decision == Decision.ALLOW

    # Same score, same code -- only the YAML changed.
    lenient_engine = PolicyEngine(load_policy_config(lenient_path))
    assert lenient_engine.decide({"rules_mcp": maybe, "pii": CLEAN}).decision == Decision.ESCALATE


def test_shipped_policy_file_loads_uncalibrated() -> None:
    config = load_policy_config()

    assert config.calibrated is False
    assert config.injection_detectors == frozenset({"rules_mcp"})
    assert config.redaction_detectors == frozenset({"pii"})
    # The default profile is the light path: no v0/v3, so no torch import and
    # no DeBERTa forward pass per tool result. They live in the research
    # profile instead -- see config/policy.yaml's header.
    assert config.inert_detectors == frozenset({"rules_inj"})
    assert config.on_detector_failure == Decision.ESCALATE


PROFILES = ("policy.guard.yaml", "policy.research.yaml")


@pytest.mark.parametrize("profile", PROFILES)
def test_profiles_differ_from_the_default_only_in_inert_detectors(profile: str) -> None:
    """Every profile split must be decision-neutral, not a policy change.

    Anything other than the `inert` list differing between the files would mean
    picking a profile could change an Allow/Redact/Block/Escalate, which is
    exactly what the split promises it cannot do.
    """
    default = load_policy_config()
    other = load_policy_config(REPO_ROOT / "config" / profile)

    assert other.injection_detectors == default.injection_detectors
    assert other.redaction_detectors == default.redaction_detectors
    assert other.calibrated == default.calibrated
    assert other.on_detector_failure == default.on_detector_failure
    assert other.thresholds == default.thresholds
    assert other.max_result_chars == default.max_result_chars


def test_each_profile_names_the_detectors_it_advertises() -> None:
    guard = load_policy_config(REPO_ROOT / "config" / "policy.guard.yaml")
    research = load_policy_config(REPO_ROOT / "config" / "policy.research.yaml")

    assert guard.inert_detectors == frozenset({"rules_inj", "guard"})
    assert research.inert_detectors == frozenset({"rules_inj", "v0", "v3", "guard"})


def test_guard_profile_needs_no_unpublishable_artifact() -> None:
    """The point of this profile: a stranger can run it after a clone.

    v0/v3 are configured by local path because their weights are not
    publishable; if either appeared here that property would be gone.
    """
    guard = load_policy_config(REPO_ROOT / "config" / "policy.guard.yaml")

    every_role = guard.injection_detectors | guard.redaction_detectors | guard.inert_detectors
    assert "v0" not in every_role
    assert "v3" not in every_role


@pytest.mark.parametrize("profile", PROFILES)
def test_no_profile_is_calibrated(profile: str) -> None:
    """Adding a classifier must not smuggle in a Block-capable configuration."""
    engine = PolicyEngine(load_policy_config(REPO_ROOT / "config" / profile))

    fired = DetectorResult(
        detector="rules",
        score=1.0,
        detail={"normalisation_only": 1.0},
        spans=(),
        latency_ms=0.1,
        truncated=False,
        error=None,
    )
    assert engine.decide({"rules_mcp": fired}).decision == Decision.ESCALATE


def test_neither_profile_lets_an_inert_detector_reach_a_decision() -> None:
    """v0/v3 firing at full confidence changes nothing in either profile."""
    screaming = DetectorResult(
        detector="v3",
        score=1.0,
        detail={},
        spans=(),
        latency_ms=1.0,
        truncated=False,
        error=None,
    )
    for path in [None, *(REPO_ROOT / "config" / p for p in PROFILES)]:
        engine = PolicyEngine(load_policy_config(path))
        outcome = engine.decide({"v0": screaming, "v3": screaming, "guard": screaming})
        assert outcome.decision == Decision.ALLOW, path


def test_on_detector_failure_allow_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("on_detector_failure: allow\n", encoding="utf-8")

    with pytest.raises(ValueError, match="SEC-6"):
        load_policy_config(bad)


def test_threshold_outside_unit_interval_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("thresholds:\n  rules_mcp:\n    escalate: 1.5\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"outside \[0, 1\]"):
        load_policy_config(bad)


def test_unparseable_policy_file_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "policy.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(ValueError, match="did not parse to a mapping"):
        load_policy_config(bad)
