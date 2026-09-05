"""Fusion and policy engine (FR-4, FR-5, FR-6, FR-7, FR-9).

Turns a bundle of named `DetectorResult`s into exactly one `Decision`. The
fusion rule is max/OR, never weighted-linear averaging: `plan.md` 2.15 records
why -- the four detectors are near-orthogonal (Jaccard 0.00-0.09) and none
exceeds 20.3% recall, so averaging them at ~0.3 weight each could never cross
a useful threshold. Each detector's own per-action threshold decides whether
IT fires; any firing detector in a role is enough.

Two roles, kept structurally separate rather than mixed into one weighted
score:

* `injection` detectors decide Escalate/Block. In M4 this is `rules_mcp`
  only -- V0 and V3 join in M5 (`plan.md` milestone table).
* `redaction` detectors (`pii`) decide which spans get masked. This is
  independent of the injection decision: PII carries zero injection weight
  (its apparent recall in the pre-M3b audit was an InjecAgent benchmark
  artefact), so a PII match can never by itself produce anything stronger
  than Redact, and a PII match found alongside an Escalate-worthy injection
  signal still gets its spans masked even though the louder label wins.

`inert` detectors (`rules_inj`) are scored and logged so the 0.0% transfer
finding stays visible every run, and never consulted here at all.

`calibrated: false` in `config/policy.yaml` is enforced as a hard ceiling:
`_ceiling` downgrades any BLOCK to ESCALATE whenever it is false, regardless
of which code path produced the BLOCK (a fired detector or a failed one).
FR-11 requires matched-FPR calibration on this surface before Block is safe;
an inherited or guessed threshold would invalidate the cross-surface
comparison the project exists to make.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.detectors.base import DetectorResult, Span
from llmshield_mcp.gating.audit import Decision, Outcome

DEFAULT_POLICY_PATH = REPO_ROOT / "config" / "policy.yaml"

#: The only fail-closed choices SEC-6 permits. "allow" would make a crashed
#: detector indistinguishable from a clean scan; "redact" implies spans that a
#: failed detector never produced.
VALID_FAILURE_DECISIONS = frozenset({Decision.ESCALATE, Decision.BLOCK})


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    calibrated: bool
    on_detector_failure: Decision
    injection_detectors: frozenset[str]
    redaction_detectors: frozenset[str]
    inert_detectors: frozenset[str]
    #: detector key -> action name -> threshold in [0, 1].
    thresholds: dict[str, dict[str, float]]
    max_result_chars: int

    def threshold(self, detector_key: str, action: str, default: float = 1.0) -> float:
        return self.thresholds.get(detector_key, {}).get(action, default)


@dataclass(frozen=True, slots=True)
class FusionOutcome:
    """Exactly one decision (FR-4), plus what it takes to act on it."""

    decision: Decision
    outcome: Outcome
    #: True when `redact_spans` should be masked in the content actually
    #: forwarded, independent of what `decision` says. Always False for BLOCK,
    #: since the whole result is replaced and per-span masking is moot.
    redacted: bool
    redact_spans: tuple[Span, ...]
    note: str | None = None


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise KeyError(f"missing required key '{key}' in {where}")
    return mapping[key]


def load_policy_config(path: Path | None = None) -> PolicyConfig:
    """Read and validate the policy configuration.

    Validation is strict and happens here, not on first decision, so a typo
    fails at startup rather than partway through a gated session.
    """
    policy_path = path or DEFAULT_POLICY_PATH
    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{policy_path} did not parse to a mapping")

    on_failure_raw = raw.get("on_detector_failure", "escalate")
    try:
        on_failure = Decision(on_failure_raw)
    except ValueError as exc:
        raise ValueError(
            f"{policy_path}: on_detector_failure {on_failure_raw!r} is not a valid decision"
        ) from exc
    if on_failure not in VALID_FAILURE_DECISIONS:
        raise ValueError(
            f"{policy_path}: on_detector_failure must be one of "
            f"{sorted(d.value for d in VALID_FAILURE_DECISIONS)} (SEC-6), got {on_failure.value!r}"
        )

    detectors_raw = raw.get("detectors", {})
    if not isinstance(detectors_raw, dict):
        raise ValueError(f"{policy_path}: detectors must be a mapping")

    thresholds_raw = raw.get("thresholds", {})
    if not isinstance(thresholds_raw, dict):
        raise ValueError(f"{policy_path}: thresholds must be a mapping")
    thresholds: dict[str, dict[str, float]] = {}
    for key, actions in thresholds_raw.items():
        if not isinstance(actions, dict):
            raise ValueError(f"{policy_path}: thresholds.{key} must be a mapping")
        parsed: dict[str, float] = {}
        for action, value in actions.items():
            score = float(value)
            if not 0.0 <= score <= 1.0:
                raise ValueError(
                    f"{policy_path}: thresholds.{key}.{action} = {score} outside [0, 1]"
                )
            parsed[str(action)] = score
        thresholds[key] = parsed

    gate_raw = raw.get("gate", {})
    if not isinstance(gate_raw, dict):
        raise ValueError(f"{policy_path}: gate must be a mapping")
    max_result_chars = int(gate_raw.get("max_result_chars", 200_000))
    if max_result_chars < 1:
        raise ValueError(f"{policy_path}: gate.max_result_chars must be at least 1")

    return PolicyConfig(
        calibrated=bool(raw.get("calibrated", False)),
        on_detector_failure=on_failure,
        injection_detectors=frozenset(detectors_raw.get("injection") or ()),
        redaction_detectors=frozenset(detectors_raw.get("redaction") or ()),
        inert_detectors=frozenset(detectors_raw.get("inert") or ()),
        thresholds=thresholds,
        max_result_chars=max_result_chars,
    )


class PolicyEngine:
    """Fuses detector results into one decision, per `PolicyConfig`."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def _ceiling(self, decision: Decision) -> Decision:
        """Enforce FR-11: BLOCK is unreachable until `calibrated: true`."""
        if decision is Decision.BLOCK and not self.config.calibrated:
            return Decision.ESCALATE
        return decision

    def decide(self, results: Mapping[str, DetectorResult]) -> FusionOutcome:
        cfg = self.config

        # SEC-6: a detector this decision actually depends on that raised is
        # "no opinion", never a silent benign vote. Sorted so the note (and
        # any test asserting its wording) is deterministic.
        decision_relevant = cfg.injection_detectors | cfg.redaction_detectors
        failed = sorted(key for key in decision_relevant if key in results and results[key].failed)
        if failed:
            return FusionOutcome(
                decision=self._ceiling(cfg.on_detector_failure),
                outcome=Outcome.DETECTOR_FAILURE,
                redacted=False,
                redact_spans=(),
                note=f"detector(s) failed: {', '.join(failed)}",
            )

        redact_spans = self._redact_spans(results)
        injection_hit, block_eligible = self._injection_signal(results)

        if block_eligible:
            decision = Decision.BLOCK
        elif injection_hit:
            decision = Decision.ESCALATE
        elif redact_spans:
            decision = Decision.REDACT
        else:
            decision = Decision.ALLOW
        decision = self._ceiling(decision)

        return FusionOutcome(
            decision=decision,
            outcome=Outcome.RESULT,
            redacted=bool(redact_spans) and decision is not Decision.BLOCK,
            redact_spans=redact_spans,
            note=None,
        )

    def _redact_spans(self, results: Mapping[str, DetectorResult]) -> tuple[Span, ...]:
        spans: list[Span] = []
        for key in self.config.redaction_detectors:
            result = results.get(key)
            if result is None or result.score is None:
                continue
            if result.score >= self.config.threshold(key, "redact"):
                spans.extend(result.spans)
        return tuple(spans)

    def _injection_signal(self, results: Mapping[str, DetectorResult]) -> tuple[bool, bool]:
        """Return (any detector escalate-worthy, any detector block-eligible)."""
        injection_hit = False
        block_eligible = False
        for key in self.config.injection_detectors:
            result = results.get(key)
            if result is None or result.score is None:
                continue
            if result.score >= self.config.threshold(key, "escalate"):
                injection_hit = True
                # Block is reserved for detections normalisation exposed but
                # that cannot be pinpointed in the original text
                # (detail["normalisation_only"], detectors/normalise.py) --
                # Redact would mask the wrong region. `_ceiling` still applies
                # on top of this, so it is inert until calibrated: true.
                if result.detail.get(
                    "normalisation_only", 0.0
                ) >= 1.0 and result.score >= self.config.threshold(key, "block"):
                    block_eligible = True
        return injection_hit, block_eligible


__all__ = [
    "DEFAULT_POLICY_PATH",
    "FusionOutcome",
    "PolicyConfig",
    "PolicyEngine",
    "load_policy_config",
]
