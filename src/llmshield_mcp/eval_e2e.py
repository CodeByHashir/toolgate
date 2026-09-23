"""End-to-end evaluation of the live gate against real adversarial payloads (M13).

This closes the measurement half of "Gap B": until now every detection number
in this project was computed by calling a detector directly. Nothing had ever
pushed a real adversarial payload through the same `Gate` a live agent session
uses and checked what the *agent-facing frame* looked like afterwards. This
module does that, with no API key, no model and no network.

What is evaluated
-----------------
Each payload is wrapped in a synthetic MCP `tools/call` result (a real
`JSONRPCResponse` frame), fed through `Gate.observe_outbound` /
`observe_inbound` with the real detectors, the real `PolicyEngine` and the real
`DecisionLog`, and three things are recorded: the detector scores, the fused
decision, and the frame the gate forwarded.

The documented contract (`gating/policy.py`, `gating/content.py`,
`config/policy.yaml`, `plan.md` 2.15-2.17) that every call is checked against:

* Precedence BLOCK > ESCALATE > REDACT > ALLOW; max/OR fusion.
* `rules_mcp` >= its `escalate` threshold means an injection hit; PII at or
  above its `redact` threshold means spans to mask. `rules_inj`, `v0`, `v3`
  are inert.
* BLOCK needs an injection hit that exists only after normalisation
  (`normalisation_only`, no offset-valid span) **and** `calibrated: true`.
  With the shipped `calibrated: false` any BLOCK is downgraded to ESCALATE.
* ALLOW and ESCALATE forward the frame unchanged, except that PII spans are
  masked (`[REDACTED:<LABEL>]`) whatever the label, so ESCALATE does **not**
  withhold injection text from the agent.
* BLOCK replaces the whole result with `build_block_result(True)`.

The oracle in `documented_outcome` re-derives the expected decision and
forwarded frame from that contract using only detector output; it does not call
`PolicyEngine`, so a wiring or policy regression shows up as a violation
instead of being echoed back.

Two policy variants are run. `shipped` is `config/policy.yaml` unchanged.
`calibrated_counterfactual` is the same file with only `calibrated` flipped to
true: it is not a shipped configuration and exists to exercise the Block path,
which the shipped policy cannot reach. Results from it say what Block *would*
do, never what the product does.

What this module deliberately does not do
-----------------------------------------
No new detector, no retraining, no policy change, no model or API call. It does
not measure whether an LLM acts on a payload that reaches it; that is a
separate, optional, model-side experiment.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import random
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import mcp_types
from mcp.shared.message import SessionMessage

from llmshield_mcp.chain import ChainRecord
from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.corpus.sources import CACHE, load_adversarial, load_benign, load_llmail_inject
from llmshield_mcp.detectors.base import Detector, DetectorResult, Span
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.detectors.pii import redact
from llmshield_mcp.dilution import build_diluted_text
from llmshield_mcp.gating.audit import Decision, DecisionLog, DecisionRecord, Outcome
from llmshield_mcp.gating.content import build_block_result
from llmshield_mcp.gating.policy import PolicyConfig, PolicyEngine
from llmshield_mcp.gating.transport import Gate
from llmshield_mcp.gauge.stats import wilson_ci

#: Same ratios as `scripts/benchmark_dilution.py`. Filler-word fraction.
DILUTION_RATIOS: tuple[float, ...] = (0.0, 0.5, 0.75, 0.9)

POLICY_SHIPPED = "shipped"
POLICY_COUNTERFACTUAL = "calibrated_counterfactual"

ARM_PLAIN = "plain"
ARM_BASE64 = "base64"
ARM_BENIGN = "benign"

ADVERSARIAL_FAMILIES: tuple[str, ...] = ("bipia", "injecagent", "llmail_inject")

BENIGN_LINE_COUNT = 50
BENIGN_LINE_SEED = 42
BENIGN_LINE_MIN_CHARS = 30

_TOOL_NAME = "read_text_file"


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Payload:
    """One text to be delivered as a tool result."""

    payload_id: str
    family: str
    threat_type: str
    text: str

    @property
    def embedded(self) -> str:
        """The payload as it appears inside a carrier.

        `build_diluted_text` joins words with single spaces at every ratio,
        including 0.0, so this is what "the payload is present" means.
        """
        return " ".join(self.text.split())


def carrier_text(payload: Payload, filler: str, ratio: float) -> str:
    """Embed `payload` in `filler` at `ratio`, using the M12 primitive unchanged."""
    return build_diluted_text(payload.text, filler, ratio, position="middle")


def base64_variant(payload: Payload) -> Payload:
    """The same payload, base64-encoded, as the normaliser's decode path sees it.

    Normalisation appends decoded base64 to the text, so a rule can match on it
    while the original text (the only text with offset-valid spans) has no
    match. That is exactly the `normalisation_only` situation Block exists for.
    """
    blob = base64.b64encode(payload.embedded.encode("utf-8")).decode("ascii")
    return Payload(
        payload_id=f"{payload.payload_id}+b64",
        family=payload.family,
        threat_type=payload.threat_type,
        text=blob,
    )


def counterfactual_policy(shipped: PolicyConfig) -> PolicyConfig:
    """The shipped policy with the calibration ceiling lifted. Nothing else changes."""
    return replace(shipped, calibrated=True)


# ---------------------------------------------------------------------------
# Frames and the capturing log
# ---------------------------------------------------------------------------


class CapturingLog(DecisionLog):
    """A `DecisionLog` that still persists every row but also keeps the last record.

    Lets the harness read back exactly what the gate wrote without re-querying
    the whole table after every call.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.last: DecisionRecord | None = None

    def append(self, record: DecisionRecord) -> None:
        super().append(record)
        self.last = record


def _text_of(result: Mapping[str, Any]) -> str:
    blocks = result.get("content", [])
    parts: list[str] = []
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
    return "\n".join(parts)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


# ---------------------------------------------------------------------------
# The oracle: the documented contract, re-derived from detector output only
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Oracle:
    decision: Decision
    scores: dict[str, float | None]
    rules_fired: tuple[str, ...]
    pii_spans: tuple[Span, ...]
    """Spans the contract says must be masked (empty when nothing qualifies or BLOCK)."""


def _redact_spans(results: Mapping[str, DetectorResult], config: PolicyConfig) -> tuple[Span, ...]:
    spans: list[Span] = []
    for key in sorted(config.redaction_detectors):
        result = results[key]
        if result.score is not None and result.score >= config.threshold(key, "redact"):
            spans.extend(result.spans)
    return tuple(spans)


def documented_outcome(
    text: str, detectors: Mapping[str, Detector], config: PolicyConfig
) -> Oracle:
    """What the contract says must happen to `text`. Does not consult `PolicyEngine`.

    Raises if a decision-relevant detector fails: the evaluation would then be
    measuring the failure path, not the contract, and must not silently continue.
    """
    scanned = text[: config.max_result_chars]
    results = {key: scan_normalised(det, scanned) for key, det in detectors.items()}
    relevant = config.injection_detectors | config.redaction_detectors
    failed = sorted(key for key in relevant if key in results and results[key].failed)
    if failed:
        raise RuntimeError(f"detector(s) failed during evaluation: {', '.join(failed)}")

    hit = False
    block_eligible = False
    for key in sorted(config.injection_detectors):
        score = results[key].score
        if score is None or score < config.threshold(key, "escalate"):
            continue
        hit = True
        if results[key].detail.get("normalisation_only", 0.0) >= 1.0 and score >= config.threshold(
            key, "block"
        ):
            block_eligible = True

    spans = _redact_spans(results, config)
    if block_eligible and config.calibrated:
        decision = Decision.BLOCK
    elif hit:
        decision = Decision.ESCALATE
    elif spans:
        decision = Decision.REDACT
    else:
        decision = Decision.ALLOW

    fired = sorted(
        {
            rule
            for key in config.injection_detectors
            for rule, value in results[key].detail.items()
            if value >= 1.0
        }
    )
    return Oracle(
        decision=decision,
        scores={key: result.score for key, result in results.items()},
        rules_fired=tuple(fired),
        pii_spans=() if decision is Decision.BLOCK else spans,
    )


def contract_violations(
    oracle: Oracle,
    *,
    text: str,
    input_result: Mapping[str, Any],
    input_snapshot: Mapping[str, Any],
    forwarded_result: Mapping[str, Any],
    record: DecisionRecord,
) -> list[str]:
    """Every way the observed gate behaviour departs from the documented contract."""
    found: list[str] = []
    if record.outcome is not Outcome.RESULT:
        found.append(f"outcome {record.outcome.value!r}, expected 'result'")
    if record.detector_scores != oracle.scores:
        found.append("audit-log detector scores differ from an independent re-scan")
    if record.fused_decision is not oracle.decision:
        found.append(
            f"decision {record.fused_decision.value!r}, documented {oracle.decision.value!r}"
        )
    if dict(input_result) != dict(input_snapshot):
        found.append("gate mutated the incoming frame in place")

    expect_redacted = bool(oracle.pii_spans)
    if record.redacted is not expect_redacted:
        found.append(f"redacted={record.redacted}, documented {expect_redacted}")

    if oracle.decision is Decision.BLOCK:
        if dict(forwarded_result) != build_block_result(is_error=True):
            found.append("BLOCK: forwarded result is not the block replacement")
    elif oracle.pii_spans:
        expected = {
            **input_result,
            "content": [{"type": "text", "text": redact(text, oracle.pii_spans)}],
        }
        if dict(forwarded_result) != expected:
            found.append("forwarded frame is not the input with exactly the PII spans masked")
        forwarded_text = _text_of(forwarded_result)
        for span in oracle.pii_spans:
            if text[span.start : span.end] in forwarded_text:
                found.append(f"a {span.label} value survived masking")
    elif dict(forwarded_result) != dict(input_result):
        found.append("frame with nothing to mask was modified")
    return found


def payload_survival(
    embedded: str,
    forwarded_text: str,
    detectors: Mapping[str, Detector],
    config: PolicyConfig,
) -> tuple[bool, bool]:
    """(verbatim, modulo_pii): does the payload text reach the agent?

    `verbatim`: the embedded payload appears unchanged in the forwarded text.
    `modulo_pii`: the payload appears with only the spans the policy masks
    replaced, i.e. the gate removed nothing beyond PII.
    """
    verbatim = embedded in forwarded_text
    results = {key: scan_normalised(det, embedded) for key, det in detectors.items()}
    masked = redact(embedded, _redact_spans(results, config))
    return verbatim, masked in forwarded_text


# ---------------------------------------------------------------------------
# One call, one run
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GateCall:
    """Everything recorded about one payload delivered through the gate."""

    policy: str
    arm: str
    payload_id: str
    family: str
    threat_type: str
    ratio: float
    input_chars: int
    input_sha256: str
    decision: Decision
    detector_scores: dict[str, float | None]
    rules_fired: tuple[str, ...]
    redacted: bool
    forwarded_text: str
    forwarded_sha256: str
    forwarded_identical: bool
    forwarded_is_error: bool
    payload_verbatim: bool | None
    payload_modulo_pii: bool | None
    violations: tuple[str, ...]
    input_text: str = field(repr=False, default="")

    def to_json(self) -> dict[str, Any]:
        """Serialisable form. Text is stored only when the gate changed the frame."""
        row: dict[str, Any] = {
            "policy": self.policy,
            "arm": self.arm,
            "payload_id": self.payload_id,
            "family": self.family,
            "threat_type": self.threat_type,
            "ratio": self.ratio,
            "input_chars": self.input_chars,
            "input_sha256": self.input_sha256,
            "decision": self.decision.value,
            "detector_scores": self.detector_scores,
            "rules_fired": list(self.rules_fired),
            "redacted": self.redacted,
            "forwarded_sha256": self.forwarded_sha256,
            "forwarded_identical": self.forwarded_identical,
            "forwarded_is_error": self.forwarded_is_error,
            "payload_verbatim": self.payload_verbatim,
            "payload_modulo_pii": self.payload_modulo_pii,
            "violations": list(self.violations),
        }
        if not self.forwarded_identical:
            row["forwarded_text"] = self.forwarded_text
        return row


def evaluate_text(
    gate: Gate,
    log: CapturingLog,
    *,
    policy_name: str,
    arm: str,
    payload: Payload,
    ratio: float,
    text: str,
    embedded: str | None,
    detectors: Mapping[str, Detector],
    config: PolicyConfig,
    request_id: int,
) -> GateCall:
    """Deliver `text` as a tool result through `gate` and check it against the contract."""
    request = SessionMessage(
        mcp_types.JSONRPCRequest(
            jsonrpc="2.0",
            id=request_id,
            method="tools/call",
            params={"name": _TOOL_NAME, "arguments": {"path": "eval.txt"}},
        )
    )
    response_message = mcp_types.JSONRPCResponse(
        jsonrpc="2.0",
        id=request_id,
        result={"content": [{"type": "text", "text": text}], "isError": False},
    )
    input_result: dict[str, Any] = response_message.result
    input_snapshot = copy.deepcopy(input_result)

    gate.observe_outbound(request)
    forwarded = gate.observe_inbound(SessionMessage(response_message))
    record = log.last
    if record is None or not isinstance(forwarded, SessionMessage):
        raise RuntimeError("gate produced no decision record for a tools/call result")
    forwarded_message = forwarded.message
    if not isinstance(forwarded_message, mcp_types.JSONRPCResponse):
        raise RuntimeError("gate forwarded something other than a JSON-RPC response")
    forwarded_result: dict[str, Any] = forwarded_message.result
    forwarded_text = _text_of(forwarded_result)

    oracle = documented_outcome(text, detectors, config)
    violations = contract_violations(
        oracle,
        text=text,
        input_result=input_result,
        input_snapshot=input_snapshot,
        forwarded_result=forwarded_result,
        record=record,
    )

    verbatim: bool | None = None
    modulo_pii: bool | None = None
    if embedded is not None:
        verbatim, modulo_pii = payload_survival(embedded, forwarded_text, detectors, config)

    return GateCall(
        policy=policy_name,
        arm=arm,
        payload_id=payload.payload_id,
        family=payload.family,
        threat_type=payload.threat_type,
        ratio=ratio,
        input_chars=len(text),
        input_sha256=_sha256(text),
        decision=record.fused_decision,
        detector_scores={
            key: float(value) if isinstance(value, int | float) else None
            for key, value in record.detector_scores.items()
        },
        rules_fired=oracle.rules_fired,
        redacted=record.redacted,
        forwarded_text=forwarded_text,
        forwarded_sha256=_sha256(forwarded_text),
        forwarded_identical=forwarded_result == input_snapshot,
        forwarded_is_error=bool(forwarded_result.get("isError")),
        payload_verbatim=verbatim,
        payload_modulo_pii=modulo_pii,
        violations=tuple(violations),
        input_text=text,
    )


@dataclass(frozen=True, slots=True)
class EvaluationRun:
    calls: tuple[GateCall, ...]
    audit: dict[str, dict[str, Any]]
    """Per policy: how many rows the SQLite audit log holds and whether they
    match the decisions the harness captured."""


class _PolicySession:
    """One `Gate` and one audit log for one policy variant."""

    def __init__(
        self,
        policy_name: str,
        config: PolicyConfig,
        detectors: Mapping[str, Detector],
        log_path: Path,
    ) -> None:
        self.policy_name = policy_name
        self.config = config
        self.detectors = detectors
        self.log = CapturingLog(log_path)
        self.gate = Gate(
            f"e2e-{policy_name}", self.log, policy=PolicyEngine(config), detectors=detectors
        )
        self.calls: list[GateCall] = []

    def deliver(
        self, arm: str, payload: Payload, ratio: float, text: str, embedded: str | None
    ) -> None:
        self.calls.append(
            evaluate_text(
                self.gate,
                self.log,
                policy_name=self.policy_name,
                arm=arm,
                payload=payload,
                ratio=ratio,
                text=text,
                embedded=embedded,
                detectors=self.detectors,
                config=self.config,
                request_id=len(self.calls) + 1,
            )
        )

    def close(self) -> dict[str, Any]:
        rows = self.log.rows()
        report = {
            "rows": len(rows),
            "calls": len(self.calls),
            "matches": [row["fused_decision"] for row in rows]
            == [call.decision.value for call in self.calls],
        }
        self.log.close()
        return report


def run_evaluation(
    *,
    adversarial: Sequence[Payload],
    benign: Sequence[Payload],
    detectors: Mapping[str, Detector],
    policies: Mapping[str, PolicyConfig],
    filler: str,
    log_dir: Path,
    ratios: Sequence[float] = DILUTION_RATIOS,
) -> EvaluationRun:
    """Run every payload through a real `Gate` under each policy variant.

    Arms: `plain` (each payload at every ratio), `base64` (payloads that
    `rules_mcp` detects in the clear, encoded, isolated only), `benign`
    (recorded tool results and repository lines, unmodified).
    """
    if "rules_mcp" not in detectors:
        raise ValueError("detectors must include 'rules_mcp'")
    log_dir.mkdir(parents=True, exist_ok=True)

    detected = [
        p
        for p in adversarial
        if (scan_normalised(detectors["rules_mcp"], p.embedded).score or 0.0) > 0.0
    ]
    encoded = [base64_variant(p) for p in detected]

    calls: list[GateCall] = []
    audit: dict[str, dict[str, Any]] = {}
    for policy_name, config in policies.items():
        path = log_dir / f"{policy_name}.sqlite"
        path.unlink(missing_ok=True)
        session = _PolicySession(policy_name, config, detectors, path)

        for payload in adversarial:
            for ratio in ratios:
                text = carrier_text(payload, filler, ratio)
                session.deliver(ARM_PLAIN, payload, ratio, text, payload.embedded)
        for payload in encoded:
            session.deliver(
                ARM_BASE64, payload, 0.0, carrier_text(payload, filler, 0.0), payload.embedded
            )
        for payload in benign:
            session.deliver(ARM_BENIGN, payload, 0.0, payload.text, None)

        audit[policy_name] = session.close()
        calls.extend(session.calls)

    return EvaluationRun(calls=tuple(calls), audit=audit)


# ---------------------------------------------------------------------------
# Corpus assembly and manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CorpusBundle:
    adversarial: tuple[Payload, ...]
    benign: tuple[Payload, ...]
    manifest: dict[str, Any]
    missing_families: tuple[str, ...]


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample_benign_lines(
    lines: Sequence[str], n: int = BENIGN_LINE_COUNT, seed: int = BENIGN_LINE_SEED
) -> tuple[list[str], dict[str, Any]]:
    """Seeded sample from a sorted, de-duplicated pool, so it is order-independent."""
    pool = sorted({ln for ln in lines if len(ln) >= BENIGN_LINE_MIN_CHARS})
    sample = random.Random(seed).sample(pool, min(n, len(pool)))
    return sample, {
        "pool_size": len(pool),
        "seed": seed,
        "sample_sha256": _sha256("\n".join(sample)),
    }


def load_corpus(
    *,
    adversarial_loader: Callable[[], list[tuple[str, str, str]]] = load_adversarial,
    llmail_loader: Callable[[], list[tuple[str, str, str]]] = load_llmail_inject,
    benign_line_loader: Callable[[], list[str]] = load_benign,
    chain_dir: Path = REPO_ROOT / "chains",
    cache_dir: Path = CACHE,
    benign_lines: int = BENIGN_LINE_COUNT,
) -> CorpusBundle:
    """Assemble the adversarial and benign inputs and a manifest that pins them.

    A missing LLMail-Inject cache is reported in `missing_families` rather than
    silently producing an empty family.
    """
    counters: Counter[str] = Counter()
    adversarial: list[Payload] = []
    raw = list(adversarial_loader()) + list(llmail_loader())
    for family, threat_type, text in raw:
        adversarial.append(Payload(f"{family}/{counters[family]:03d}", family, threat_type, text))
        counters[family] += 1
    missing = tuple(f for f in ADVERSARIAL_FAMILIES if counters[f] == 0)

    benign: list[Payload] = []
    seen: set[str] = set()
    chain_files = sorted(chain_dir.glob("*.json"))
    for chain_path in chain_files:
        for call in ChainRecord.read(chain_path).calls:
            if call.result_text and call.result_text not in seen:
                seen.add(call.result_text)
                benign.append(
                    Payload(
                        f"benign_chain/{len(benign):03d}",
                        "benign_chain",
                        "benign",
                        call.result_text,
                    )
                )
    n_chain = len(benign)
    lines, line_info = sample_benign_lines(benign_line_loader(), n=benign_lines)
    for index, line in enumerate(lines):
        benign.append(Payload(f"benign_lines/{index:03d}", "benign_lines", "benign", line))

    manifest: dict[str, Any] = {
        "adversarial_counts": {family: counters[family] for family in ADVERSARIAL_FAMILIES},
        "benign_counts": {"benign_chain": n_chain, "benign_lines": len(lines)},
        "benign_lines": line_info,
        "corpus_files": {
            path.name: _file_sha256(path)
            for path in sorted(cache_dir.glob("*"))
            if path.is_file() and path.suffix in {".json", ".jsonl"}
        },
        "chain_files": {path.name: _file_sha256(path) for path in chain_files},
        "config_files": {
            name: _file_sha256(REPO_ROOT / "config" / name)
            for name in ("policy.yaml", "rules.yaml")
        },
    }
    return CorpusBundle(tuple(adversarial), tuple(benign), manifest, missing)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _rate(k: int, n: int) -> dict[str, Any]:
    interval = wilson_ci(k, n)
    return {
        "k": k,
        "n": n,
        "rate": None if n == 0 else interval.point,
        "ci95": None if n == 0 else [interval.low, interval.high],
    }


def _cell(calls: Sequence[GateCall]) -> dict[str, Any]:
    n = len(calls)
    counts = {d.value: sum(1 for c in calls if c.decision is d) for d in Decision}
    survive = [c for c in calls if c.payload_verbatim is not None]
    return {
        "n": n,
        "decisions": counts,
        "injection_flag": _rate(counts["escalate"] + counts["block"], n),
        "mcp_recall": _rate(
            sum(1 for c in calls if (c.detector_scores.get("rules_mcp") or 0.0) > 0.0), n
        ),
        "any_action": _rate(n - counts["allow"], n),
        "frames_redacted": _rate(sum(1 for c in calls if c.redacted), n),
        "payload_verbatim": _rate(sum(1 for c in survive if c.payload_verbatim), len(survive)),
        "payload_modulo_pii": _rate(sum(1 for c in survive if c.payload_modulo_pii), len(survive)),
        "forwarded_identical": _rate(sum(1 for c in calls if c.forwarded_identical), n),
        "contract_violations": sum(1 for c in calls if c.violations),
    }


def summarise(calls: Sequence[GateCall]) -> dict[str, Any]:
    """Cells keyed policy -> arm -> ratio -> family (plus `all`)."""
    out: dict[str, Any] = {}
    for policy in sorted({c.policy for c in calls}):
        out[policy] = {}
        for arm in sorted({c.arm for c in calls if c.policy == policy}):
            subset = [c for c in calls if c.policy == policy and c.arm == arm]
            arm_out: dict[str, Any] = {}
            for ratio in sorted({c.ratio for c in subset}):
                at_ratio = [c for c in subset if c.ratio == ratio]
                cells = {"all": _cell(at_ratio)}
                for family in sorted({c.family for c in at_ratio}):
                    cells[family] = _cell([c for c in at_ratio if c.family == family])
                arm_out[f"{ratio:.2f}"] = cells
            out[policy][arm] = arm_out
    return out


def rule_hits(calls: Sequence[GateCall], policy: str = POLICY_SHIPPED) -> dict[str, dict[str, Any]]:
    """Per family, at ratio 0.0 in the plain arm: which MCP-* rules fired how often."""
    out: dict[str, dict[str, Any]] = {}
    isolated = [c for c in calls if c.policy == policy and c.arm == ARM_PLAIN and c.ratio == 0.0]
    for family in sorted({c.family for c in isolated}):
        members = [c for c in isolated if c.family == family]
        counter = Counter(rule for c in members for rule in c.rules_fired)
        by_type: dict[str, list[int]] = {}
        for c in members:
            k_n = by_type.setdefault(c.threat_type, [0, 0])
            k_n[0] += 1 if (c.detector_scores.get("rules_mcp") or 0.0) > 0.0 else 0
            k_n[1] += 1
        out[family] = {"rules": dict(sorted(counter.items())), "by_threat_type": by_type}
    return out


def raw_isolated_recall(
    adversarial: Sequence[Payload], detector: Detector
) -> dict[str, dict[str, Any]]:
    """`detector` recall on each payload exactly as loaded (no whitespace joining).

    A control: the gate evaluation embeds payloads word-joined, as the M12
    dilution benchmark does, so this shows whether that changed any verdict.
    """
    out: dict[str, dict[str, Any]] = {}
    for family in sorted({p.family for p in adversarial}):
        members = [p for p in adversarial if p.family == family]
        hits = sum(1 for p in members if (scan_normalised(detector, p.text).score or 0.0) > 0.0)
        out[family] = _rate(hits, len(members))
    return out


def results_digest(calls: Sequence[GateCall], *, exclude_families: Sequence[str] = ()) -> str:
    """Hash of every deterministic per-call field, for run-to-run comparison.

    `exclude_families` exists because the repository-line benign sample is drawn
    from files this repository edits (`corpus.sources.load_benign`), so its
    digest legitimately moves when docs change. The remaining inputs are pinned
    by the manifest.
    """
    rows = [
        [
            c.policy,
            c.arm,
            c.payload_id,
            c.ratio,
            c.decision.value,
            sorted(c.detector_scores.items()),
            c.forwarded_sha256,
            c.redacted,
        ]
        for c in calls
        if c.family not in exclude_families
    ]
    return _sha256(json.dumps(rows, sort_keys=True))
