"""The GAUGE harness (FR-11, FR-12, NFR-6, NFR-7).

Runs the workflow `PROPOSAL.md` section 8.2 describes:

1. Load the clean (decontaminated) corpus M6 produced.
2. Split the benign pool into the two references PROPOSAL.md names --
   realistic and adversarial-styled (`gauge/references.py`) -- and each of
   those 50/50 into calibration/test.
3. Calibrate each graded detector (V0, V3) against each reference's
   calibration split, at each of `config/policy.yaml`'s `fpr_budget` values.
4. Evaluate on the held-out adversarial items: attack-success-rate by threat
   type AND by source family (FR-12, M8 -- see below), achieved FPR on the
   held-out benign test split, DeLong AUROC -- every figure with a
   confidence interval (NFR-7).
5. Write `scores.csv` (`plan.md` section 2.6): every item, every detector,
   raw score plus the four class probabilities where they exist. Because the
   reused weights are not published (`prd.md` A1), this file -- not the
   models -- is what every downstream statistic must be recomputable from.

**FR-12, leave-one-source-out, and why it is a report breakdown rather than a
retraining loop.** The dissertation's own leave-one-out protocol
(`exp2_lobo.py`) retrains a classifier with and without each benchmark family
and compares the two. This project never retrains V0/V3 (`prd.md` scope), so
there is no IN/OUT training distinction to make, and no meaningful sense in
which a family could be "held out" of a training set that was never built
from this corpus at all (`plan.md` section 2.20 records this correction).
What generalisation means here instead: calibration never looks at adversarial
data (only the benign reference sets, matched-FPR), so the *same* calibrated
threshold already applies uniformly to every source family. FR-12's real
question is whether recall at that threshold holds up consistently across
families or is family-specific -- exactly a `by_source` breakdown of the ASR
this harness already computes, parallel to the existing `by_threat_type` one.
"Held out" is reporting language here, not a training-set exclusion.

This does NOT edit `config/policy.yaml`. Flipping `calibrated: true` and
moving V0/V3 out of `inert` is a deliberate, reviewed action for a human to
take after reading this run's report, not something the harness decides for
itself (the file's own comment already says so).
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from llmshield_mcp.config import REPO_ROOT, load_models_config
from llmshield_mcp.corpus.store import CorpusLabel, CorpusStore, DecontaminationStatus
from llmshield_mcp.detectors.base import Detector
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector
from llmshield_mcp.gauge.calibrate import attack_success_rate, threshold_at_fpr
from llmshield_mcp.gauge.references import partition_benign_references
from llmshield_mcp.gauge.stats import Interval, auroc_delong, clopper_pearson_ci, wilson_ci

DEFAULT_CORPUS_DB = REPO_ROOT / "corpus" / "payload_corpus.sqlite"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "gauge"

#: Detectors whose scores are graded enough to calibrate a threshold against.
#: Rules are binary and PII's threshold is a fixed pattern confidence
#: (docs/POLICY-AUDIT.md); calibrating threshold-at-FPR against either would
#: just hit the "constant score" degenerate case `CalibrationResult` already
#: handles, not produce a second real operating point.
CALIBRATABLE_DETECTORS: tuple[str, ...] = ("v0", "v3", "guard")

#: A benign line drawn at random from ~7,000 real repository lines is cheap
#: to score with rules/PII but not with V3 (~180-220ms/window,
#: docs/M0-OBSERVATIONS.md) at thousands of items. Sampling keeps one run in
#: the low hundreds per reference, matching prd.md's own corpus-scale target,
#: with a fixed seed so a run is exactly reproducible.
DEFAULT_BENIGN_SAMPLE_SIZE = 300
DEFAULT_SEED = 42

REPORT_CONFIG_FILES: tuple[str, ...] = (
    "policy.yaml",
    "models.yaml",
    "rules.yaml",
    "decontamination.yaml",
)


@dataclass(frozen=True, slots=True)
class CorpusItemRef:
    id: int
    source: str
    threat_type: str | None
    text: str


@dataclass(frozen=True, slots=True)
class ScoreRecord:
    item_id: int
    source: str
    threat_type: str | None
    label: str
    reference: str | None
    split: str
    detector: str
    raw_score: float | None
    benign_p: float | None
    injection_p: float | None
    jailbreak_p: float | None
    harmful_p: float | None
    config_hash: str


def build_detectors() -> dict[str, Detector]:
    """Every detector, unconditionally.

    GAUGE scores every item with all of them -- unlike the live `Gate`, whose
    construction is config-role-driven (`gating/transport.py:build_detectors`,
    a different function despite the shared name).
    """
    from llmshield_mcp.detectors.v0_lexical import V0LexicalDetector
    from llmshield_mcp.detectors.v3_transformer import V3TransformerDetector

    models_config = load_models_config()
    detectors: dict[str, Detector] = {
        "rules_mcp": RuleDetector(families=frozenset({"mcp"})),
        "rules_inj": RuleDetector(families=frozenset({"inj"})),
        "pii": PiiDetector(),
        "v0": V0LexicalDetector(models_config.v0),
        "v3": V3TransformerDetector(models_config.v3),
    }
    if models_config.guard is not None:
        # Scored through the identical protocol, on the identical corpus and
        # references, so its numbers are comparable to V0/V3's rather than a
        # separate benchmark that happens to share a name. Absent when
        # config/models.yaml defines no `guard` block, which keeps older
        # configurations loading.
        from llmshield_mcp.detectors.guard import GuardDetector

        detectors["guard"] = GuardDetector(models_config.guard)
    return detectors


def config_hash(paths: Sequence[Path]) -> str:
    """Fingerprint the config files a run used, so a report is traceable to
    the exact configuration state that produced it."""
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.read_bytes())
    return digest.hexdigest()[:16]


def _score_item(
    detectors: dict[str, Detector],
    item: CorpusItemRef,
    *,
    label: str,
    reference: str | None,
    split: str,
    config_hash_: str,
) -> list[ScoreRecord]:
    records: list[ScoreRecord] = []
    for name, detector in detectors.items():
        result = scan_normalised(detector, item.text)
        records.append(
            ScoreRecord(
                item_id=item.id,
                source=item.source,
                threat_type=item.threat_type,
                label=label,
                reference=reference,
                split=split,
                detector=name,
                raw_score=result.score,
                benign_p=result.detail.get("benign"),
                injection_p=result.detail.get("injection"),
                jailbreak_p=result.detail.get("jailbreak"),
                harmful_p=result.detail.get("harmful"),
                config_hash=config_hash_,
            )
        )
    return records


def write_scores_csv(records: list[ScoreRecord], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(records[0]).keys()) if records else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(asdict(record))


def _load_fpr_budgets(policy_path: Path) -> dict[str, float]:
    raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    budgets = raw.get("fpr_budget") or {}
    return {str(action): float(value) for action, value in budgets.items()}


def _load_clean_items(db: Path) -> tuple[list[CorpusItemRef], dict[int, tuple[str, str]]]:
    """Return (clean adversarial items, {id: (source, text)} for clean benign rows)."""
    store = CorpusStore(db)
    try:
        rows = store.rows()
    finally:
        store.close()

    adversarial = [
        CorpusItemRef(id=r["id"], source=r["source"], threat_type=r["threat_type"], text=r["text"])
        for r in rows
        if r["label"] == CorpusLabel.ADVERSARIAL
        and r["decontamination_status"] == DecontaminationStatus.CLEAN
    ]
    benign = {
        r["id"]: (r["source"], r["text"])
        for r in rows
        if r["label"] == CorpusLabel.BENIGN
        and r["decontamination_status"] == DecontaminationStatus.CLEAN
    }
    return adversarial, benign


def _sample_benign_references(
    benign: dict[int, tuple[str, str]], sample_size: int, rng: random.Random
) -> dict[str, list[CorpusItemRef]]:
    id_by_text: dict[str, int] = {}
    for item_id, (_source, text) in benign.items():
        id_by_text.setdefault(text, item_id)

    realistic_texts, styled_texts = partition_benign_references(
        [text for _source, text in benign.values()]
    )

    def to_items(texts: list[str]) -> list[CorpusItemRef]:
        sample = texts if len(texts) <= sample_size else rng.sample(texts, sample_size)
        items = []
        for text in sample:
            item_id = id_by_text[text]
            source, _ = benign[item_id]
            items.append(CorpusItemRef(id=item_id, source=source, threat_type=None, text=text))
        return items

    return {"realistic": to_items(realistic_texts), "adversarial_styled": to_items(styled_texts)}


def _interval_dict(interval: Interval) -> dict[str, float]:
    return {"point": interval.point, "low": interval.low, "high": interval.high}


def _grouped_asr(
    adversarial_items: list[CorpusItemRef],
    adv_scores: dict[int, float],
    threshold: float,
    key_fn: Callable[[CorpusItemRef], str],
) -> dict[str, Any]:
    """ASR (with CIs) grouped by whatever `key_fn` returns.

    Shared by the `by_threat_type` and `by_source` (FR-12) breakdowns in
    `_build_report` -- both are "ASR at this threshold, split by some item
    attribute", differing only in which attribute.
    """
    grouped: dict[str, Any] = {}
    for key in sorted({key_fn(item) for item in adversarial_items}):
        ids = [item.id for item in adversarial_items if key_fn(item) == key]
        scores = [adv_scores[i] for i in ids if i in adv_scores]
        if not scores:
            continue
        successes, total = attack_success_rate(scores, threshold)
        grouped[key] = {
            "asr_wilson": _interval_dict(wilson_ci(successes, total)),
            "asr_clopper_pearson": _interval_dict(clopper_pearson_ci(successes, total)),
            "successes": successes,
            "total": total,
        }
    return grouped


def _scores_for(
    records: list[ScoreRecord], detector: str, split: str, reference: str | None
) -> list[float]:
    return [
        r.raw_score
        for r in records
        if r.detector == detector
        and r.split == split
        and r.reference == reference
        and r.raw_score is not None
    ]


def run_gauge(
    db: Path = DEFAULT_CORPUS_DB,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    sample_size: int = DEFAULT_BENIGN_SAMPLE_SIZE,
    seed: int = DEFAULT_SEED,
) -> dict[str, Any]:
    rng = random.Random(seed)

    adversarial_items, benign_by_id = _load_clean_items(db)
    if not adversarial_items:
        raise ValueError(f"no clean adversarial items found in {db}; run `corpus-ingest` first")
    if not benign_by_id:
        raise ValueError(f"no clean benign items found in {db}; run `corpus-ingest` first")

    source_families = sorted({item.source for item in adversarial_items})
    if len(source_families) < 2:
        # FR-12's by_source breakdown needs at least two families to say
        # anything about generalisation -- one family is just the overall
        # number again. Warn rather than raise: a run against a partial
        # corpus is still useful for the other report sections.
        print(
            f"warning: only {len(source_families)} adversarial source family "
            f"({', '.join(source_families) or 'none'}) in {db} -- the by_source "
            "breakdown (FR-12) needs >= 2 to say anything about generalisation"
        )

    references = _sample_benign_references(benign_by_id, sample_size, rng)

    config_paths = [REPO_ROOT / "config" / name for name in REPORT_CONFIG_FILES]
    hash_ = config_hash(config_paths)
    fpr_budgets = _load_fpr_budgets(REPO_ROOT / "config" / "policy.yaml")

    detectors = build_detectors()

    all_records: list[ScoreRecord] = []
    cal_test_by_reference: dict[str, tuple[list[CorpusItemRef], list[CorpusItemRef]]] = {}
    for reference_name, items in references.items():
        shuffled = list(items)
        rng.shuffle(shuffled)
        half = len(shuffled) // 2
        calibration, test = shuffled[:half], shuffled[half:]
        cal_test_by_reference[reference_name] = (calibration, test)
        for split_name, split_items in (("calibration", calibration), ("test", test)):
            for item in split_items:
                all_records.extend(
                    _score_item(
                        detectors,
                        item,
                        label=CorpusLabel.BENIGN.value,
                        reference=reference_name,
                        split=split_name,
                        config_hash_=hash_,
                    )
                )

    for item in adversarial_items:
        all_records.extend(
            _score_item(
                detectors,
                item,
                label=CorpusLabel.ADVERSARIAL.value,
                reference=None,
                split="test",
                config_hash_=hash_,
            )
        )

    scores_csv_path = output_dir / "scores.csv"
    write_scores_csv(all_records, scores_csv_path)

    report = _build_report(adversarial_items, cal_test_by_reference, all_records, fpr_budgets)
    report["config_hash"] = hash_
    report["scores_csv"] = str(scores_csv_path)
    report["adversarial_source_families"] = source_families

    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "calibration_report.json"
    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    report["report_path"] = str(report_path)
    return report


def _build_report(
    adversarial_items: list[CorpusItemRef],
    cal_test_by_reference: dict[str, tuple[list[CorpusItemRef], list[CorpusItemRef]]],
    records: list[ScoreRecord],
    fpr_budgets: dict[str, float],
) -> dict[str, Any]:
    adversarial_scores_by_detector: dict[str, dict[int, float]] = {}
    for record in records:
        if record.label == CorpusLabel.ADVERSARIAL.value and record.raw_score is not None:
            adversarial_scores_by_detector.setdefault(record.detector, {})[record.item_id] = (
                record.raw_score
            )

    report: dict[str, Any] = {"references": {}}

    for reference_name in cal_test_by_reference:
        calibration_scores = {
            detector: _scores_for(records, detector, "calibration", reference_name)
            for detector in CALIBRATABLE_DETECTORS
        }
        test_benign_scores = {
            detector: _scores_for(records, detector, "test", reference_name)
            for detector in CALIBRATABLE_DETECTORS
        }

        reference_report: dict[str, Any] = {"detectors": {}}
        for detector in CALIBRATABLE_DETECTORS:
            if not calibration_scores[detector]:
                # A calibratable detector that produced no scores was not built
                # for this run -- `guard` when config/models.yaml defines no
                # `guard` block, for instance. Skipping keeps the report honest
                # (an absent detector is absent, not a row of zeros) and keeps
                # a partial configuration runnable.
                continue
            adv_scores = adversarial_scores_by_detector.get(detector, {})
            detector_report: dict[str, Any] = {"budgets": {}}

            for budget_name, target_fpr in fpr_budgets.items():
                calibration = threshold_at_fpr(calibration_scores[detector], target_fpr)
                held_out = test_benign_scores[detector]
                achieved_test_count = sum(1 for s in held_out if s >= calibration.threshold)
                achieved_test_fpr = (
                    wilson_ci(achieved_test_count, len(held_out)) if held_out else None
                )

                by_threat_type = _grouped_asr(
                    adversarial_items,
                    adv_scores,
                    calibration.threshold,
                    lambda item: item.threat_type or "unknown",
                )
                # FR-12 / M8: the same ASR breakdown, grouped by source family
                # instead of threat type -- see the module docstring for why
                # this is the leave-one-source-out generalisation test here.
                by_source = _grouped_asr(
                    adversarial_items,
                    adv_scores,
                    calibration.threshold,
                    lambda item: item.source,
                )

                overall_scores = list(adv_scores.values())
                overall_successes, overall_total = (
                    attack_success_rate(overall_scores, calibration.threshold)
                    if overall_scores
                    else (0, 0)
                )

                detector_report["budgets"][budget_name] = {
                    "target_fpr": target_fpr,
                    "threshold": calibration.threshold,
                    "calibration_unreachable": calibration.unreachable,
                    "achieved_fpr_calibration": calibration.achieved_fpr,
                    "achieved_fpr_test": (
                        _interval_dict(achieved_test_fpr) if achieved_test_fpr else None
                    ),
                    "asr_overall_wilson": (
                        _interval_dict(wilson_ci(overall_successes, overall_total))
                        if overall_total
                        else None
                    ),
                    "by_threat_type": by_threat_type,
                    "by_source": by_source,
                }

            if adv_scores and test_benign_scores[detector]:
                delong = auroc_delong(list(adv_scores.values()), test_benign_scores[detector])
                detector_report["auroc_delong"] = asdict(delong)

            reference_report["detectors"][detector] = detector_report

        report["references"][reference_name] = reference_report

    return report


__all__ = ["build_detectors", "config_hash", "run_gauge", "write_scores_csv"]
