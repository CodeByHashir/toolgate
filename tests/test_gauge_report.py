"""Tests for the leave-one-source-out report breakdown (FR-12, M8).

`_build_report` is pure post-processing over already-computed `ScoreRecord`s
-- no detector, no model weights, no corpus store -- so the `by_source`
grouping it adds for M8 is fully testable with synthetic scores. This is
deliberately NOT a `models`-marked test: the grouping logic itself has
nothing to do with which detector produced the numbers.
"""

from __future__ import annotations

from llmshield_mcp.corpus.store import CorpusLabel
from llmshield_mcp.gauge.run import CorpusItemRef, ScoreRecord, _build_report


def _benign_records(detector: str, scores: list[float], split: str) -> list[ScoreRecord]:
    return [
        ScoreRecord(
            item_id=1000 + i,
            source="repository",
            threat_type=None,
            label=CorpusLabel.BENIGN.value,
            reference="realistic",
            split=split,
            detector=detector,
            raw_score=score,
            benign_p=None,
            injection_p=None,
            jailbreak_p=None,
            harmful_p=None,
            config_hash="test",
        )
        for i, score in enumerate(scores)
    ]


def _adversarial_records(
    detector: str, items: list[CorpusItemRef], scores: list[float]
) -> list[ScoreRecord]:
    return [
        ScoreRecord(
            item_id=item.id,
            source=item.source,
            threat_type=item.threat_type,
            label=CorpusLabel.ADVERSARIAL.value,
            reference=None,
            split="test",
            detector=detector,
            raw_score=score,
            benign_p=None,
            injection_p=None,
            jailbreak_p=None,
            harmful_p=None,
            config_hash="test",
        )
        for item, score in zip(items, scores, strict=True)
    ]


def test_by_source_separates_recall_between_two_families() -> None:
    # Calibration scores 0.0..0.9 at target_fpr=0.5 place the threshold at
    # ~0.5 (see gauge/calibrate.py's convention). family_a scores comfortably
    # above it (detected every time); family_b comfortably below (missed
    # every time) -- by_source should show that split, by_threat_type should
    # not blur it away.
    calibration_scores = [i / 10 for i in range(10)]
    fpr_budgets = {"escalate": 0.5}

    family_a = [
        CorpusItemRef(id=1, source="family_a", threat_type="phishing", text="a1"),
        CorpusItemRef(id=2, source="family_a", threat_type="phishing", text="a2"),
    ]
    family_b = [
        CorpusItemRef(id=3, source="family_b", threat_type="phishing", text="b1"),
        CorpusItemRef(id=4, source="family_b", threat_type="phishing", text="b2"),
    ]
    adversarial_items = family_a + family_b

    records: list[ScoreRecord] = []
    for detector in ("v0", "v3"):
        records += _benign_records(detector, calibration_scores, "calibration")
        records += _benign_records(detector, calibration_scores, "test")
        records += _adversarial_records(detector, family_a, [0.9, 0.9])
        records += _adversarial_records(detector, family_b, [0.1, 0.1])

    cal_test_by_reference = {
        "realistic": (
            [
                CorpusItemRef(id=i, source="repository", threat_type=None, text="x")
                for i in range(10)
            ],
            [
                CorpusItemRef(id=i, source="repository", threat_type=None, text="x")
                for i in range(10)
            ],
        )
    }

    report = _build_report(adversarial_items, cal_test_by_reference, records, fpr_budgets)

    budget = report["references"]["realistic"]["detectors"]["v0"]["budgets"]["escalate"]
    by_source = budget["by_source"]

    assert by_source["family_a"]["asr_wilson"]["point"] == 0.0  # every attack detected
    assert by_source["family_b"]["asr_wilson"]["point"] == 1.0  # every attack missed
    assert by_source["family_a"]["total"] == 2
    assert by_source["family_b"]["total"] == 2

    # by_threat_type groups both families together (same "phishing" type),
    # so it must NOT show the same clean 0%/100% split -- confirming
    # by_source is answering a genuinely different question.
    by_threat_type = budget["by_threat_type"]
    assert by_threat_type["phishing"]["total"] == 4
    assert by_threat_type["phishing"]["asr_wilson"]["point"] == 0.5


def test_a_single_source_family_still_produces_one_group() -> None:
    calibration_scores = [i / 10 for i in range(10)]
    items = [CorpusItemRef(id=1, source="only_family", threat_type=None, text="x")]

    records: list[ScoreRecord] = []
    for detector in ("v0", "v3"):
        records += _benign_records(detector, calibration_scores, "calibration")
        records += _benign_records(detector, calibration_scores, "test")
        records += _adversarial_records(detector, items, [0.9])

    cal_test_by_reference = {
        "realistic": (
            [
                CorpusItemRef(id=i, source="repository", threat_type=None, text="x")
                for i in range(10)
            ],
            [
                CorpusItemRef(id=i, source="repository", threat_type=None, text="x")
                for i in range(10)
            ],
        )
    }

    report = _build_report(items, cal_test_by_reference, records, {"escalate": 0.5})

    by_source = report["references"]["realistic"]["detectors"]["v0"]["budgets"]["escalate"][
        "by_source"
    ]
    assert set(by_source) == {"only_family"}
