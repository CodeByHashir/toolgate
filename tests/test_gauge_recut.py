"""Tests for the score-mode re-cut (`gauge/recut.py`).

The point of this module is that a published AUROC can be re-derived from
`scores.csv` alone, so these tests build CSVs by hand rather than running the
harness: a re-cut that only worked on real output would not prove the file is
self-sufficient.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from llmshield_mcp.config import DETECTOR_CLASSES
from llmshield_mcp.gauge.recut import (
    DEFAULT_MODES,
    format_table,
    load_rows,
    recut,
    to_report,
)

FIELDNAMES = [
    "item_id",
    "source",
    "threat_type",
    "label",
    "reference",
    "split",
    "detector",
    "raw_score",
    "benign_p",
    "injection_p",
    "jailbreak_p",
    "harmful_p",
    "config_hash",
]


def _write_csv(path: Path, rows: list[dict[str, object]]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for index, row in enumerate(rows):
            full: dict[str, object] = {name: "" for name in FIELDNAMES}
            full.update({"item_id": index, "source": "synthetic", "split": "test"})
            full.update(row)
            writer.writerow(full)
    return path


def _proba_row(
    detector: str,
    label: str,
    reference: str | None,
    proba: tuple[float, float, float, float],
    raw_score: float | None = None,
) -> dict[str, object]:
    benign, injection, jailbreak, harmful = proba
    return {
        "detector": detector,
        "label": label,
        "reference": reference or "",
        "raw_score": "" if raw_score is None else raw_score,
        "benign_p": benign,
        "injection_p": injection,
        "jailbreak_p": jailbreak,
        "harmful_p": harmful,
    }


class TestLoadRows:
    def test_reads_probabilities_and_optional_score(self, tmp_path: Path) -> None:
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                _proba_row("v3", "adversarial", None, (0.1, 0.7, 0.1, 0.1), raw_score=0.7),
                _proba_row("v3", "benign", "realistic", (0.9, 0.05, 0.03, 0.02), raw_score=0.05),
            ],
        )
        rows = load_rows(path)

        assert len(rows) == 2
        assert rows[0].detector == "v3"
        assert rows[0].label == "adversarial"
        assert rows[0].reference is None
        assert rows[0].raw_score == pytest.approx(0.7)
        assert rows[0].proba == pytest.approx((0.1, 0.7, 0.1, 0.1))

    def test_rows_without_a_full_probability_vector_keep_their_score(self, tmp_path: Path) -> None:
        """Rules and PII have no class vector; they must survive the read."""
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                {
                    "detector": "rules_mcp",
                    "label": "adversarial",
                    "reference": "",
                    "raw_score": 1.0,
                },
            ],
        )
        rows = load_rows(path)

        assert rows[0].proba is None
        assert rows[0].raw_score == pytest.approx(1.0)

    def test_missing_required_column_is_an_error(self, tmp_path: Path) -> None:
        path = tmp_path / "scores.csv"
        path.write_text("detector,label\nv3,benign\n", encoding="utf-8")

        with pytest.raises(ValueError, match="missing column"):
            load_rows(path)


class TestRecut:
    def test_stored_mode_reproduces_the_published_ordering(self, tmp_path: Path) -> None:
        """A re-cut under the stored score must match what raw_score implies."""
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                _proba_row("v3", "adversarial", None, (0.1, 0.8, 0.05, 0.05), raw_score=0.8),
                _proba_row("v3", "adversarial", None, (0.2, 0.7, 0.05, 0.05), raw_score=0.7),
                _proba_row("v3", "benign", "realistic", (0.9, 0.05, 0.03, 0.02), raw_score=0.05),
                _proba_row("v3", "benign", "realistic", (0.8, 0.1, 0.05, 0.05), raw_score=0.1),
            ],
        )
        rows = recut(load_rows(path), modes=("injection",))

        stored = next(r for r in rows if r.mode == "stored")
        injection = next(r for r in rows if r.mode == "injection")
        # raw_score WAS P(injection) for v3, so the two cuts must agree exactly.
        assert stored.result.auc == pytest.approx(injection.result.auc)
        assert stored.result.auc == pytest.approx(1.0)

    def test_benign_mode_is_the_exact_complement_of_not_benign(self, tmp_path: Path) -> None:
        """AUROC(benign) == 1 - AUROC(not_benign); a self-check on the machinery."""
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                _proba_row("v0", "adversarial", None, (0.3, 0.4, 0.2, 0.1)),
                _proba_row("v0", "adversarial", None, (0.6, 0.2, 0.1, 0.1)),
                _proba_row("v0", "adversarial", None, (0.45, 0.3, 0.15, 0.1)),
                _proba_row("v0", "benign", "realistic", (0.9, 0.05, 0.03, 0.02)),
                _proba_row("v0", "benign", "realistic", (0.5, 0.3, 0.1, 0.1)),
                _proba_row("v0", "benign", "realistic", (0.7, 0.1, 0.1, 0.1)),
            ],
        )
        rows = recut(load_rows(path), modes=("not_benign", "benign"), include_stored=False)

        not_benign = next(r for r in rows if r.mode == "not_benign")
        benign = next(r for r in rows if r.mode == "benign")
        assert benign.result.auc == pytest.approx(1.0 - not_benign.result.auc)

    def test_a_score_mode_can_move_a_detector_across_chance(self, tmp_path: Path) -> None:
        """The polarity check `gauge/recut.py` exists for, on constructed data.

        Here `injection` orders adversarial items BELOW benign ones while
        `not_benign` orders them above -- exactly the pattern that would mean a
        published below-chance figure is about the cut, not the classifier.
        """
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                # Adversarial: low P(injection) but very low P(benign) --
                # the mass sits on jailbreak/harmful.
                _proba_row("v3", "adversarial", None, (0.05, 0.10, 0.60, 0.25), raw_score=0.10),
                _proba_row("v3", "adversarial", None, (0.10, 0.15, 0.50, 0.25), raw_score=0.15),
                _proba_row("v3", "adversarial", None, (0.08, 0.12, 0.55, 0.25), raw_score=0.12),
                # Benign: higher P(injection) than any adversarial row, and a
                # high P(benign) too.
                _proba_row("v3", "benign", "realistic", (0.60, 0.30, 0.05, 0.05), raw_score=0.30),
                _proba_row("v3", "benign", "realistic", (0.65, 0.25, 0.05, 0.05), raw_score=0.25),
                _proba_row("v3", "benign", "realistic", (0.70, 0.20, 0.05, 0.05), raw_score=0.20),
            ],
        )
        rows = recut(load_rows(path), modes=("not_benign",))

        stored = next(r for r in rows if r.mode == "stored")
        not_benign = next(r for r in rows if r.mode == "not_benign")
        assert stored.below_chance
        assert not not_benign.below_chance
        assert not_benign.result.auc == pytest.approx(1.0)

    def test_detector_without_probabilities_yields_only_the_stored_row(
        self, tmp_path: Path
    ) -> None:
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                {
                    "detector": "rules_mcp",
                    "label": "adversarial",
                    "reference": "",
                    "raw_score": 1.0,
                },
                {
                    "detector": "rules_mcp",
                    "label": "benign",
                    "reference": "realistic",
                    "raw_score": 0.0,
                },
            ],
        )
        rows = recut(load_rows(path))

        assert {r.mode for r in rows} == {"stored"}

    def test_every_default_mode_is_a_known_score_mode(self) -> None:
        assert set(DEFAULT_MODES) == {"not_benign", *DETECTOR_CLASSES}

    def test_references_are_reported_separately(self, tmp_path: Path) -> None:
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                _proba_row("v3", "adversarial", None, (0.1, 0.8, 0.05, 0.05), raw_score=0.8),
                _proba_row("v3", "adversarial", None, (0.2, 0.7, 0.05, 0.05), raw_score=0.7),
                _proba_row("v3", "benign", "realistic", (0.9, 0.05, 0.03, 0.02), raw_score=0.05),
                _proba_row(
                    "v3", "benign", "adversarial_styled", (0.3, 0.6, 0.05, 0.05), raw_score=0.6
                ),
            ],
        )
        rows = recut(load_rows(path), modes=("injection",))

        assert {r.reference for r in rows} == {"realistic", "adversarial_styled"}


class TestOutput:
    def test_report_is_json_serialisable_and_carries_the_flag(self, tmp_path: Path) -> None:
        path = _write_csv(
            tmp_path / "scores.csv",
            [
                _proba_row("v3", "adversarial", None, (0.9, 0.05, 0.03, 0.02), raw_score=0.05),
                _proba_row("v3", "benign", "realistic", (0.1, 0.8, 0.05, 0.05), raw_score=0.8),
            ],
        )
        report = to_report(recut(load_rows(path), modes=("injection",)))

        assert report["rows"]
        stored = next(r for r in report["rows"] if r["mode"] == "stored")
        assert stored["below_chance"] is True
        assert stored["n_positive"] == 1
        assert stored["n_negative"] == 1

    def test_empty_input_formats_without_raising(self) -> None:
        assert "no (detector, reference, mode)" in format_table([])
