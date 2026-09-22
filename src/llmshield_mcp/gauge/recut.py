"""Recompute AUROC from a saved `scores.csv` under a different score mode.

`plan.md` section 2.6 promises that every statistic this project publishes is
recomputable from `scores.csv` alone, without the unpublishable V0/V3 weights
(`prd.md` A1). `gauge/run.py` writes all four class probabilities for exactly
that reason. Until this module existed, the promise was architectural rather
than executable: nothing actually read those columns back.

## Why this exists beyond keeping a promise

`docs/REPORT.md` section 4 reports V3 at DeLong AUROC 0.32 on the realistic
benign reference -- *below* chance. An AUROC meaningfully below 0.5 has two
very different explanations:

1. The detector is genuinely anti-correlated on this surface, which is the
   reported finding; or
2. the wrong scalar is being cut out of the probability vector -- a label
   polarity or score-mode error, which would be a bug in this project, not a
   finding about V3.

The two are distinguishable without the weights. V0 is scored `not_benign`
(1 - P(benign)) and V3 `injection` (P(injection)) -- an asymmetry inherited
from the dissertation's own `exp2_eval.py` and documented in
`config/models.yaml`. If re-cutting V3 as `not_benign` from the *same stored
probabilities* moves it above chance, explanation 2 is live and the 0.32
figure is about the cut, not the classifier. If every mode stays below
chance, explanation 1 survives a real attempt to falsify it.

This module performs that re-cut. It asserts nothing about which answer is
correct: it prints both and leaves the interpretation to whoever reads it,
in the same spirit as `gauge-run` refusing to edit `config/policy.yaml`.

## What it deliberately does not do

* No model loading. Input is a CSV; a run needs neither weights nor a corpus.
* No re-scoring. A score mode is a projection of a probability vector that is
  already stored; recomputing it cannot change the underlying inference.
* No writes to `config/`. Same reasoning as `gauge/run.py`'s own docstring.
* No recall/ASR re-cut. Those need a threshold, and a threshold re-cut under a
  new score mode would need the calibration split re-run -- that is a
  `gauge-run` job, not a read-only re-analysis.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from llmshield_mcp.config import DETECTOR_CLASSES, scalar_from_proba
from llmshield_mcp.gauge.stats import DelongResult, auroc_delong

#: Score modes worth re-cutting. `benign` is included on purpose: it is the
#: exact complement of `not_benign`, so its AUROC must come out as
#: `1 - AUROC(not_benign)`. That identity is a free self-check that the
#: re-cut machinery is wired up correctly.
DEFAULT_MODES: tuple[str, ...] = ("not_benign", *DETECTOR_CLASSES)

#: Below this, a detector orders adversarial items *below* benign ones more
#: often than chance. Used only to label a row in the printed table.
CHANCE = 0.5


@dataclass(frozen=True, slots=True)
class RecutRow:
    """One (detector, reference, mode) AUROC, recomputed from stored probabilities."""

    detector: str
    reference: str
    mode: str
    result: DelongResult
    n_positive: int
    n_negative: int

    @property
    def below_chance(self) -> bool:
        return self.result.auc < CHANCE


@dataclass(frozen=True, slots=True)
class _Row:
    """One CSV line, reduced to the fields a re-cut needs."""

    detector: str
    label: str
    reference: str | None
    raw_score: float | None
    proba: tuple[float, ...] | None


def _optional_float(value: str) -> float | None:
    if value == "" or value.lower() == "none":
        return None
    return float(value)


def load_rows(path: Path) -> list[_Row]:
    """Read `scores.csv`, keeping only what a re-cut needs.

    Rows whose four class probabilities are not all present are kept with
    `proba=None`: the rule and PII detectors legitimately have no probability
    vector, and dropping them here would silently change which detectors
    appear in the output.
    """
    rows: list[_Row] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"detector", "label", "reference", "raw_score"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: scores.csv is missing column(s) {sorted(missing)}")
        for raw in reader:
            parts = [_optional_float(raw.get(f"{name}_p", "") or "") for name in DETECTOR_CLASSES]
            proba = tuple(p for p in parts if p is not None)
            rows.append(
                _Row(
                    detector=raw["detector"],
                    label=raw["label"],
                    reference=raw["reference"] or None,
                    raw_score=_optional_float(raw.get("raw_score", "") or ""),
                    proba=proba if len(proba) == len(DETECTOR_CLASSES) else None,
                )
            )
    return rows


def _score(row: _Row, mode: str | None) -> float | None:
    """Project `row` onto `mode`, or return the stored score when mode is None."""
    if mode is None:
        return row.raw_score
    if row.proba is None:
        return None
    return scalar_from_proba(row.proba, mode)


def recut(
    rows: Iterable[_Row],
    modes: Iterable[str] = DEFAULT_MODES,
    *,
    include_stored: bool = True,
) -> list[RecutRow]:
    """Recompute AUROC for every (detector, benign reference, mode) combination.

    Positives are adversarial rows (which carry no reference); negatives are
    the benign rows of one reference. That pairing mirrors `gauge/run.py`'s own
    AUROC, so a re-cut under the stored mode reproduces the published figure
    rather than merely resembling it.
    """
    materialised = list(rows)
    detectors = sorted({r.detector for r in materialised})
    references = sorted({r.reference for r in materialised if r.reference is not None})
    # None is the sentinel for "use raw_score as stored", which reproduces the
    # published number and anchors every re-cut against it.
    mode_list: list[str | None] = ([None] if include_stored else []) + list(modes)

    out: list[RecutRow] = []
    for detector in detectors:
        adversarial = [
            r for r in materialised if r.detector == detector and r.label == "adversarial"
        ]
        for reference in references:
            benign = [
                r
                for r in materialised
                if r.detector == detector and r.reference == reference and r.label == "benign"
            ]
            for mode in mode_list:
                positive = [s for r in adversarial if (s := _score(r, mode)) is not None]
                negative = [s for r in benign if (s := _score(r, mode)) is not None]
                if not positive or not negative:
                    # A detector with no probability vector under a class mode,
                    # or an empty split. Skipped rather than reported as 0.0,
                    # which would read as a finding.
                    continue
                out.append(
                    RecutRow(
                        detector=detector,
                        reference=reference,
                        mode="stored" if mode is None else mode,
                        result=auroc_delong(positive, negative),
                        n_positive=len(positive),
                        n_negative=len(negative),
                    )
                )
    return out


def to_report(rows: list[RecutRow]) -> dict[str, Any]:
    """Structured form of a re-cut, for writing to JSON."""
    return {
        "rows": [
            {
                "detector": row.detector,
                "reference": row.reference,
                "mode": row.mode,
                "auroc": row.result.auc,
                "ci_low": row.result.ci_low,
                "ci_high": row.result.ci_high,
                "n_positive": row.n_positive,
                "n_negative": row.n_negative,
                "below_chance": row.below_chance,
            }
            for row in rows
        ],
    }


def format_table(rows: list[RecutRow]) -> str:
    """Human-readable table, grouped by detector then reference."""
    if not rows:
        return "no (detector, reference, mode) combination had both classes present"

    lines = [
        f"{'detector':10} {'reference':22} {'mode':12} "
        f"{'AUROC':>7} {'95% CI':>18} {'n+':>5} {'n-':>5}",
    ]
    lines.append("-" * len(lines[0]))
    for row in rows:
        ci = f"[{row.result.ci_low:.2f}, {row.result.ci_high:.2f}]"
        flag = "  below chance" if row.below_chance else ""
        lines.append(
            f"{row.detector:10} {row.reference:22} {row.mode:12} "
            f"{row.result.auc:>7.3f} {ci:>18} {row.n_positive:>5} {row.n_negative:>5}{flag}"
        )
    return "\n".join(lines)


__all__ = [
    "CHANCE",
    "DEFAULT_MODES",
    "RecutRow",
    "format_table",
    "load_rows",
    "recut",
    "to_report",
]
