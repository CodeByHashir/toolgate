"""Generate the M10 report figures from a completed GAUGE run (AC-7, [18]).

Reads `results/gauge/calibration_report.json` (produced by `mcp-shield
gauge-run`, gitignored -- the raw calibration data is regenerable and its
sampling varies run to run, per plan.md 2.20/2.22) and writes plain SVG bar
charts to `docs/figures/` (committed: these are the curated, reported
figures, not raw data). No plotting library: three simple bar charts do not
need one, and it keeps NFR-8's pinned dependency set unchanged.

Latency figures are not re-read from a run here -- `docs/LATENCY-BENCHMARK.md`
already committed those numbers (M9); this script treats them as the
source of truth and charts the same figures, so there is exactly one place
each number is measured.

    uv run python scripts/generate_report.py

Writes docs/figures/asr_by_source_family.svg, latency_by_component.svg,
auroc_by_reference.svg.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CALIBRATION_REPORT = REPO_ROOT / "results" / "gauge" / "calibration_report.json"
FIGURES_DIR = REPO_ROOT / "docs" / "figures"

# docs/LATENCY-BENCHMARK.md section 1 -- committed numbers, not re-measured here.
LATENCY_MS: dict[str, float] = {
    "rules_mcp": 0.06,
    "rules_inj": 0.06,
    "pii": 0.07,
    "v0": 2.07,
    "v3": 208.28,
    "fused": 215.03,
}
NFR1_BUDGET_MS = 5.0
NFR2_BUDGET_MS = 100.0

WIDTH = 720
BAR_COLOR = "#4C72B0"
BAR_COLOR_2 = "#DD8452"
GRID_COLOR = "#D9D9D9"
TEXT_COLOR = "#222222"
BUDGET_COLOR = "#C44E52"


def _svg_header(width: int, height: int, title: str) -> str:
    return (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'font-family="Verdana, sans-serif">\n'
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>\n'
        f'<text x="{width / 2}" y="24" font-size="14" font-weight="bold" '
        f'text-anchor="middle" fill="{TEXT_COLOR}">{title}</text>\n'
    )


def grouped_bar_chart(
    title: str,
    categories: list[str],
    series: dict[str, list[float]],
    *,
    y_max: float,
    y_label: str,
    value_fmt: str = "{:.1f}",
    errors: dict[str, list[tuple[float, float]]] | None = None,
    threshold: float | None = None,
    threshold_label: str = "",
    log_scale: bool = False,
) -> str:
    """A minimal grouped bar chart, values already in `series` (no library).

    `errors`, if given, is `{series_name: [(low, high), ...]}` in the same
    units as `series` -- drawn as a vertical whisker on each bar.
    """
    height = 380
    margin_left, margin_right, margin_top, margin_bottom = 60, 20, 50, 70
    plot_w = WIDTH - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom
    colors = [BAR_COLOR, BAR_COLOR_2]

    def y_pos(value: float) -> float:
        if log_scale:
            log_max = math.log10(y_max)
            log_v = math.log10(max(value, y_max / 10_000))
            frac = log_v / log_max
        else:
            frac = value / y_max
        # A value far enough below the axis floor (log scale) or above y_max
        # would otherwise push the bar/label past the plot area -- clamp so
        # it renders as a sliver at the floor/ceiling instead of a
        # negative-height rect (which SVG silently does not draw at all).
        frac = max(0.0, min(1.0, frac))
        return margin_top + plot_h * (1 - frac)

    svg = [_svg_header(WIDTH, height, title)]

    # Gridlines + y-axis labels (5 ticks).
    for i in range(6):
        frac = i / 5
        gy = margin_top + plot_h * (1 - frac)
        tick_val = 10 ** (math.log10(y_max) * frac) if log_scale else y_max * frac
        svg.append(
            f'<line x1="{margin_left}" y1="{gy:.1f}" x2="{WIDTH - margin_right}" '
            f'y2="{gy:.1f}" stroke="{GRID_COLOR}" stroke-width="1"/>'
        )
        svg.append(
            f'<text x="{margin_left - 8}" y="{gy + 4:.1f}" font-size="10" '
            f'text-anchor="end" fill="{TEXT_COLOR}">{value_fmt.format(tick_val)}</text>'
        )

    svg.append(
        f'<text x="{16}" y="{margin_top + plot_h / 2:.1f}" font-size="11" '
        f'fill="{TEXT_COLOR}" transform="rotate(-90 16 {margin_top + plot_h / 2:.1f})" '
        f'text-anchor="middle">{y_label}</text>'
    )

    n_categories = len(categories)
    n_series = len(series)
    group_w = plot_w / n_categories
    bar_w = group_w / (n_series + 1)

    for cat_index, category in enumerate(categories):
        group_x = margin_left + cat_index * group_w
        for series_index, (name, values) in enumerate(series.items()):
            value = values[cat_index]
            bx = group_x + (series_index + 0.5) * bar_w
            by = y_pos(value)
            bh = margin_top + plot_h - by
            svg.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w * 0.85:.1f}" '
                f'height="{bh:.1f}" fill="{colors[series_index % len(colors)]}"/>'
            )
            svg.append(
                f'<text x="{bx + bar_w * 0.425:.1f}" y="{by - 4:.1f}" font-size="9" '
                f'text-anchor="middle" fill="{TEXT_COLOR}">{value_fmt.format(value)}</text>'
            )
            if errors and name in errors:
                low, high = errors[name][cat_index]
                cx = bx + bar_w * 0.425
                y_low, y_high = y_pos(low), y_pos(high)
                svg.append(
                    f'<line x1="{cx:.1f}" y1="{y_low:.1f}" x2="{cx:.1f}" y2="{y_high:.1f}" '
                    f'stroke="{TEXT_COLOR}" stroke-width="1.5"/>'
                )
        svg.append(
            f'<text x="{group_x + group_w / 2:.1f}" y="{margin_top + plot_h + 16:.1f}" '
            f'font-size="10" text-anchor="middle" fill="{TEXT_COLOR}">{category}</text>'
        )

    if threshold is not None:
        ty = y_pos(threshold)
        svg.append(
            f'<line x1="{margin_left}" y1="{ty:.1f}" x2="{WIDTH - margin_right}" y2="{ty:.1f}" '
            f'stroke="{BUDGET_COLOR}" stroke-width="1.5" stroke-dasharray="6,4"/>'
        )
        svg.append(
            f'<text x="{WIDTH - margin_right}" y="{ty - 4:.1f}" font-size="10" '
            f'text-anchor="end" fill="{BUDGET_COLOR}">{threshold_label}</text>'
        )

    legend_y = height - 24
    for i, name in enumerate(series):
        lx = margin_left + i * 120
        svg.append(f'<rect x="{lx}" y="{legend_y}" width="10" height="10" fill="{colors[i % 2]}"/>')
        label_x, label_y = lx + 14, legend_y + 9
        svg.append(
            f'<text x="{label_x}" y="{label_y}" font-size="10" fill="{TEXT_COLOR}">{name}</text>'
        )

    svg.append("</svg>\n")
    return "\n".join(svg)


def figure_asr_by_source_family(report: dict) -> str:
    families = report["adversarial_source_families"]
    series = {}
    errors = {}
    for detector in ("v0", "v3"):
        budget = report["references"]["realistic"]["detectors"][detector]["budgets"]["escalate"]
        values, bars = [], []
        for family in families:
            entry = budget["by_source"][family]
            values.append(entry["asr_wilson"]["point"] * 100)
            bars.append((entry["asr_wilson"]["low"] * 100, entry["asr_wilson"]["high"] * 100))
        series[detector] = values
        errors[detector] = bars
    return grouped_bar_chart(
        "ASR by source family (escalate budget, realistic reference)",
        families,
        series,
        y_max=100,
        y_label="ASR %",
        value_fmt="{:.0f}",
        errors=errors,
    )


def figure_latency_by_component() -> str:
    order = ["rules_mcp", "rules_inj", "pii", "v0", "v3", "fused"]
    return grouped_bar_chart(
        "Per-call latency by component (mean, log scale)",
        order,
        {"mean ms": [LATENCY_MS[k] for k in order]},
        y_max=1000,
        y_label="ms (log)",
        value_fmt="{:.2f}",
        log_scale=True,
        threshold=NFR2_BUDGET_MS,
        threshold_label="NFR-2 100ms",
    )


def figure_auroc_by_reference(report: dict) -> str:
    references = ["realistic", "adversarial_styled"]
    series = {}
    for detector in ("v0", "v3"):
        series[detector] = [
            report["references"][ref]["detectors"][detector]["auroc_delong"]["auc"]
            for ref in references
        ]
    return grouped_bar_chart(
        "DeLong AUROC by benign reference (0.5 = chance)",
        references,
        series,
        y_max=1.0,
        y_label="AUROC",
        value_fmt="{:.2f}",
        threshold=0.5,
        threshold_label="chance",
    )


def main() -> int:
    if not CALIBRATION_REPORT.exists():
        raise SystemExit(
            f"{CALIBRATION_REPORT} not found -- run `mcp-shield gauge-run` first "
            "(needs the real weights and an ingested corpus)."
        )
    report = json.loads(CALIBRATION_REPORT.read_text(encoding="utf-8"))

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    figures = {
        "asr_by_source_family.svg": figure_asr_by_source_family(report),
        "latency_by_component.svg": figure_latency_by_component(),
        "auroc_by_reference.svg": figure_auroc_by_reference(report),
    }
    for name, svg in figures.items():
        path = FIGURES_DIR / name
        path.write_text(svg, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
