"""Measure the rule families against real indirect prompt injection benchmarks.

Replaces the hand-written cases used in the first draft of
`docs/POLICY-AUDIT.md`. Those gave 38.1% recall; the same rules score 0.0%
against real benchmark data. The difference was that the hand-written cases had
been written by someone who knew what the rules matched, so they measured the
author's assumptions rather than the rules.

Sources, both MIT licensed, fetched on demand and cached under `corpus/external/`:

* **BIPIA** (microsoft/BIPIA) -- 125 attacker objectives across 25 categories,
  spanning text and code scenarios.
* **InjecAgent** (uiuc-kang-lab/InjecAgent) -- 62 attacker instructions across
  direct-harm and data-stealing attack types.

Both supply the *injected instruction* rather than the composed document. The
real gate sees it embedded in a host tool result, which if anything is harder
(see the dilution effect in docs/M0-OBSERVATIONS.md), so treat these numbers as
an upper bound.

    uv run python scripts/benchmark_rules.py
"""

from __future__ import annotations

import json
import urllib.request
from collections import defaultdict

from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.detectors.normalise import normalise
from llmshield_mcp.detectors.rules import RuleDetector

CACHE = REPO_ROOT / "corpus" / "external"

SOURCES: dict[str, str] = {
    "bipia_text.json": "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/text_attack_test.json",
    "bipia_code.json": "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/code_attack_test.json",
    "injecagent_dh.jsonl": "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_dh.jsonl",
    "injecagent_ds.jsonl": "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/attacker_cases_ds.jsonl",
}


def fetch() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = CACHE / name
        if target.exists():
            continue
        print(f"fetching {name} ...")
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 -- pinned https
            target.write_bytes(response.read())


def load_adversarial() -> list[tuple[str, str, str]]:
    """Return (family, threat_type, payload)."""
    cases: list[tuple[str, str, str]] = []
    for name, family in (("bipia_text.json", "bipia"), ("bipia_code.json", "bipia")):
        for category, items in json.loads((CACHE / name).read_text(encoding="utf-8")).items():
            cases += [(family, category, text) for text in items]
    for name, family in (
        ("injecagent_dh.jsonl", "injecagent"),
        ("injecagent_ds.jsonl", "injecagent"),
    ):
        for line in (CACHE / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                cases.append(
                    (family, row.get("Attack Type", "unknown"), row["Attacker Instruction"])
                )
    return cases


def load_benign() -> list[str]:
    """Benign lines from real technical content this repo contains."""
    lines: list[str] = []
    globs = (
        "*.md",
        "src/**/*.py",
        "tests/**/*.py",
        "docs/*.md",
        "config/*.yaml",
        "sandbox/**/*",
        "chains/*.json",
    )
    for pattern in globs:
        for path in REPO_ROOT.glob(pattern):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                lines += [ln.strip() for ln in text.splitlines() if len(ln.strip()) >= 20]
    return lines


def main() -> int:
    fetch()
    adversarial = load_adversarial()
    benign = load_benign()

    variants = {
        "INJ-* only (ported)": RuleDetector(families=frozenset({"inj"})),
        "MCP-* only (new)": RuleDetector(families=frozenset({"mcp"})),
        "both families": RuleDetector(),
    }

    counts: dict[str, int] = defaultdict(int)
    for family, _, _ in adversarial:
        counts[family] += 1

    print(f"\nadversarial: {len(adversarial)}  benign lines: {len(benign)}\n")
    header = (
        f"{'variant':24} {'bipia':>8} {'injecag':>9} {'overall':>9} {'+norm':>8} {'benign FP':>11}"
    )
    print(header)
    print("-" * len(header))

    for label, detector in variants.items():
        hit: dict[str, int] = defaultdict(int)
        normalised_hits = 0
        for family, _, text in adversarial:
            if detector.score(text).score:
                hit[family] += 1
            if detector.score(normalise(text).text).score:
                normalised_hits += 1
        false_positives = sum(1 for line in benign if detector.score(line).score)
        total = sum(hit.values())
        print(
            f"{label:24} {hit['bipia'] / counts['bipia']:>7.1%} "
            f"{hit['injecagent'] / counts['injecagent']:>8.1%} "
            f"{total / len(adversarial):>8.1%} "
            f"{normalised_hits / len(adversarial):>7.1%} "
            f"{false_positives:>4} ({false_positives / len(benign):>5.2%})"
        )

    print(
        "\nThe gap between the two sources is the point: rules tuned on one "
        "attack family do not transfer to another, which is what FR-12's "
        "leave-one-source-out test exists to measure."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
