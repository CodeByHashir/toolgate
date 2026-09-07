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

from collections import defaultdict

from llmshield_mcp.corpus.sources import fetch, load_adversarial, load_benign
from llmshield_mcp.detectors.normalise import normalise
from llmshield_mcp.detectors.rules import RuleDetector


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
