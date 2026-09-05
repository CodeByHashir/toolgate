"""Fetch and load the payload corpus's raw sources (M6).

Moved from `scripts/benchmark_rules.py`, which imports these functions rather
than defining its own copy, now that a second consumer (`corpus ingest`) needs
the same loaders. Nothing about the fetch/parse behaviour changed.

Sources, both MIT licensed, fetched on demand and cached under
`corpus/external/` (gitignored):

* **BIPIA** (microsoft/BIPIA) -- 125 attacker objectives across 25 categories,
  spanning text and code scenarios.
* **InjecAgent** (uiuc-kang-lab/InjecAgent) -- 62 attacker instructions across
  direct-harm and data-stealing attack types.

Both supply the *injected instruction* rather than the composed document. The
real gate sees it embedded in a host tool result, which if anything is harder
(see the dilution effect in docs/M0-OBSERVATIONS.md), so treat these as an
upper bound on real-world recall.
"""

from __future__ import annotations

import json
import urllib.request

from llmshield_mcp.config import REPO_ROOT

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
    """Return `(family, threat_type, payload)` for every fetched attack case."""
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
