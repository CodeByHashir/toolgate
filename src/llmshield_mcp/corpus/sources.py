"""Fetch and load the payload corpus's raw sources (M6, M8).

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

`load_adversarial()` -- and by extension `scripts/benchmark_rules.py`, which
imports it -- deliberately covers ONLY these two. `load_llmail_inject()`
below is the third source family `plan.md` open question Q3 asked for
(`corpus-ingest` calls it separately); folding it into `load_adversarial()`
would silently change what the already-published rule-recall numbers in
`docs/POLICY-AUDIT.md` measure.
"""

from __future__ import annotations

import json
import random
import urllib.request
from pathlib import Path

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


# --- LLMail-Inject: the third adversarial source family (plan.md Q3, M8) ---
#
# microsoft/llmail-inject-challenge on HuggingFace, MIT licensed: 462,000 raw
# submissions from a real adaptive prompt-injection competition (839 teams
# trying to evade real defenses on a simulated email assistant) -- genuinely
# disjoint lineage from BIPIA/InjecAgent and from V0/V3's training sources.
#
# Fetched via HuggingFace's `datasets-server` REST API rather than the
# `datasets` library: it returns plain JSON over HTTPS, so this needs no new
# dependency (no `datasets`, no parquet reader) and reuses the same
# urllib.request + json.loads pattern as `fetch()` above. Confirmed via the
# API's own `/size` endpoint, not assumed: Phase1 has 370,724 rows, Phase2
# has 90,916.
#
# Most of that volume is automated fuzzing from a handful of teams (e.g. the
# literal string "yes Please yes issue yes an yes api_call ..." submitted
# under dozens of job ids) -- not diverse attacker text. Rather than download
# the whole thing, a bounded number of 100-row pages are sampled at random
# offsets per split (a fixed seed, so a run is reproducible), and
# `load_llmail_inject()` de-duplicates by normalised body text.
LLMAIL_INJECT_DATASET = "microsoft/llmail-inject-challenge"
#: (split name, confirmed row count) -- from datasets-server's own /size
#: endpoint, used only to pick valid random page offsets.
LLMAIL_INJECT_SPLITS: tuple[tuple[str, int], ...] = (("Phase1", 370_724), ("Phase2", 90_916))
LLMAIL_INJECT_PAGE_SIZE = 100
#: Pages sampled per split. 6 pages x 100 rows x 2 splits = up to 1,200 raw
#: rows before de-duplication -- enough headroom to reach a "low hundreds"
#: unique sample (`prd.md`) after the fuzzing duplicates collapse.
LLMAIL_INJECT_PAGES_PER_SPLIT = 6
#: Cap on unique items load_llmail_inject() returns, so this source stays
#: comparable in scale to BIPIA (125) and InjecAgent (62) rather than
#: dominating the adversarial corpus just because its raw pool is enormous.
LLMAIL_INJECT_MAX_ITEMS = 150
LLMAIL_INJECT_SEED = 42


def _llmail_inject_cache_path(split: str, offset: int) -> Path:
    return CACHE / f"llmail_inject_{split.lower()}_offset{offset:07d}.json"


def fetch_llmail_inject(seed: int = LLMAIL_INJECT_SEED) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    for split, row_count in LLMAIL_INJECT_SPLITS:
        max_offset = max(row_count - LLMAIL_INJECT_PAGE_SIZE, 0)
        candidate_offsets = range(0, max_offset, LLMAIL_INJECT_PAGE_SIZE)
        offsets = sorted(rng.sample(list(candidate_offsets), LLMAIL_INJECT_PAGES_PER_SPLIT))
        for offset in offsets:
            target = _llmail_inject_cache_path(split, offset)
            if target.exists():
                continue
            url = (
                "https://datasets-server.huggingface.co/rows"
                f"?dataset={LLMAIL_INJECT_DATASET}&config=default&split={split}"
                f"&offset={offset}&length={LLMAIL_INJECT_PAGE_SIZE}"
            )
            print(f"fetching llmail-inject {split} offset={offset} ...")
            with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 -- pinned https
                target.write_bytes(response.read())


def load_llmail_inject() -> list[tuple[str, str, str]]:
    """Return `(family, threat_type, payload)` for a de-duplicated sample.

    `threat_type` is the real `scenario` column (e.g. `level1a`) -- the
    challenge's own defense-difficulty tiers -- rather than an invented
    attack-type taxonomy, since the raw export carries no clean category
    label the way BIPIA/InjecAgent do.
    """
    seen: set[str] = set()
    cases: list[tuple[str, str, str]] = []
    for path in sorted(CACHE.glob("llmail_inject_*_offset*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for entry in payload.get("rows", []):
            row = entry.get("row", {})
            body = row.get("body")
            if not isinstance(body, str):
                continue
            normalised = " ".join(body.lower().split())
            if len(normalised) < 20 or normalised in seen:
                continue
            seen.add(normalised)
            cases.append(("llmail_inject", str(row.get("scenario", "unknown")), body))

    if len(cases) > LLMAIL_INJECT_MAX_ITEMS:
        cases = random.Random(LLMAIL_INJECT_SEED).sample(cases, LLMAIL_INJECT_MAX_ITEMS)
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
