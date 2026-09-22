"""Fetch and load the payload corpus's raw sources (M6, M8).

Moved from `scripts/benchmark_rules.py`, which imports these functions rather
than defining its own copy, now that a second consumer (`corpus ingest`) needs
the same loaders. Nothing about the fetch/parse behaviour changed.

Sources, both MIT licensed, fetched on demand and cached under
`corpus/external/` (gitignored). Every file is pinned to an upstream **commit
SHA** and verified against a recorded **sha256** on both download and load --
see `Source` below for why a branch ref was not good enough:

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

import hashlib
import json
import random
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from llmshield_mcp.config import REPO_ROOT

CACHE = REPO_ROOT / "corpus" / "external"


class CorpusIntegrityError(RuntimeError):
    """A fetched or cached source file did not match its recorded digest.

    Raised rather than warned about: a corpus that silently differs from the
    one a published figure was computed against would make every downstream
    number unfalsifiable, which is the specific failure this project exists
    to avoid.
    """


@dataclass(frozen=True, slots=True)
class Source:
    """One pinned upstream file.

    `commit` is a full commit SHA, never a branch. An earlier version of this
    module fetched from `.../main/...`; the `# noqa: S310 -- pinned https`
    comment on the request pinned the *scheme*, not the content, so upstream
    could change any of these four files and every published recall figure
    would silently start measuring a different corpus. `config/servers.yaml`
    already pins `@modelcontextprotocol/server-filesystem@2026.8.31` and
    `mcp-server-fetch==2026.8.18` for exactly this reason -- the evaluation
    inputs were the one thing left floating.

    `sha256` is the digest of the bytes those commits serve, recorded from the
    cached copies the published BIPIA/InjecAgent figures in
    `docs/POLICY-AUDIT.md` and `docs/REPORT.md` were actually computed against.
    A commit pin alone would still trust GitHub to serve the same bytes for
    that SHA; the digest removes that assumption too, and additionally detects
    a locally corrupted or hand-edited cache.
    """

    repo: str
    commit: str
    path: str
    sha256: str

    @property
    def url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.repo}/{self.commit}/{self.path}"


SOURCES: dict[str, Source] = {
    "bipia_text.json": Source(
        repo="microsoft/BIPIA",
        commit="5a48626aece9739ce587ffdbcb2b7badcfd9d8ba",
        path="benchmark/text_attack_test.json",
        sha256="75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8",
    ),
    "bipia_code.json": Source(
        repo="microsoft/BIPIA",
        commit="5a48626aece9739ce587ffdbcb2b7badcfd9d8ba",
        path="benchmark/code_attack_test.json",
        sha256="892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0",
    ),
    "injecagent_dh.jsonl": Source(
        repo="uiuc-kang-lab/InjecAgent",
        commit="623f1bf3ad8ed35abe71f9f9d8fd9d99ad65aeea",
        path="data/attacker_cases_dh.jsonl",
        sha256="999d52e15af3c80a3303a09430af0f3878d1f91e4c573ca7b477a91cdfa6b991",
    ),
    "injecagent_ds.jsonl": Source(
        repo="uiuc-kang-lab/InjecAgent",
        commit="623f1bf3ad8ed35abe71f9f9d8fd9d99ad65aeea",
        path="data/attacker_cases_ds.jsonl",
        sha256="87952398c989d8ca841724e38ecdbb789676d3841e19dfc44aac7b710df9cb1f",
    ),
}


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_cache() -> dict[str, str]:
    """Check every cached file against its recorded digest.

    Returns `{filename: actual_digest}` for files that are present and match.
    Raises on a mismatch; silently omits files not fetched yet.
    """
    verified: dict[str, str] = {}
    for name, source in SOURCES.items():
        target = CACHE / name
        if not target.exists():
            continue
        actual = digest(target.read_bytes())
        if actual != source.sha256:
            raise CorpusIntegrityError(
                f"{target} does not match its recorded digest.\n"
                f"  expected {source.sha256}\n"
                f"  actual   {actual}\n"
                f"Delete the file to re-fetch from {source.url}. If the upstream "
                f"content legitimately changed, that is a new corpus: update the "
                f"pin AND re-run every benchmark that cites the old one."
            )
        verified[name] = actual
    return verified


def fetch() -> None:
    """Download any missing pinned source, verifying every file's digest.

    Already-cached files are verified too, not skipped: a cache poisoned or
    corrupted between runs is exactly as damaging as a bad download, and
    checking costs one hash of a few kilobytes.
    """
    CACHE.mkdir(parents=True, exist_ok=True)
    for name, source in SOURCES.items():
        target = CACHE / name
        if not target.exists():
            print(f"fetching {name} ...")
            with urllib.request.urlopen(  # noqa: S310 -- https, pinned commit, digest-checked below
                source.url, timeout=60
            ) as response:
                payload = response.read()
            actual = digest(payload)
            if actual != source.sha256:
                raise CorpusIntegrityError(
                    f"{source.url} served unexpected content.\n"
                    f"  expected sha256 {source.sha256}\n"
                    f"  actual   sha256 {actual}\n"
                    f"Nothing was written to {target}."
                )
            target.write_bytes(payload)
    verify_cache()


def load_adversarial() -> list[tuple[str, str, str]]:
    """Return `(family, threat_type, payload)` for every fetched attack case.

    Verifies the cache before parsing it. A benchmark that loaded a modified
    corpus and reported a number against it would be worse than one that
    failed to run.
    """
    verify_cache()
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
#
# **Pinning gap, stated rather than papered over.** BIPIA and InjecAgent above
# are pinned to commit SHAs and digest-verified. This source cannot be, by
# construction: it is a paginated query against a live API, so there is no
# immutable ref to pin and the per-page bytes are not stable enough to record a
# digest for. The fixed seed makes the *offsets* reproducible, not the rows
# they return. Anything computed from this family is therefore reproducible
# only up to HuggingFace continuing to serve the same dataset revision. Treat
# a LLMail-Inject figure as weaker evidence than a BIPIA/InjecAgent one, and
# re-derive it rather than assuming an old run still holds.
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
