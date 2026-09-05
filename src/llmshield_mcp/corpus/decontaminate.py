"""MinHash decontamination against the V0/V3 training corpus (FR-10, M6).

Reuses the dissertation's own decontamination check
(`evaluation/experiment2/exp2_data.py`): 5-character shingles over normalised
text, a threshold of Jaccard >= 0.85 or an exact normalised-text match. Using
the identical shingle definition and threshold means an item flagged
"contaminated" here is held to the same standard that kept V0/V3's own
training set disjoint from their eval suite -- not a number invented for this
project. See `config/decontamination.yaml`.

One deliberate departure from the dissertation's script: this uses
`datasketch.MinHashLSH`, not the hand-rolled numpy version in
`exp2_data.py`/`exp2_lobo.py`. The dissertation computed one full eval x pool
similarity matrix in a single process; this project checks new corpus items
against a ~19k-row reference corpus repeatedly, across separate `corpus
ingest` invocations, so an indexed approximate nearest-neighbour structure is
the right tool -- and `datasketch` is already a pinned dependency for exactly
this (`pyproject.toml`).

That swap incidentally fixes a reproducibility gap the dissertation's script
never had to care about: `exp2_data.py` hashes shingles with Python's builtin
`hash()`, whose string hashing is randomised per process
(`PYTHONHASHSEED`) unless disabled. Harmless there, since one process builds
both signatures being compared in the same run. It would not be harmless here,
where `minhash_signature` (`store.py`) is meant to stay comparable across
separate CLI invocations. `datasketch`'s own default `hashfunc` (SHA1-based)
is already stable across processes and machines -- verified directly rather
than assumed -- so no custom hash function is needed; using the library
correctly solves this for free.
"""

from __future__ import annotations

import json
import os
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from datasketch import MinHash, MinHashLSH

from llmshield_mcp.config import REPO_ROOT

DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "decontamination.yaml"


def _norm(text: str) -> str:
    """Same normalisation as exp2_data.py's `_norm`: casefold + collapse whitespace.

    NFKC first so full-width/compatibility variants of the same character
    shingle identically; the dissertation's corpus did not need this, but
    this project's detectors already treat NFKC as part of "the same text"
    (`detectors/normalise.py`), so the decontamination check should agree.
    """
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _shingles(text: str, k: int) -> set[bytes]:
    normalised = _norm(text)
    if len(normalised) < k:
        return {normalised.encode("utf-8")}
    return {normalised[i : i + k].encode("utf-8") for i in range(len(normalised) - k + 1)}


def _minhash(text: str, *, shingle_size: int, num_perm: int) -> MinHash:
    mh = MinHash(num_perm=num_perm)
    for shingle in _shingles(text, shingle_size):
        mh.update(shingle)
    return mh


@dataclass(frozen=True, slots=True)
class DecontaminationConfig:
    shingle_size: int
    num_perm: int
    jaccard_threshold: float
    training_corpus_path: Path


def load_decontamination_config(path: Path | None = None) -> DecontaminationConfig:
    import yaml

    config_path = path or DEFAULT_CONFIG_PATH
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} did not parse to a mapping")

    shingle_size = int(raw.get("shingle_size", 5))
    if shingle_size < 1:
        raise ValueError(f"{config_path}: shingle_size must be at least 1")

    num_perm = int(raw.get("num_perm", 64))
    if num_perm < 1:
        raise ValueError(f"{config_path}: num_perm must be at least 1")

    threshold = float(raw.get("jaccard_threshold", 0.85))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"{config_path}: jaccard_threshold must be in [0, 1]")

    corpus_raw = os.environ.get("LLMSHIELD_TRAINING_CORPUS") or raw.get("training_corpus_path")
    if not corpus_raw:
        raise KeyError(f"{config_path}: missing required key 'training_corpus_path'")
    corpus_path = Path(corpus_raw)
    if not corpus_path.is_absolute():
        corpus_path = REPO_ROOT / corpus_path

    return DecontaminationConfig(
        shingle_size=shingle_size,
        num_perm=num_perm,
        jaccard_threshold=threshold,
        training_corpus_path=corpus_path,
    )


@dataclass(frozen=True, slots=True)
class ContaminationResult:
    text: str
    contaminated: bool
    #: The reference-corpus row index of the nearest match, when any query
    #: (exact or near-duplicate) found one. `None` when nothing matched.
    matched_reference_index: int | None


def _load_reference_texts(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(
            f"training-data reference corpus not found at {path}. "
            "Set LLMSHIELD_TRAINING_CORPUS or config/decontamination.yaml's "
            "training_corpus_path to your copy of "
            "evaluation/experiment2/data/train.jsonl (not published; see "
            "config/decontamination.yaml)."
        )
    texts: list[str] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row: dict[str, Any] = json.loads(line)
            texts.append(str(row["prompt"]))
    return texts


def _build_reference_index(
    reference_texts: Sequence[str], config: DecontaminationConfig
) -> tuple[MinHashLSH, dict[str, int]]:
    lsh = MinHashLSH(threshold=config.jaccard_threshold, num_perm=config.num_perm)
    exact: dict[str, int] = {}
    for index, text in enumerate(reference_texts):
        normalised = _norm(text)
        exact.setdefault(normalised, index)
        mh = _minhash(text, shingle_size=config.shingle_size, num_perm=config.num_perm)
        # Reference rows can collide after normalisation (the dissertation's
        # own dedup was on raw prompts); duplicate keys are harmless for LSH
        # membership queries, so skip re-inserting rather than erroring.
        lsh.insert(str(index), mh, check_duplication=False)
    return lsh, exact


def decontaminate(
    items: Iterable[str],
    config: DecontaminationConfig | None = None,
    reference_texts: Sequence[str] | None = None,
) -> list[ContaminationResult]:
    """Flag which `items` are near-duplicates of the training-data reference corpus.

    `reference_texts` lets a caller (or a test) supply the reference corpus
    directly, bypassing `config.training_corpus_path` -- useful when the real
    ~19k-row file isn't available, since the check itself needs no model
    weights and no network access.
    """
    cfg = config or load_decontamination_config()
    ref_texts = (
        reference_texts
        if reference_texts is not None
        else _load_reference_texts(cfg.training_corpus_path)
    )
    lsh, exact = _build_reference_index(ref_texts, cfg)

    results: list[ContaminationResult] = []
    for text in items:
        normalised = _norm(text)
        exact_index = exact.get(normalised)
        if exact_index is not None:
            results.append(
                ContaminationResult(text, contaminated=True, matched_reference_index=exact_index)
            )
            continue

        mh = _minhash(text, shingle_size=cfg.shingle_size, num_perm=cfg.num_perm)
        candidates = lsh.query(mh)
        if candidates:
            results.append(
                ContaminationResult(
                    text, contaminated=True, matched_reference_index=int(candidates[0])
                )
            )
        else:
            results.append(
                ContaminationResult(text, contaminated=False, matched_reference_index=None)
            )
    return results


__all__ = [
    "ContaminationResult",
    "DecontaminationConfig",
    "decontaminate",
    "load_decontamination_config",
]
