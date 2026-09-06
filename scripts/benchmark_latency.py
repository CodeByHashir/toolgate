"""Measure per-detector and fused-pipeline latency (FR-13, NFR-1, NFR-2).

Mean + p95 in milliseconds, warmup excluded -- `exp2_eval.py`'s own
`latency_hf`/`latency_sklearn` convention (`n_warm=10`), reused via
`llmshield_mcp.latency` rather than invented for this project.

Needs the real reused weights (`config/models.yaml` / `LLMSHIELD_MODELS_ROOT`)
and a corpus already produced by `mcp-shield corpus-ingest`. Samples items
from that corpus (both labels, so the mix is realistically benign-heavy,
matching what a live gate actually scans) rather than a handful of hand-picked
probes.

    uv run python scripts/benchmark_latency.py

FR-14 (the 20-call chain's gate overhead) is measured separately -- record a
chain with `mcp-shield run-agent --db ...` and read the resulting decision
log; see docs/LATENCY-BENCHMARK.md for the committed numbers and exactly how
that chain was produced.
"""

from __future__ import annotations

import random

from llmshield_mcp.corpus.store import CorpusStore, DecontaminationStatus
from llmshield_mcp.detectors.base import Detector
from llmshield_mcp.detectors.normalise import scan_normalised
from llmshield_mcp.gating.policy import PolicyEngine, load_policy_config
from llmshield_mcp.gauge.run import DEFAULT_CORPUS_DB, build_detectors
from llmshield_mcp.latency import LatencyStats, time_calls

SAMPLE_SIZE = 60
SEED = 42
N_WARM = 10


def _sample_corpus_texts(sample_size: int, seed: int) -> list[str]:
    store = CorpusStore(DEFAULT_CORPUS_DB)
    try:
        rows = store.rows()
    finally:
        store.close()
    clean_texts = [
        r["text"] for r in rows if r["decontamination_status"] == DecontaminationStatus.CLEAN
    ]
    if not clean_texts:
        raise ValueError(
            f"no clean items found in {DEFAULT_CORPUS_DB}; run `mcp-shield corpus-ingest` first"
        )
    rng = random.Random(seed)
    return clean_texts if len(clean_texts) <= sample_size else rng.sample(clean_texts, sample_size)


def _print_row(label: str, stats: LatencyStats) -> None:
    print(f"  {label:12} mean={stats.mean_ms:7.2f} ms   p95={stats.p95_ms:7.2f} ms   n={stats.n}")


def main() -> int:
    texts = _sample_corpus_texts(SAMPLE_SIZE, SEED)
    print(f"sampled {len(texts)} clean corpus items ({SAMPLE_SIZE - N_WARM} timed after warmup)\n")

    detectors: dict[str, Detector] = build_detectors()

    print("per-detector (raw text, no normalisation pass):")
    for name, detector in detectors.items():
        stats = time_calls(lambda text, d=detector: d.score(text), texts, n_warm=N_WARM)
        _print_row(name, stats)

    print("\nper-detector (scan_normalised -- what the live gate actually calls):")
    for name, detector in detectors.items():
        stats = time_calls(lambda text, d=detector: scan_normalised(d, text), texts, n_warm=N_WARM)
        _print_row(name, stats)

    policy = PolicyEngine(load_policy_config())

    def _fused(text: str) -> None:
        results = {name: scan_normalised(detector, text) for name, detector in detectors.items()}
        policy.decide(results)

    fused_stats = time_calls(_fused, texts, n_warm=N_WARM)
    print("\nfused pipeline (all detectors + PolicyEngine.decide, per tool result):")
    _print_row("fused", fused_stats)

    print(
        "\nNFR-1 (~5ms rule/PII budget): compare the rules_mcp/rules_inj/pii rows above.\n"
        "NFR-2 (report honestly against a 100ms SME budget, even if missed): compare v3 "
        "and the fused row."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
