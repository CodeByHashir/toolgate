"""The payload corpus: sources, decontamination, and storage (M6)."""

from llmshield_mcp.corpus.decontaminate import (
    ContaminationResult,
    DecontaminationConfig,
    decontaminate,
    load_decontamination_config,
)
from llmshield_mcp.corpus.sources import (
    fetch,
    fetch_llmail_inject,
    load_adversarial,
    load_benign,
    load_llmail_inject,
)
from llmshield_mcp.corpus.store import (
    CorpusLabel,
    CorpusStore,
    DecontaminationStatus,
    PayloadCorpusItem,
    corpus_store,
)

__all__ = [
    "ContaminationResult",
    "CorpusLabel",
    "CorpusStore",
    "DecontaminationConfig",
    "DecontaminationStatus",
    "PayloadCorpusItem",
    "corpus_store",
    "decontaminate",
    "fetch",
    "fetch_llmail_inject",
    "load_adversarial",
    "load_benign",
    "load_decontamination_config",
    "load_llmail_inject",
]
