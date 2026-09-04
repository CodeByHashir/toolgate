"""Loading of the model-artifact configuration.

Model paths live in config rather than code because the reused LLMShield
weights are not vendored into this repository (they are not publishable), so
every operator will have them somewhere different.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

# Model driving the reference agent. Lives here rather than in agent.py so the
# CLI can show it in --help without importing anthropic and mcp.
#
# Chains that feed the evaluation are recorded with this model: PROPOSAL.md
# section 3.1 wants *realistic* tool-call chains, and a weaker model produces a
# thinner, less realistic call sequence. Because the agent records once and the
# GAUGE evaluation then runs offline (assumption A2), this choice costs a
# one-off spend rather than one that scales with corpus size. Use
# claude-haiku-4-5 via --model for cheap smoke runs.
DEFAULT_AGENT_MODEL = "claude-opus-5"

DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "models.yaml"

# Fixed by the LLMShield training script (evaluation/experiment2/exp2_train.py:25).
# BOTH V0 and V3 are 4-class over exactly this label order, which is the model's
# index order and must not be reordered.
DETECTOR_CLASSES: tuple[str, ...] = ("benign", "injection", "jailbreak", "harmful")

BENIGN_INDEX = DETECTOR_CLASSES.index("benign")

# How a 4-class probability vector collapses to one scalar "suspicion" score.
#
#   not_benign -- 1 - P(benign); fires on injection, jailbreak AND harmful.
#                 What the dissertation used for V0 (exp2_eval.py:74).
#   injection  -- P(injection) alone.
#                 What the dissertation used for V3 (exp2_eval.py:90).
#
# The two are not interchangeable. Under matched-FPR each detector gets its own
# threshold so neither is unfairly penalised overall, but on threat-type
# disaggregation a P(injection) scorer will read as weak on jailbreak/harmful
# rows by construction rather than by capability. Defaults below preserve
# dissertation continuity; the harmonised comparison re-runs both as not_benign.
SCORE_MODES: frozenset[str] = frozenset({"not_benign", *DETECTOR_CLASSES})

LONG_TEXT_STRATEGIES: frozenset[str] = frozenset({"truncate", "chunk_max"})


def scalar_from_proba(proba: Sequence[float], mode: str) -> float:
    """Collapse a 4-class probability vector to one score in [0, 1]."""
    if len(proba) != len(DETECTOR_CLASSES):
        raise ValueError(f"expected {len(DETECTOR_CLASSES)} class probabilities, got {len(proba)}")
    if mode == "not_benign":
        return 1.0 - float(proba[BENIGN_INDEX])
    if mode not in DETECTOR_CLASSES:
        raise ValueError(f"unknown score mode {mode!r}")
    return float(proba[DETECTOR_CLASSES.index(mode)])


@dataclass(frozen=True, slots=True)
class V0Config:
    path: Path
    score_mode: str


@dataclass(frozen=True, slots=True)
class V3Config:
    path: Path
    device: str
    max_length: int
    score_mode: str
    long_text_strategy: str
    chunk_stride: int
    max_chunks: int
    batch_size: int


@dataclass(frozen=True, slots=True)
class ModelsConfig:
    v0: V0Config
    v3: V3Config


def _require(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise KeyError(f"missing required key '{key}' in {where}")
    return mapping[key]


def _score_mode(raw: dict[str, Any], default: str, where: str) -> str:
    mode = raw.get("score_mode", default)
    if mode not in SCORE_MODES:
        raise ValueError(f"{where}: score_mode {mode!r} not one of {sorted(SCORE_MODES)}")
    return str(mode)


def load_models_config(path: Path | None = None) -> ModelsConfig:
    """Read and validate the model configuration.

    Validation is strict and happens here rather than at first inference, so a
    typo in a score mode or strategy fails immediately instead of halfway
    through an evaluation run.
    """
    config_path = path or DEFAULT_CONFIG_PATH
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} did not parse to a mapping")

    root = Path(os.environ.get("LLMSHIELD_MODELS_ROOT") or _require(raw, "root", "models.yaml"))

    v0_raw = _require(raw, "v0", "models.yaml")
    v3_raw = _require(raw, "v3", "models.yaml")

    strategy = v3_raw.get("long_text_strategy", "chunk_max")
    if strategy not in LONG_TEXT_STRATEGIES:
        raise ValueError(
            f"long_text_strategy {strategy!r} not one of {sorted(LONG_TEXT_STRATEGIES)}"
        )

    max_length = int(v3_raw.get("max_length", 512))
    chunk_stride = int(v3_raw.get("chunk_stride", 128))
    if not 0 < chunk_stride < max_length:
        raise ValueError(f"chunk_stride {chunk_stride} must be in (0, max_length={max_length})")

    max_chunks = int(v3_raw.get("max_chunks", 64))
    if max_chunks < 1:
        raise ValueError(f"max_chunks {max_chunks} must be at least 1")

    batch_size = int(v3_raw.get("batch_size", 16))
    if batch_size < 1:
        raise ValueError(f"batch_size {batch_size} must be at least 1")

    return ModelsConfig(
        v0=V0Config(
            path=root / _require(v0_raw, "path", "models.yaml:v0"),
            score_mode=_score_mode(v0_raw, "not_benign", "models.yaml:v0"),
        ),
        v3=V3Config(
            path=root / _require(v3_raw, "path", "models.yaml:v3"),
            device=v3_raw.get("device", "cpu"),
            max_length=max_length,
            score_mode=_score_mode(v3_raw, "injection", "models.yaml:v3"),
            long_text_strategy=strategy,
            chunk_stride=chunk_stride,
            max_chunks=max_chunks,
            batch_size=batch_size,
        ),
    )
