"""Tests for model configuration loading and the score-mode collapse."""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.config import (
    DEFAULT_CONFIG_PATH,
    DETECTOR_CLASSES,
    REPO_ROOT,
    load_models_config,
    scalar_from_proba,
)

VALID = """
root: "{root}"
v0:
  path: "v0_tfidf_lr.joblib"
  score_mode: "not_benign"
v3:
  path: "v3_deberta_base"
  device: "cpu"
  max_length: 512
  score_mode: "injection"
  long_text_strategy: "chunk_max"
  chunk_stride: 128
  max_chunks: 64
  batch_size: 16
"""


def _write(tmp_path: Path, body: str, root: Path | None = None) -> Path:
    """Write a config, substituting an OS-appropriate absolute root.

    A bare "/models" is not absolute on Windows (no drive letter), so it would
    be resolved against the repository root instead of taken literally.
    """
    path = tmp_path / "models.yaml"
    resolved = (root or (tmp_path / "models")).as_posix()
    path.write_text(body.replace("{root}", resolved), encoding="utf-8")
    return path


def test_loads_valid_config(tmp_path: Path) -> None:
    config = load_models_config(_write(tmp_path, VALID))

    assert config.v0.path == tmp_path / "models" / "v0_tfidf_lr.joblib"
    assert config.v0.score_mode == "not_benign"
    assert config.v3.path == tmp_path / "models" / "v3_deberta_base"
    assert config.v3.score_mode == "injection"
    assert config.v3.long_text_strategy == "chunk_max"


def test_env_var_overrides_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    elsewhere = tmp_path / "elsewhere"
    monkeypatch.setenv("LLMSHIELD_MODELS_ROOT", str(elsewhere))

    config = load_models_config(_write(tmp_path, VALID))

    assert config.v0.path == elsewhere / "v0_tfidf_lr.joblib"


def test_relative_root_resolves_against_the_repository(tmp_path: Path) -> None:
    """Q4: the checked-in default is relative so it discloses no host path."""
    body = VALID.replace('root: "{root}"', 'root: "models"')
    path = tmp_path / "models.yaml"
    path.write_text(body, encoding="utf-8")

    config = load_models_config(path)

    assert config.v0.path == REPO_ROOT / "models" / "v0_tfidf_lr.joblib"


def test_checked_in_config_discloses_no_absolute_host_path() -> None:
    text = DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
    root_line = next(line for line in text.splitlines() if line.startswith("root:"))

    assert not Path(root_line.split(":", 1)[1].strip().strip('"')).is_absolute()


def test_unknown_score_mode_is_rejected(tmp_path: Path) -> None:
    body = VALID.replace('score_mode: "injection"', 'score_mode: "malicious"')
    with pytest.raises(ValueError, match="score_mode"):
        load_models_config(_write(tmp_path, body))


def test_unknown_long_text_strategy_is_rejected(tmp_path: Path) -> None:
    body = VALID.replace('long_text_strategy: "chunk_max"', 'long_text_strategy: "summarise"')
    with pytest.raises(ValueError, match="long_text_strategy"):
        load_models_config(_write(tmp_path, body))


@pytest.mark.parametrize("stride", [0, 512, 600])
def test_chunk_stride_must_be_inside_the_window(tmp_path: Path, stride: int) -> None:
    body = VALID.replace("chunk_stride: 128", f"chunk_stride: {stride}")
    with pytest.raises(ValueError, match="chunk_stride"):
        load_models_config(_write(tmp_path, body))


@pytest.mark.parametrize("field", ["max_chunks", "batch_size"])
def test_bounding_fields_must_be_positive(tmp_path: Path, field: str) -> None:
    # SEC-2: these are the ceilings that stop an oversized tool result from
    # exhausting CPU or memory, so a zero would silently disable the defence.
    body = VALID.replace(f"{field}: 64", f"{field}: 0").replace(f"{field}: 16", f"{field}: 0")
    with pytest.raises(ValueError, match=field):
        load_models_config(_write(tmp_path, body))


def test_missing_required_key_is_rejected(tmp_path: Path) -> None:
    body = VALID.replace('  path: "v0_tfidf_lr.joblib"\n', "")
    with pytest.raises(KeyError, match="path"):
        load_models_config(_write(tmp_path, body))


# --- score-mode collapse -------------------------------------------------
# proba order is (benign, injection, jailbreak, harmful)
PROBA = [0.10, 0.60, 0.25, 0.05]


def test_not_benign_sums_every_malicious_class() -> None:
    assert scalar_from_proba(PROBA, "not_benign") == pytest.approx(0.90)


def test_named_class_selects_that_class_only() -> None:
    assert scalar_from_proba(PROBA, "injection") == pytest.approx(0.60)
    assert scalar_from_proba(PROBA, "jailbreak") == pytest.approx(0.25)


def test_the_two_dissertation_modes_genuinely_differ() -> None:
    # This is the asymmetry that matters for threat-type disaggregation:
    # a jailbreak-heavy item scores high under not_benign and low under
    # injection, so V0 and V3 are not directly comparable at their
    # dissertation defaults without saying so.
    jailbreak_item = [0.05, 0.05, 0.85, 0.05]
    assert scalar_from_proba(jailbreak_item, "not_benign") == pytest.approx(0.95)
    assert scalar_from_proba(jailbreak_item, "injection") == pytest.approx(0.05)


def test_wrong_length_probability_vector_is_rejected() -> None:
    with pytest.raises(ValueError, match="class probabilities"):
        scalar_from_proba([0.5, 0.5], "injection")


def test_class_order_is_the_trained_label_order() -> None:
    # Reordering these silently mislabels every score in the project.
    assert DETECTOR_CLASSES == ("benign", "injection", "jailbreak", "harmful")
