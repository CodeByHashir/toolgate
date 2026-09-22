"""Tests for the `guard` model configuration block.

No weights needed: every case here is YAML in, `GuardConfig` (or an error) out.
The adapter itself, which has to download a checkpoint, is tested separately in
`tests/test_guard_with_models.py` under the `models` marker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from llmshield_mcp.config import load_models_config

BASE = """
root: "models"
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

GUARD = """
guard:
  repo: "protectai/deberta-v3-base-prompt-injection-v2"
  revision: "90c9989b1a342275dd0d1a95aad283c04e075671"
  positive_label: "INJECTION"
  device: "cpu"
  max_length: 512
  long_text_strategy: "chunk_max"
  chunk_stride: 128
  max_chunks: 64
  batch_size: 16
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "models.yaml"
    path.write_text(body, encoding="utf-8")
    return path


class TestGuardBlock:
    def test_absent_guard_block_loads_as_none(self, tmp_path: Path) -> None:
        """Older two-detector configurations must keep working unchanged."""
        config = load_models_config(_write(tmp_path, BASE))

        assert config.guard is None
        assert config.v0.score_mode == "not_benign"

    def test_guard_block_is_parsed(self, tmp_path: Path) -> None:
        config = load_models_config(_write(tmp_path, BASE + GUARD))

        assert config.guard is not None
        assert config.guard.repo == "protectai/deberta-v3-base-prompt-injection-v2"
        assert config.guard.revision == "90c9989b1a342275dd0d1a95aad283c04e075671"
        assert config.guard.positive_label == "INJECTION"
        assert config.guard.long_text_strategy == "chunk_max"

    def test_guard_is_identified_by_repo_not_a_local_path(self, tmp_path: Path) -> None:
        """The point of this detector is that it needs no local artifact.

        V0/V3 are configured by filesystem path because their weights are
        unpublishable. If `guard` ever grows a path, that property is gone.
        """
        config = load_models_config(_write(tmp_path, BASE + GUARD))

        assert config.guard is not None
        assert not hasattr(config.guard, "path")
        assert "/" in config.guard.repo  # a Hub id, not a directory


class TestRevisionPinning:
    @pytest.mark.parametrize("revision", ["main", "v2", "90c9989", "HEAD", ""])
    def test_non_sha_revisions_are_rejected(self, tmp_path: Path, revision: str) -> None:
        """A branch or tag lets upstream change what a published figure measured."""
        body = BASE + GUARD.replace("90c9989b1a342275dd0d1a95aad283c04e075671", revision)

        with pytest.raises(ValueError, match="must be a full 40-character commit SHA"):
            load_models_config(_write(tmp_path, body))

    def test_non_hex_forty_character_revision_is_rejected(self, tmp_path: Path) -> None:
        body = BASE + GUARD.replace("90c9989b1a342275dd0d1a95aad283c04e075671", "z" * 40)

        with pytest.raises(ValueError, match="must be a full 40-character commit SHA"):
            load_models_config(_write(tmp_path, body))

    def test_missing_revision_is_rejected(self, tmp_path: Path) -> None:
        body = BASE + "\n".join(line for line in GUARD.splitlines() if "revision" not in line)

        with pytest.raises(KeyError, match="revision"):
            load_models_config(_write(tmp_path, body))

    def test_missing_repo_is_rejected(self, tmp_path: Path) -> None:
        body = BASE + "\n".join(line for line in GUARD.splitlines() if "repo" not in line)

        with pytest.raises(KeyError, match="repo"):
            load_models_config(_write(tmp_path, body))


class TestGuardValidation:
    def test_bad_long_text_strategy_is_rejected(self, tmp_path: Path) -> None:
        body = BASE + GUARD.replace('long_text_strategy: "chunk_max"', 'long_text_strategy: "nope"')

        with pytest.raises(ValueError, match="long_text_strategy"):
            load_models_config(_write(tmp_path, body))

    def test_stride_at_or_above_max_length_is_rejected(self, tmp_path: Path) -> None:
        body = BASE + GUARD.replace("chunk_stride: 128", "chunk_stride: 512")

        with pytest.raises(ValueError, match="chunk_stride"):
            load_models_config(_write(tmp_path, body))


def test_shipped_models_yaml_defines_a_pinned_guard() -> None:
    """The checked-in configuration must itself satisfy the pinning rule."""
    config = load_models_config()

    assert config.guard is not None
    assert len(config.guard.revision) == 40
    assert config.guard.positive_label == "INJECTION"
