"""V3 adapter: reused LLMShield DeBERTa-v3-base 4-class classifier.

The checkpoint's config was written by transformers 5.12.1, pinned exactly in
pyproject.toml. Architecture is DebertaV2ForSequenceClassification with
num_labels=4 over ("benign", "injection", "jailbreak", "harmful").

The 512-token window is the central design problem on this surface. User
prompts fit inside it; tool results routinely do not. An injection planted
past token 512 of a long file read is invisible to a truncating scorer -- not
because the detector is weak, but because it never sees the text. Two
strategies are therefore implemented and both are evaluated:

  truncate   score the first window only. Reproduces the dissertation setup
             exactly, and is the honest baseline for "what you get if you drop
             a prompt-surface detector onto the tool-result surface unchanged".

  chunk_max  slide a window over the whole text with overlap and take the
             maximum score across chunks. Sees everything, at a latency cost
             linear in content length.

The gap between the two IS the finding, so neither is a fallback for the other.
"""

from __future__ import annotations

from typing import ClassVar

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from llmshield_mcp.config import DETECTOR_CLASSES, V3Config, scalar_from_proba
from llmshield_mcp.detectors.base import Detector, RawScore


class V3TransformerDetector(Detector):
    name: ClassVar[str] = "v3"

    def __init__(self, config: V3Config) -> None:
        self._config = config
        path = str(config.path)

        self._tokenizer = AutoTokenizer.from_pretrained(path)
        self._model = AutoModelForSequenceClassification.from_pretrained(path)
        self._model.eval()
        self._model.to(config.device)

        n_labels = int(self._model.config.num_labels)
        if n_labels != len(DETECTOR_CLASSES):
            raise ValueError(
                f"checkpoint has {n_labels} labels, expected {len(DETECTOR_CLASSES)} "
                f"({list(DETECTOR_CLASSES)})"
            )

    @torch.no_grad()
    def _score(self, text: str) -> RawScore:
        # The tokenizer's own sliding window handles special tokens correctly
        # for each window; `stride` is the overlap in tokens. Overlap matters:
        # an injection straddling a window boundary would otherwise be split
        # across two chunks and diluted in both.
        encoded = self._tokenizer(
            text,
            truncation=True,
            max_length=self._config.max_length,
            stride=self._config.chunk_stride,
            return_overflowing_tokens=True,
            padding=True,
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"]
        attention_mask = encoded["attention_mask"]
        total_windows = int(input_ids.shape[0])

        if self._config.long_text_strategy == "truncate":
            scored_windows = 1
        else:
            # SEC-2: a large tool result would otherwise produce unboundedly
            # many windows. Cap the work and record that content was dropped.
            scored_windows = min(total_windows, self._config.max_chunks)

        input_ids = input_ids[:scored_windows].to(self._config.device)
        attention_mask = attention_mask[:scored_windows].to(self._config.device)

        probabilities: list[list[float]] = []
        for start in range(0, scored_windows, self._config.batch_size):
            stop = start + self._config.batch_size
            logits = self._model(
                input_ids=input_ids[start:stop],
                attention_mask=attention_mask[start:stop],
            ).logits
            probabilities.extend(torch.softmax(logits, dim=-1).cpu().tolist())

        scores = [scalar_from_proba(p, self._config.score_mode) for p in probabilities]
        best = max(range(len(scores)), key=scores.__getitem__)
        winning = probabilities[best]

        detail = {name: float(winning[i]) for i, name in enumerate(DETECTOR_CLASSES)}
        detail["n_windows_total"] = float(total_windows)
        detail["n_windows_scored"] = float(scored_windows)
        detail["winning_window"] = float(best)

        return RawScore(
            score=scores[best],
            detail=detail,
            # Truncated means content existed that was never scored -- either
            # because the truncate strategy discarded it, or because the chunk
            # cap was hit.
            truncated=scored_windows < total_windows,
        )
