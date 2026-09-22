"""Guard adapter: a published, redistributable binary injection classifier.

Default checkpoint is `protectai/deberta-v3-base-prompt-injection-v2`
(Apache-2.0), pinned by commit SHA in `config/models.yaml`.

## Why a third classifier at all

V0 and V3 are reused dissertation artifacts and are not publishable
(`prd.md` A1). A reader of `docs/REPORT.md` therefore cannot check a single
number this project reports about them, and someone who clones the repository
cannot run the research profile at all. That is a real limit on both the
evidence and the usability, and it is not fixed by writing more carefully.

This adapter loads a classifier anyone can fetch, under a licence that permits
redistribution, and runs it through the *identical* GAUGE protocol against the
*identical* decontaminated corpus. Whatever it scores is reproducible by a
third party.

## Two differences from V3, both deliberate

**Binary, not 4-class.** The checkpoint classifies `(SAFE, INJECTION)`, so
`config.scalar_from_proba` -- which assumes the 4-class
`(benign, injection, jailbreak, harmful)` vector -- does not apply and this is
a separate class rather than a parameter on `V3TransformerDetector`. The score
is P(INJECTION).

**The positive class is resolved by name, not by index.** V3's checkpoint
carries only `LABEL_0..LABEL_3`, so `1 = injection` lived in a comment in a
training script and had to be verified empirically against the weights
(`plan.md` 2.25) -- precisely the class of bug that makes a below-chance AUROC
ambiguous. This checkpoint publishes `{0: SAFE, 1: INJECTION}`, so the adapter
reads it and raises if `positive_label` is absent. An index is never assumed.

## What this adapter does NOT claim

Loading a better-performing detector does not make this a guardrail. It ships
`inert` like every other classifier here, and promotion to a decision-carrying
role still requires a calibration run on this surface plus a deliberate policy
edit. The 512-token window problem is identical to V3's -- same backbone, same
limit -- so `truncate` and `chunk_max` are both implemented and the gap between
them is measured rather than assumed away.

The upstream model card states two limitations worth carrying here rather than
discovering later: it does not detect jailbreak attacks, and its authors do not
recommend it on system-prompt-like text because it produces false positives.
The second is directly relevant -- this project's `adversarial_styled` benign
reference is exactly that stress case. The project has also been archived
upstream, so the weights are frozen: fine for reproducibility, and a reason not
to build anything load-bearing on top of it.
"""

from __future__ import annotations

from typing import ClassVar

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from llmshield_mcp.config import GuardConfig
from llmshield_mcp.detectors.base import Detector, RawScore


class GuardDetector(Detector):
    """Binary injection classifier fetched from the Hugging Face Hub."""

    name: ClassVar[str] = "guard"

    def __init__(self, config: GuardConfig) -> None:
        self._config = config

        # `revision` is a pinned commit SHA (validated in config.py), so this
        # resolves to exactly one immutable snapshot. transformers caches it
        # under HF_HOME; nothing is written inside this repository.
        self._tokenizer = AutoTokenizer.from_pretrained(config.repo, revision=config.revision)
        self._model = AutoModelForSequenceClassification.from_pretrained(
            config.repo, revision=config.revision
        )
        self._model.eval()
        self._model.to(config.device)

        id2label = dict(self._model.config.id2label)
        self._labels: tuple[str, ...] = tuple(
            str(id2label[index]) for index in sorted(id2label, key=int)
        )
        wanted = config.positive_label
        matches = [i for i, name in enumerate(self._labels) if name == wanted]
        if not matches:
            raise ValueError(
                f"{config.repo}@{config.revision[:8]} has labels {list(self._labels)}, "
                f"which do not include positive_label {wanted!r}. Fix "
                f"config/models.yaml:guard.positive_label rather than guessing an index."
            )
        self._positive_index = matches[0]

    @property
    def labels(self) -> tuple[str, ...]:
        """The checkpoint's own class names, in index order."""
        return self._labels

    @property
    def positive_index(self) -> int:
        """Index the score is read from, resolved from `labels`."""
        return self._positive_index

    @torch.no_grad()
    def _score(self, text: str) -> RawScore:
        # Same windowing as V3: the tokenizer's sliding window handles special
        # tokens per window, and `stride` is the token overlap, so an injection
        # straddling a boundary is not diluted in both halves.
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
            # SEC-2: cap the work an oversized tool result can demand.
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

        scores = [float(p[self._positive_index]) for p in probabilities]
        best = max(range(len(scores)), key=scores.__getitem__)
        winning = probabilities[best]

        detail = {name: float(winning[i]) for i, name in enumerate(self._labels)}
        detail["n_windows_total"] = float(total_windows)
        detail["n_windows_scored"] = float(scored_windows)
        detail["winning_window"] = float(best)

        return RawScore(
            score=scores[best],
            detail=detail,
            truncated=scored_windows < total_windows,
        )
