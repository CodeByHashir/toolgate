"""Dual benign references (PROPOSAL.md section 8.2: "benign-realistic,
benign-adversarial-styled").

M6's `corpus.sources.load_benign()` (and everything ingested from it) is one
undifferentiated pool of real repository content, labelled `benign` with no
further split -- that was sufficient for M6's own verification bar, but GAUGE
needs the pool split into:

* **realistic** -- ordinary content, no detector-relevant vocabulary.
* **adversarial-styled** -- genuinely benign, but containing words a naive
  detector could plausibly trigger on (the `config_loader.py`-style
  false-positive risk PROPOSAL.md section 2 names explicitly, and the exact
  shape M1/M3 already found by hand: `sandbox/src/config_loader.py`
  deliberately contains "ignore all previous overrides").

The split is a MECHANICAL FILTER over already-real content, not new authored
sentences -- unlike the hand-written adversarial cases M3b's audit found were
contaminated by the author's own knowledge of the rule patterns (`plan.md`
section 2.13), nothing here invents what an attacker would say. The keyword
list below is deliberately broader than -- and independent of -- the actual
`INJ-*`/`MCP-*` regex patterns: those score 0 on every item in this corpus by
construction (M3b), which is exactly why a same-vocabulary filter would
produce an empty adversarial-styled set.
"""

from __future__ import annotations

import re

#: Broad, common prompt-injection-adjacent vocabulary. Independent of
#: config/rules.yaml's actual patterns (see module docstring) -- this is a
#: coarser net, meant to catch content a naive or aggressive detector might
#: flag, not a restatement of what this project's own rules match.
ADVERSARIAL_STYLE_KEYWORDS: tuple[str, ...] = (
    "ignore",
    "disregard",
    "override",
    "bypass",
    "instructions",
    "system prompt",
    "assistant",
    "jailbreak",
    "unrestricted",
    "reveal",
    "decode",
    "base64",
    "credentials",
    "password",
    "secret",
    "admin",
    "root",
    "exec",
    "eval",
    "sudo",
)

_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(keyword) for keyword in ADVERSARIAL_STYLE_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def is_adversarial_styled(text: str) -> bool:
    return _PATTERN.search(text) is not None


def partition_benign_references(items: list[str]) -> tuple[list[str], list[str]]:
    """Split `items` into `(realistic, adversarial_styled)`.

    Both references are calibrated and reported SEPARATELY by `gauge/run.py`,
    never conflated -- the same principle the reference dissertation's LOBO
    protocol states explicitly (`exp2_lobo.py`'s docstring).
    """
    realistic: list[str] = []
    adversarial_styled: list[str] = []
    for text in items:
        (adversarial_styled if is_adversarial_styled(text) else realistic).append(text)
    return realistic, adversarial_styled


__all__ = ["ADVERSARIAL_STYLE_KEYWORDS", "is_adversarial_styled", "partition_benign_references"]
