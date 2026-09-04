"""Interchangeable detector adapters.

V3 is imported lazily: it pulls in torch and transformers, which cost seconds
of import time. Nothing that only needs the detector contract or V0 should pay
that, and CI runs the contract tests without a torch install.
"""

from typing import TYPE_CHECKING, Any

from llmshield_mcp.detectors.base import Detector, DetectorResult, RawScore, Span
from llmshield_mcp.detectors.v0_lexical import V0LexicalDetector

if TYPE_CHECKING:
    from llmshield_mcp.detectors.v3_transformer import V3TransformerDetector

__all__ = [
    "Detector",
    "DetectorResult",
    "RawScore",
    "Span",
    "V0LexicalDetector",
    "V3TransformerDetector",
]


def __getattr__(name: str) -> Any:
    if name == "V3TransformerDetector":
        from llmshield_mcp.detectors.v3_transformer import V3TransformerDetector

        return V3TransformerDetector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
