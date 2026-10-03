"""Interchangeable detector adapters.

V0 and V3 are imported lazily. V3 pulls in torch and transformers, which cost
seconds of import time; V0 pulls in joblib and scikit-learn (and with them
numpy and scipy). Both live in the `research` extra, so a slim install does not
have them at all. Importing any submodule -- `toolgate.detectors.base` from the
proxy path, say -- runs this file first, so an eager import here would put the
scientific stack on the proxy's import graph, or fail outright without the
extra. The rules, PII and normalisation detectors need none of it.
"""

from typing import TYPE_CHECKING, Any

from toolgate.detectors.base import Detector, DetectorResult, RawScore, Span
from toolgate.detectors.normalise import Normalised, normalise, scan_normalised
from toolgate.detectors.pii import PiiDetector, redact
from toolgate.detectors.rules import Rule, RuleDetector, load_rules

if TYPE_CHECKING:
    from toolgate.detectors.v0_lexical import V0LexicalDetector
    from toolgate.detectors.v3_transformer import V3TransformerDetector

__all__ = [
    "Detector",
    "DetectorResult",
    "Normalised",
    "PiiDetector",
    "RawScore",
    "Rule",
    "RuleDetector",
    "Span",
    "V0LexicalDetector",
    "V3TransformerDetector",
    "load_rules",
    "normalise",
    "redact",
    "scan_normalised",
]


def __getattr__(name: str) -> Any:
    if name == "V0LexicalDetector":
        from toolgate.detectors.v0_lexical import V0LexicalDetector

        return V0LexicalDetector
    if name == "V3TransformerDetector":
        from toolgate.detectors.v3_transformer import V3TransformerDetector

        return V3TransformerDetector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
