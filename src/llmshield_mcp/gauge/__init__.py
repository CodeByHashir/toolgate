"""The GAUGE evaluation protocol: statistics, calibration, and the harness (M7)."""

from llmshield_mcp.gauge.calibrate import CalibrationResult, attack_success_rate, threshold_at_fpr
from llmshield_mcp.gauge.references import partition_benign_references
from llmshield_mcp.gauge.stats import (
    DelongResult,
    Interval,
    McNemarResult,
    auroc_delong,
    clopper_pearson_ci,
    mcnemar_test,
    wilson_ci,
)

__all__ = [
    "CalibrationResult",
    "DelongResult",
    "Interval",
    "McNemarResult",
    "attack_success_rate",
    "auroc_delong",
    "clopper_pearson_ci",
    "mcnemar_test",
    "partition_benign_references",
    "threshold_at_fpr",
    "wilson_ci",
]
