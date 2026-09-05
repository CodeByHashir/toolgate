"""Rule-engine adapter: regex injection signatures (FR-2).

Ported from the LLMShield dissertation's `InjectionRuleEngine`
(`src/llmshield/pre_llm/rule_engine.py`) with the 19 rules carried across
verbatim in `config/rules.yaml`. The dissertation's implementation is not
imported: it implements a different interface (`InputScanner.scan(prompt,
PolicyConfig)`) and pulls in structlog and pydantic policy models this project
does not have. The reused asset is the rule data; the matching logic is a
handful of lines behind this project's own `Detector` contract.

One deliberate difference from the original. The dissertation calls
`pattern.search()`, recording only the first match of each rule, because it
only needed a binary flag for fusion. This adapter uses `finditer()` and
records every match as a `Span`, because FR-5 (Redact) has to mask *all*
offending regions, not just the first. The score is unaffected: it is binary
either way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import yaml

from llmshield_mcp.config import REPO_ROOT
from llmshield_mcp.detectors.base import Detector, RawScore, Span

DEFAULT_RULES_PATH = REPO_ROOT / "config" / "rules.yaml"

SEVERITIES = frozenset({"low", "medium", "high"})


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern[str]
    description: str = ""
    #: Rule family. `inj` is the dissertation's frozen 19; `mcp` is new work
    #: for the tool-result surface. Kept separate so the two can be enabled
    #: independently and their contributions measured apart -- the INJ-* set is
    #: the comparability baseline and must not be diluted by new rules.
    family: str = "inj"


def load_rules(
    path: Path | None = None, families: frozenset[str] | None = None
) -> tuple[Rule, ...]:
    """Read and compile the rule set.

    Compilation happens here rather than per scan so that a malformed pattern
    fails at construction instead of midway through an evaluation run, and so
    the regex cost is paid once.
    """
    rules_path = path or DEFAULT_RULES_PATH
    raw: Any = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{rules_path} did not parse to a mapping")

    entries = raw.get("rules")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{rules_path} defines no rules")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"{rules_path}: rule entry is not a mapping")
        for required in ("id", "pattern", "severity"):
            if required not in entry:
                raise KeyError(f"{rules_path}: rule is missing '{required}'")

        rule_id = str(entry["id"])
        if rule_id in seen:
            # A duplicate id would make a matched rule ambiguous in the log
            # and double-count it in any per-rule analysis.
            raise ValueError(f"{rules_path}: duplicate rule id {rule_id!r}")
        seen.add(rule_id)

        severity = str(entry["severity"])
        if severity not in SEVERITIES:
            raise ValueError(
                f"{rules_path}: rule {rule_id} has severity {severity!r}, "
                f"expected one of {sorted(SEVERITIES)}"
            )

        if not entry.get("enabled", True):
            continue

        family = str(entry.get("family", "inj"))
        if families is not None and family not in families:
            continue

        try:
            compiled = re.compile(str(entry["pattern"]), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"{rules_path}: rule {rule_id} has an invalid pattern: {exc}") from exc

        rules.append(
            Rule(
                id=rule_id,
                severity=severity,
                pattern=compiled,
                description=str(entry.get("description", "")),
                family=family,
            )
        )

    if not rules:
        raise ValueError(f"{rules_path}: every rule is disabled")
    return tuple(rules)


class RuleDetector(Detector):
    """Binary regex detector over the injection rule set."""

    name: ClassVar[str] = "rules"

    def __init__(
        self,
        rules: tuple[Rule, ...] | None = None,
        families: frozenset[str] | None = None,
    ) -> None:
        self._rules = rules if rules is not None else load_rules(families=families)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def _score(self, text: str) -> RawScore:
        spans: list[Span] = []
        # detail maps rule id -> 1.0 for each rule that fired. It is numeric by
        # the contract's type, so no matched text can reach a log through it
        # (SEC-3 / NFR-4); spans carry offsets, never content.
        detail: dict[str, float] = {}

        for rule in self._rules:
            matched = False
            for match in rule.pattern.finditer(text):
                spans.append(Span(start=match.start(), end=match.end(), label=rule.id))
                matched = True
            if matched:
                detail[rule.id] = 1.0

        # Binary, as in the dissertation: the rule engine asserts "a known
        # signature is present", not how confident it is. Severity is policy's
        # business (M4), not the detector's.
        return RawScore(score=1.0 if spans else 0.0, detail=detail, spans=tuple(spans))
