"""Policy for tool-declaration verdicts (step 4), parsed from `policy.yaml`.

Pure: no I/O, no clock, no state. The same report always gets the same action,
which is what lets this layer's behaviour be checked by reading the config
rather than by running the agent -- the same property `gating/tool_calls.py`
has, and for the same reason.

## Conditions, not verdicts

A declaration can be several things at once. It can be `mutated` *and*
concealed *and* shadowing another server's tool name. Steps 1-3 kept those as
separate fields precisely so none of them would be lost to a precedence
argument, so the policy is keyed on **conditions** rather than on a single
verdict:

    new | mutated | stale_pin | shadowed | concealed

`unchanged` has no key. A declaration byte-identical to its pin, carrying no
concealment and shadowing nothing, is the case this whole mechanism exists to
say nothing about.

When several conditions hold, the **most severe action wins** and the condition
that produced it is named in the audit row. Severity is
`allow < escalate < block`. Taking the maximum rather than a first match means
adding a rule can never accidentally weaken a verdict that another condition
already made stricter.

## Why `block` is not a default

The mechanism has no false-negative rate: a hash comparison either matches or
does not, so there is nothing to calibrate and `calibrated: false` does not
gate these blocks. That is the same argument `tool_calls` makes, and it holds.

What it does **not** mean is that blocking is safe to switch on by default. The
operationally relevant number is how often a legitimate server changes a
declaration -- benign churn -- and nobody has published it, including this
project (plan §3.1 is the measurement, step 5 is when it happens). A control
that fires on every routine upstream release is a control an operator turns
off, and `config/policy.yaml`'s own header records that lesson.

So the shipped defaults escalate, which logs and changes nothing about what the
model receives. `block` is one word away per condition, per tool, for an
operator who has decided their servers are stable enough.

## Failing when verification is impossible

`on_pin_error` decides what a corrupt or unreadable pin store means. It
defaults to `block`, which withholds that server's declarations rather than
forwarding them unverified: "the pin store is damaged" and "trust everything
again" must not be the same outcome.

Blocking is deliberately scoped to that server. Plan §2.3 requires that
withholding a declaration never breaks the session, so the agent keeps running
with whatever other servers verified cleanly, and the drop is logged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

#: Every condition a rule may name, in the order a tie is reported.
CONDITIONS: tuple[str, ...] = ("new", "mutated", "stale_pin", "shadowed", "concealed")


class DeclarationAction(StrEnum):
    """What to do about a declaration that meets a condition."""

    #: Hand the declaration to the model, with a log row.
    ALLOW = "allow"
    #: Hand it to the model anyway, but mark the row. Logs, changes nothing.
    ESCALATE = "escalate"
    #: Withhold it: the declaration never becomes a `ToolParam`.
    BLOCK = "block"


_SEVERITY: dict[DeclarationAction, int] = {
    DeclarationAction.ALLOW: 0,
    DeclarationAction.ESCALATE: 1,
    DeclarationAction.BLOCK: 2,
}

#: Shipped when a `tool_declarations` block is present but a condition is not
#: named. Escalate rather than block, for the churn reason in the module
#: docstring; `new` allows because trust on first use is the whole premise of
#: the pin store, and a first sighting is reported rather than refused.
DEFAULT_ACTIONS: dict[str, DeclarationAction] = {
    "new": DeclarationAction.ALLOW,
    "mutated": DeclarationAction.ESCALATE,
    "stale_pin": DeclarationAction.ESCALATE,
    "shadowed": DeclarationAction.ESCALATE,
    "concealed": DeclarationAction.ESCALATE,
}


@dataclass(frozen=True, slots=True)
class DeclarationRule:
    """Per-condition actions. `None` means "inherit the default block"."""

    actions: dict[str, DeclarationAction] = field(default_factory=dict)

    def action_for(
        self, condition: str, fallback: DeclarationRule | None = None
    ) -> DeclarationAction:
        if condition in self.actions:
            return self.actions[condition]
        if fallback is not None and condition in fallback.actions:
            return fallback.actions[condition]
        return DEFAULT_ACTIONS[condition]


@dataclass(frozen=True, slots=True)
class DeclarationPolicy:
    """The `tool_declarations` block of a policy file."""

    #: False when the block is absent, which is how this ships. The caller then
    #: builds no gate at all, so nothing is pinned and nothing is logged.
    enabled: bool = False
    default: DeclarationRule = field(default_factory=DeclarationRule)
    #: Keyed `"<server>.<tool>"`, e.g. `"filesystem.read_file"`.
    rules: dict[str, DeclarationRule] = field(default_factory=dict)
    #: What an unreadable pin store means. Fails closed.
    on_pin_error: DeclarationAction = DeclarationAction.BLOCK

    def rule_for(self, server: str, tool: str) -> DeclarationRule | None:
        return self.rules.get(f"{server}.{tool}")


@dataclass(frozen=True, slots=True)
class DeclarationDecision:
    """The action, and which condition earned it."""

    action: DeclarationAction
    #: The condition that produced `action`, or `""` when nothing applied.
    condition: str = ""
    #: Every condition that held, for the audit row.
    conditions: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.action is DeclarationAction.BLOCK


def conditions_of(verdict: str, *, shadowed: bool, concealed: bool) -> tuple[str, ...]:
    """Which policy conditions one report meets.

    Takes primitives rather than a `DeclarationReport` so this module stays
    free of an import cycle with the gate that applies it.
    """
    met = [name for name in ("new", "mutated", "stale_pin") if name == verdict]
    if shadowed:
        met.append("shadowed")
    if concealed:
        met.append("concealed")
    return tuple(name for name in CONDITIONS if name in met)


def evaluate_declaration(
    policy: DeclarationPolicy,
    server: str,
    tool: str,
    *,
    verdict: str,
    shadowed: bool,
    concealed: bool,
) -> DeclarationDecision:
    """Decide what to do about one declaration.

    The most severe applicable action wins, so a rule can only ever tighten a
    verdict another condition already reached.
    """
    met = conditions_of(verdict, shadowed=shadowed, concealed=concealed)
    if not met:
        return DeclarationDecision(action=DeclarationAction.ALLOW)

    rule = policy.rule_for(server, tool)
    best = DeclarationAction.ALLOW
    reason = ""
    for condition in met:
        action = (
            rule.action_for(condition, policy.default)
            if rule is not None
            else policy.default.action_for(condition)
        )
        if _SEVERITY[action] > _SEVERITY[best]:
            best, reason = action, condition
    return DeclarationDecision(action=best, condition=reason, conditions=met)


def _parse_actions(raw: Any, where: str) -> dict[str, DeclarationAction]:
    if not isinstance(raw, dict):
        raise ValueError(f"{where} must be a mapping of condition to action")
    actions: dict[str, DeclarationAction] = {}
    for key, value in raw.items():
        name = str(key)
        if name not in CONDITIONS:
            raise ValueError(f"{where}.{name} is not one of {list(CONDITIONS)}")
        try:
            actions[name] = DeclarationAction(value)
        except ValueError as exc:
            raise ValueError(
                f"{where}.{name} {value!r} is not one of "
                f"{sorted(a.value for a in DeclarationAction)}"
            ) from exc
    return actions


def load_declaration_policy(raw: Any) -> DeclarationPolicy:
    """Parse and validate a policy file's `tool_declarations` block.

    Strict, and at load time, for the reason `load_tool_call_policy` is: a typo
    in a security rule is a silently weaker posture, which is the worst way for
    a configuration error to present. An unknown condition name is an error
    rather than an ignored key, because `mutatedd: block` that quietly does
    nothing is exactly the failure this refuses to have.
    """
    if raw is None:
        return DeclarationPolicy()
    if not isinstance(raw, dict):
        raise ValueError("tool_declarations must be a mapping")

    unknown = set(raw) - {"default", "rules", "on_pin_error"}
    if unknown:
        raise ValueError(
            f"tool_declarations has unknown keys {sorted(unknown)}; "
            "expected 'default', 'rules', 'on_pin_error'"
        )

    default = DeclarationRule(
        actions=_parse_actions(raw.get("default") or {}, "tool_declarations.default")
    )

    error_raw = raw.get("on_pin_error", DeclarationAction.BLOCK.value)
    try:
        on_pin_error = DeclarationAction(error_raw)
    except ValueError as exc:
        raise ValueError(
            f"tool_declarations.on_pin_error {error_raw!r} is not one of "
            f"{sorted(a.value for a in DeclarationAction)}"
        ) from exc

    rules_raw = raw.get("rules") or {}
    if not isinstance(rules_raw, dict):
        raise ValueError("tool_declarations.rules must be a mapping")

    rules: dict[str, DeclarationRule] = {}
    for key, entry in rules_raw.items():
        where = f"tool_declarations.rules.{key}"
        if "." not in str(key):
            raise ValueError(
                f"{where}: rule keys are '<server>.<tool>', e.g. 'filesystem.read_file'"
            )
        rules[str(key)] = DeclarationRule(actions=_parse_actions(entry, where))

    return DeclarationPolicy(enabled=True, default=default, rules=rules, on_pin_error=on_pin_error)


__all__ = [
    "CONDITIONS",
    "DEFAULT_ACTIONS",
    "DeclarationAction",
    "DeclarationDecision",
    "DeclarationPolicy",
    "DeclarationRule",
    "conditions_of",
    "evaluate_declaration",
    "load_declaration_policy",
]
