"""Tests for the `tool_declarations` policy block and its enforcement (step 4).

Three things carry the weight: strict loading (a typo in a security rule is a
silently weaker posture), most-severe-wins across conditions, and failing
closed when the pin store cannot be read.
"""

from __future__ import annotations

from pathlib import Path

import mcp_types
import pytest

from llmshield_mcp.gating.audit import Decision, DecisionLog, Outcome
from llmshield_mcp.gating.declaration_gate import DeclarationGate
from llmshield_mcp.gating.declaration_policy import (
    CONDITIONS,
    DeclarationAction,
    DeclarationPolicy,
    evaluate_declaration,
    load_declaration_policy,
)
from llmshield_mcp.gating.pins import PIN_SCHEMA_VERSION


def tag_encode(text: str) -> str:
    return "".join(chr(0xE0000 + (ord(char) & 0x7F)) for char in text)


def make_tool(name: str = "read_file", **overrides: object) -> mcp_types.Tool:
    payload: dict[str, object] = {
        "name": name,
        "description": "Reads a file from the workspace.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    }
    payload.update(overrides)
    return mcp_types.Tool.model_validate(payload)


def decide(policy: DeclarationPolicy, verdict: str, **kwargs: bool) -> DeclarationAction:
    return evaluate_declaration(
        policy,
        "filesystem",
        "read_file",
        verdict=verdict,
        shadowed=kwargs.get("shadowed", False),
        concealed=kwargs.get("concealed", False),
    ).action


# --- loading --------------------------------------------------------------


def test_an_absent_block_is_disabled() -> None:
    """How this ships: no block, no gate, no behaviour."""
    policy = load_declaration_policy(None)

    assert not policy.enabled
    assert policy.on_pin_error is DeclarationAction.BLOCK


def test_an_empty_block_is_enabled_with_shipped_defaults() -> None:
    policy = load_declaration_policy({})

    assert policy.enabled
    assert decide(policy, "new") is DeclarationAction.ALLOW
    assert decide(policy, "mutated") is DeclarationAction.ESCALATE
    assert decide(policy, "stale_pin") is DeclarationAction.ESCALATE
    assert decide(policy, "unchanged", shadowed=True) is DeclarationAction.ESCALATE
    assert decide(policy, "unchanged", concealed=True) is DeclarationAction.ESCALATE


def test_nothing_blocks_by_default() -> None:
    """Benign churn is unmeasured, so blocking is not a default."""
    policy = load_declaration_policy({})

    for condition in CONDITIONS:
        assert decide(policy, condition, shadowed=True, concealed=True) is not (
            DeclarationAction.BLOCK
        )


def test_a_default_action_can_be_overridden() -> None:
    policy = load_declaration_policy({"default": {"mutated": "block"}})

    assert decide(policy, "mutated") is DeclarationAction.BLOCK
    assert decide(policy, "new") is DeclarationAction.ALLOW


def test_a_per_tool_rule_overrides_the_default() -> None:
    policy = load_declaration_policy(
        {
            "default": {"mutated": "escalate"},
            "rules": {"filesystem.read_file": {"mutated": "block"}},
        }
    )

    assert decide(policy, "mutated") is DeclarationAction.BLOCK
    assert (
        evaluate_declaration(
            policy, "filesystem", "other", verdict="mutated", shadowed=False, concealed=False
        ).action
        is DeclarationAction.ESCALATE
    )


def test_a_rule_falls_back_to_the_default_for_conditions_it_omits() -> None:
    policy = load_declaration_policy(
        {
            "default": {"concealed": "block"},
            "rules": {"filesystem.read_file": {"mutated": "escalate"}},
        }
    )

    assert decide(policy, "unchanged", concealed=True) is DeclarationAction.BLOCK


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("not a mapping", "tool_declarations must be a mapping"),
        ({"nonsense": {}}, "unknown keys"),
        ({"default": {"mutatedd": "block"}}, "not one of"),
        ({"default": {"mutated": "banish"}}, "not one of"),
        ({"default": "block"}, "must be a mapping"),
        ({"rules": "no"}, "must be a mapping"),
        ({"rules": {"read_file": {"mutated": "block"}}}, "<server>.<tool>"),
        ({"on_pin_error": "shrug"}, "not one of"),
    ],
)
def test_a_malformed_block_is_rejected_at_load_time(raw: object, message: str) -> None:
    """A typo in a security rule must not become a silently weaker posture."""
    with pytest.raises(ValueError, match=message):
        load_declaration_policy(raw)


def test_an_unknown_condition_is_an_error_not_an_ignored_key() -> None:
    # `mutatedd: block` that quietly does nothing is the failure mode this
    # refuses to have.
    with pytest.raises(ValueError, match="mutatedd"):
        load_declaration_policy({"default": {"mutatedd": "block"}})


# --- most severe wins -----------------------------------------------------


def test_the_most_severe_condition_wins() -> None:
    policy = load_declaration_policy({"default": {"mutated": "escalate", "concealed": "block"}})

    assert decide(policy, "mutated", concealed=True) is DeclarationAction.BLOCK


def test_severity_is_taken_not_first_match() -> None:
    """Order of conditions must not decide the outcome."""
    policy = load_declaration_policy({"default": {"new": "block", "concealed": "escalate"}})

    assert decide(policy, "new", concealed=True) is DeclarationAction.BLOCK


def test_the_winning_condition_is_named() -> None:
    policy = load_declaration_policy({"default": {"mutated": "escalate", "shadowed": "block"}})

    decision = evaluate_declaration(
        policy, "filesystem", "read_file", verdict="mutated", shadowed=True, concealed=False
    )

    assert decision.condition == "shadowed"
    assert decision.conditions == ("mutated", "shadowed")


def test_an_unchanged_clean_declaration_meets_no_condition() -> None:
    policy = load_declaration_policy({"default": {"mutated": "block"}})

    decision = evaluate_declaration(
        policy, "filesystem", "read_file", verdict="unchanged", shadowed=False, concealed=False
    )

    assert decision.action is DeclarationAction.ALLOW
    assert decision.conditions == ()


# --- enforcement through the gate ----------------------------------------


def test_a_policy_block_withholds_the_declaration(tmp_path: Path) -> None:
    gate = DeclarationGate(
        directory=tmp_path,
        policy=load_declaration_policy({"default": {"mutated": "block"}}),
        persist=False,
    )
    gate.admit("filesystem", [make_tool()])

    kept = gate.admit("filesystem", [make_tool(description="poisoned")])

    assert kept == ()
    assert gate.reports[-1].admitted is False


def test_escalate_logs_but_forwards(tmp_path: Path) -> None:
    """Escalate must change nothing about what the model receives."""
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}), persist=False)
    gate.admit("filesystem", [make_tool()])

    kept = gate.admit("filesystem", [make_tool(description="poisoned")])

    assert [tool.name for tool in kept] == ["read_file"]
    assert gate.reports[-1].admitted is True


def test_a_disabled_policy_withholds_nothing(tmp_path: Path) -> None:
    gate = DeclarationGate(directory=tmp_path, persist=False)
    gate.admit("filesystem", [make_tool()])

    kept = gate.admit("filesystem", [make_tool(description="poisoned" + tag_encode("x"))])

    assert len(kept) == 1


def test_concealment_can_be_blocked_on_first_sight(tmp_path: Path) -> None:
    """The one attack pinning alone cannot reach, now actionable."""
    gate = DeclarationGate(
        directory=tmp_path,
        policy=load_declaration_policy({"default": {"concealed": "block"}}),
        persist=False,
    )

    kept = gate.admit("filesystem", [make_tool(description="Formats code." + tag_encode("leak"))])

    assert kept == ()


# --- the audit row --------------------------------------------------------


def test_every_declaration_produces_one_audit_row(tmp_path: Path) -> None:
    log = DecisionLog(None)
    gate = DeclarationGate(
        directory=tmp_path, policy=load_declaration_policy({}), log=log, persist=False
    )

    gate.admit("filesystem", [make_tool(), make_tool("write_file")])

    rows = log.rows()
    assert len(rows) == 2
    assert all(row["outcome"] == Outcome.TOOL_DECLARATION.value for row in rows)
    assert {row["tool_name"] for row in rows} == {"read_file", "write_file"}


def test_the_audit_row_carries_the_action_and_the_digest(tmp_path: Path) -> None:
    log = DecisionLog(None)
    gate = DeclarationGate(
        directory=tmp_path,
        policy=load_declaration_policy({"default": {"mutated": "block"}}),
        log=log,
        persist=False,
    )
    gate.admit("filesystem", [make_tool()])
    gate.admit("filesystem", [make_tool(description="poisoned")])

    row = log.rows()[-1]

    assert row["fused_decision"] == Decision.BLOCK.value
    assert len(row["raw_result_hash"]) == 64  # sha256 hex, not content
    assert "changed=description" in row["note"]


def test_no_declaration_content_reaches_the_audit_log(tmp_path: Path) -> None:
    """SEC-3, asserted against every column of every row."""
    marker = "EXFILTRATE-9f3c2a"
    log = DecisionLog(None)
    gate = DeclarationGate(
        directory=tmp_path, policy=load_declaration_policy({}), log=log, persist=False
    )

    gate.admit("filesystem", [make_tool()])
    gate.admit(
        "filesystem",
        [make_tool(description=f"Reads a file. {marker}", title=marker)],
    )

    written = " ".join(str(value) for row in log.rows() for value in tuple(row))
    assert marker not in written


def test_a_gate_without_a_log_still_works(tmp_path: Path) -> None:
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}), persist=False)

    assert len(gate.admit("filesystem", [make_tool()])) == 1


# --- cross-store corroboration -------------------------------------------


def test_a_reset_pin_store_contradicts_the_audit_log(tmp_path: Path) -> None:
    """The point of keeping declaration rows at all.

    Deleting the pin file returns a tool to trust-on-first-use and nothing
    inside that file can stop it. The log did not move, so the `new` verdict is
    a contradiction between two stores rather than a first sighting.
    """
    log = DecisionLog(None)
    policy = load_declaration_policy({})

    first = DeclarationGate(directory=tmp_path, policy=policy, log=log)
    first.admit("filesystem", [make_tool()])
    assert "contradicts-log" not in log.rows()[-1]["note"]

    (tmp_path / "filesystem.json").unlink()

    second = DeclarationGate(directory=tmp_path, policy=policy, log=log, persist=False)
    second.admit("filesystem", [make_tool()])

    assert "contradicts-log" in log.rows()[-1]["note"]


def test_declaration_seen_only_matches_declaration_rows(tmp_path: Path) -> None:
    log = DecisionLog(None)
    gate = DeclarationGate(
        directory=tmp_path, policy=load_declaration_policy({}), log=log, persist=False
    )
    gate.admit("filesystem", [make_tool()])

    assert log.declaration_seen("filesystem", "read_file")
    assert not log.declaration_seen("filesystem", "other_tool")
    assert not log.declaration_seen("other_server", "read_file")


# --- an unreadable pin store fails closed --------------------------------


def _corrupt(directory: Path) -> None:
    (directory / "filesystem.json").write_text("{not json", encoding="utf-8")


def test_an_unreadable_pin_store_withholds_that_server_by_default(tmp_path: Path) -> None:
    _corrupt(tmp_path)
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}), persist=False)

    kept = gate.admit("filesystem", [make_tool(), make_tool("write_file")])

    assert kept == ()
    assert "filesystem" in gate.pin_errors


def test_an_unreadable_pin_store_can_be_configured_to_escalate(tmp_path: Path) -> None:
    _corrupt(tmp_path)
    gate = DeclarationGate(
        directory=tmp_path,
        policy=load_declaration_policy({"on_pin_error": "escalate"}),
        persist=False,
    )

    kept = gate.admit("filesystem", [make_tool()])

    assert len(kept) == 1
    assert "filesystem" in gate.pin_errors


def test_an_unreadable_pin_store_does_not_break_other_servers(tmp_path: Path) -> None:
    """Withholding must never take the session down (plan 2.3)."""
    _corrupt(tmp_path)
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}), persist=False)

    assert gate.admit("filesystem", [make_tool()]) == ()
    assert len(gate.admit("fetch", [make_tool("fetch")])) == 1


def test_a_damaged_pin_store_is_not_overwritten_with_fresh_pins(tmp_path: Path) -> None:
    """Otherwise a corrupt file becomes a clean TOFU in one step.

    That is precisely the silent reset `PinStoreCorrupt` exists to prevent, so
    the gate must not "repair" the store by pinning over it.
    """
    _corrupt(tmp_path)
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}))

    gate.admit("filesystem", [make_tool()])

    assert (tmp_path / "filesystem.json").read_text(encoding="utf-8") == "{not json"


def test_the_pin_store_failure_is_logged(tmp_path: Path) -> None:
    _corrupt(tmp_path)
    log = DecisionLog(None)
    gate = DeclarationGate(
        directory=tmp_path, policy=load_declaration_policy({}), log=log, persist=False
    )

    gate.admit("filesystem", [make_tool()])

    row = log.rows()[-1]
    assert row["outcome"] == Outcome.TOOL_DECLARATION.value
    assert row["fused_decision"] == Decision.BLOCK.value
    assert "pin store unreadable" in row["note"]


def test_a_stale_schema_version_also_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "filesystem.json").write_text(
        f'{{"schema_version": {PIN_SCHEMA_VERSION + 1}, "tools": {{}}}}', encoding="utf-8"
    )
    gate = DeclarationGate(directory=tmp_path, policy=load_declaration_policy({}), persist=False)

    assert gate.admit("filesystem", [make_tool()]) == ()


# --- the policy file plumbing --------------------------------------------


def test_the_shipped_policy_file_leaves_declaration_gating_off() -> None:
    """The layer must add nothing for anyone who has not opted in."""
    from llmshield_mcp.gating.policy import load_policy_config

    assert not load_policy_config().tool_declarations.enabled


def test_a_policy_file_with_the_block_enables_it(tmp_path: Path) -> None:
    from llmshield_mcp.gating.policy import load_policy_config

    path = tmp_path / "policy.yaml"
    path.write_text(
        "calibrated: false\n"
        "on_detector_failure: escalate\n"
        "detectors:\n"
        "  injection: [rules_mcp]\n"
        "tool_declarations:\n"
        "  default:\n"
        "    mutated: block\n"
        "  on_pin_error: escalate\n",
        encoding="utf-8",
    )

    config = load_policy_config(path)

    assert config.tool_declarations.enabled
    assert config.tool_declarations.on_pin_error is DeclarationAction.ESCALATE
    assert decide(config.tool_declarations, "mutated") is DeclarationAction.BLOCK


def test_a_typo_in_the_policy_file_fails_at_load_not_at_runtime(tmp_path: Path) -> None:
    from llmshield_mcp.gating.policy import load_policy_config

    path = tmp_path / "policy.yaml"
    path.write_text(
        "calibrated: false\non_detector_failure: escalate\n"
        "tool_declarations:\n  default:\n    mutatedd: block\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="mutatedd"):
        load_policy_config(path)
