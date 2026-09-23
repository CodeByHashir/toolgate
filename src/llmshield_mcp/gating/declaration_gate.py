"""Verification of tool declarations at the point they become model input (step 3).

Step 1 hashes a declaration, step 2 remembers it. This is where the answer is
used: every tool the agent is about to hand to the model is checked, and one
that policy refuses is dropped from the list rather than forwarded.

## Where this runs, and why not at the transport

Everything else in this package gates at the MCP transport boundary, which is
the right place for tool results: one code path for every transport. Tool
declarations are checked *after* `session.list_tools()` instead, and that is a
deliberate departure with a measured reason.

`docs/PLAN-DECLARATION-INTEGRITY.md` §5.4 left open whether client-side caching
could make a pin verify something the agent never saw. Checked against the
pinned `mcp==2.1.1`:

- `ClientSession.list_tools()` calls `send_request` unconditionally, so on the
  API this project uses every listing does cross the transport. A transport-
  layer check would see them all.
- But `ClientSession._absorb_tool_listing()` mutates the result *after* the
  transport hands it over, and it **drops** tools whose `x-mcp-header`
  annotations are invalid. The transport therefore sees a superset of what the
  agent receives.
- And the higher-level `mcp.client.client.Client` keeps a response cache
  (SEP-2549) whose own comment records that "a cache hit skips
  `session.list_tools`". On that API a transport-layer check sees nothing at
  all while the model is handed a full tool list.

A control that verifies bytes the model did not receive, or misses bytes it
did, is worse than no control: it converts an unknown into a false assurance.
So verification is anchored to the object the agent actually uses. The tuple
this module returns is the tuple that becomes `ToolParam`, which makes the
guarantee structural rather than a property of the call graph staying the same.

`test_gating_declaration_gate.py` asserts it against the tool list the fake
Anthropic client receives, rather than against this docstring.

## Shadowing is reported, not collapsed into the pin verdict

A tool name already declared by another server is a different fact from "this
declaration changed", and a declaration can be both at once. Folding them into
one enum would lose whichever lost the precedence argument, so `pin` and
`shadowed_by` are separate fields on the report -- the same reasoning that kept
concealment orthogonal in step 1.

Ownership is first-declared-wins within one gate's lifetime, in the order
`config/servers.yaml` lists servers. That order is deterministic for a given
config, and it is stated rather than hidden: if a malicious server is listed
first it owns the name and the honest one is reported as the shadow. Reading
the report as "these two servers both declare this name" is always correct;
reading it as "the second one is the attacker" is not.

Only admitted tools claim a name. A dropped declaration never reaches the
model, so it must not be able to reserve a name against a later server.
A server does not shadow itself: `shadowed_by` is set only when the name is
owned by a *different* server.

A name declared twice inside one listing is not a shadowing case and is not
treated as one. It does not need to be: the first copy is pinned on sight, so
the second is compared against it and comes back `mutated` if it differs --
which is the more informative verdict anyway, since it names the fields.

### What shadowing actually costs in *this* agent, honestly

`agent.py` qualifies every tool as `<server>__<tool>` before the model sees it,
so two servers declaring `read_file` become two distinct model-visible names.
The substitution attack -- server B silently receiving calls meant for server A
-- is therefore not available here, by construction and not by this module.
What remains is that the model is offered two similarly-named, similarly-
described tools and may pick the wrong one, which is a real but weaker problem.
A client that does not qualify names has the full version of the attack, which
is why the verdict is reported rather than dropped as inapplicable.

## Off by default, in two layers

`open_servers()` takes no gate unless one is passed, and a `DeclarationPolicy`
with no `tool_declarations` block in the YAML reports `enabled = False`, so the
caller builds no gate at all. Nothing is pinned, nothing is logged, nothing is
withheld.

When the block *is* present, its shipped defaults escalate rather than block
(`gating/declaration_policy.py`): every verdict is recorded and the model still
receives every declaration. That intermediate state is deliberate -- an
operator can run the layer in observe-only mode and see what their servers
actually do before any tool is withheld, which matters because the benign-churn
base rate is unmeasured until plan §3.1.

## What gets logged

One `Outcome.TOOL_DECLARATION` row per tool per listing, including the
uninteresting ones. Tens of rows per session, against thousands for tool
results, so the volume is not the reason to be selective -- and a log that
omits "this was fine" cannot distinguish a clean check from a check that never
ran.

Rows carry the verdict, the field *names* that moved, the combined digest, and
the action. Never a field value: a description can carry exactly the payload
this layer exists to catch, and SEC-3 keeps it off disk.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import mcp_types

from llmshield_mcp.gating.audit import Decision, DecisionLog, DecisionRecord, Outcome
from llmshield_mcp.gating.declaration_policy import (
    DeclarationAction,
    DeclarationDecision,
    DeclarationPolicy,
    evaluate_declaration,
)
from llmshield_mcp.gating.declarations import hash_declaration
from llmshield_mcp.gating.pins import (
    DeclarationVerdict,
    PinStore,
    PinStoreCorrupt,
    PinVerdict,
)

#: How a declaration action appears in the shared decision log. The audit
#: vocabulary has a `REDACT` this layer can never produce: a declaration is
#: withheld whole or forwarded whole, never partially rewritten, because
#: editing a tool's description before handing it to the model would make the
#: pin describe bytes the model never saw.
_AUDIT_DECISION: dict[DeclarationAction, Decision] = {
    DeclarationAction.ALLOW: Decision.ALLOW,
    DeclarationAction.ESCALATE: Decision.ESCALATE,
    DeclarationAction.BLOCK: Decision.BLOCK,
}

#: Decides whether a declaration is withheld from the model. Step 4 supplies a
#: policy-driven one; `None` withholds nothing.
BlockPredicate = Callable[["DeclarationReport"], bool]


@dataclass(frozen=True, slots=True)
class DeclarationReport:
    """One tool declaration, checked."""

    pin: PinVerdict
    #: Server that already declared this tool name, if any. Independent of
    #: `pin.verdict` -- a declaration can be unchanged *and* shadowing.
    shadowed_by: str | None = None
    #: False when the declaration was withheld from the model.
    admitted: bool = True

    @property
    def server(self) -> str:
        return self.pin.server

    @property
    def tool(self) -> str:
        return self.pin.tool

    @property
    def verdict(self) -> DeclarationVerdict:
        return self.pin.verdict

    @property
    def is_actionable(self) -> bool:
        """Anything an operator would want to look at."""
        return self.pin.is_actionable or self.shadowed_by is not None

    def summary(self) -> str:
        """A log line. Field names and verdicts only, never field values."""
        parts = [f"{self.server}/{self.tool}", self.pin.verdict.value]
        if self.pin.changed:
            parts.append("changed=" + ",".join(self.pin.changed))
        if self.pin.concealed:
            new = "+new" if self.pin.concealment_is_new else ""
            parts.append(f"concealed{new}=" + ",".join(self.pin.concealed))
        if self.shadowed_by is not None:
            parts.append(f"shadows={self.shadowed_by}")
        if not self.admitted:
            parts.append("withheld")
        return " ".join(parts)


@dataclass
class DeclarationGate:
    """Pin stores for every connected server, plus the cross-server name view."""

    #: Where `<server>.json` lives. `None` uses `pins/` under the repo root.
    directory: Path | None = None
    #: The `tool_declarations` block. A disabled policy withholds nothing.
    policy: DeclarationPolicy = field(default_factory=DeclarationPolicy)
    #: Where verdicts are recorded. `None` keeps them in `reports` only.
    log: DecisionLog | None = None
    #: An override used by tests and by callers that want a one-off rule
    #: without a policy file. Takes precedence over `policy` when set.
    block: BlockPredicate | None = None
    #: False keeps pins in memory only -- used by tests and by a dry run that
    #: should not leave a trust decision behind.
    persist: bool = True
    stores: dict[str, PinStore] = field(default_factory=dict)
    #: Tool name -> the server that first admitted it.
    owners: dict[str, str] = field(default_factory=dict)
    #: Every report this gate has produced, in order, for logging and tests.
    reports: list[DeclarationReport] = field(default_factory=list)
    #: Servers whose pin store could not be read, and the reason.
    pin_errors: dict[str, str] = field(default_factory=dict)

    def store_for(self, server: str) -> PinStore:
        """The pin store for one server, loaded on first use.

        Raises `PinStoreCorrupt` unchanged. `admit()` is where the policy
        decides what that means; a caller using `inspect()` directly gets the
        exception, because there is no sensible verdict for "the pin store is
        unreadable" that is not a policy choice.
        """
        store = self.stores.get(server)
        if store is None:
            store = PinStore.load(server, directory=self.directory)
            self.stores[server] = store
        return store

    def inspect(
        self, server: str, tools: Sequence[mcp_types.Tool]
    ) -> tuple[DeclarationReport, ...]:
        """Check one server's listing. Pins unseen tools; withholds nothing."""
        store = self.store_for(server)
        reports: list[DeclarationReport] = []
        for tool in tools:
            hashes = hash_declaration(tool)
            verdict = store.verify_hashes(tool.name, hashes)
            if verdict.verdict is DeclarationVerdict.NEW:
                # Trust on first use, recorded through `record_hashes` rather
                # than `observe`/`accept` so the declaration is hashed once per
                # listing rather than twice.
                store.record_hashes(tool.name, hashes)
            owner = self.owners.get(tool.name)
            reports.append(
                DeclarationReport(
                    pin=verdict,
                    shadowed_by=owner if owner is not None and owner != server else None,
                )
            )
        return tuple(reports)

    def _decide(self, report: DeclarationReport) -> DeclarationDecision:
        if self.block is not None:
            action = DeclarationAction.BLOCK if self.block(report) else DeclarationAction.ALLOW
            return DeclarationDecision(action=action)
        return evaluate_declaration(
            self.policy,
            report.server,
            report.tool,
            verdict=report.pin.verdict.value,
            shadowed=report.shadowed_by is not None,
            concealed=bool(report.pin.concealed),
        )

    def admit(self, server: str, tools: Sequence[mcp_types.Tool]) -> tuple[mcp_types.Tool, ...]:
        """Check a listing and return the tools the model may be given.

        The returned tuple is the one the caller hands onward, which is what
        makes "a withheld declaration never reaches the model" structural
        rather than a claim about the call graph.

        An unreadable pin store is handled here rather than raised, because
        what it means is a policy question: `on_pin_error` decides, and it
        fails closed. Only that server's declarations are affected -- plan §2.3
        requires that withholding never breaks the session.
        """
        try:
            reports = self.inspect(server, tools)
        except PinStoreCorrupt as exc:
            return self._pin_store_unreadable(server, tools, exc)

        kept: list[mcp_types.Tool] = []
        for tool, report in zip(tools, reports, strict=True):
            decision = self._decide(report)
            settled = DeclarationReport(
                pin=report.pin,
                shadowed_by=report.shadowed_by,
                admitted=not decision.blocked,
            )
            self.reports.append(settled)
            self._record(settled, decision)
            if decision.blocked:
                continue
            # Only an admitted tool claims the name: a withheld declaration
            # never reaches the model, so it must not reserve a name against a
            # server that connects later.
            self.owners.setdefault(tool.name, server)
            kept.append(tool)

        if self.persist:
            self.save()
        return tuple(kept)

    def _pin_store_unreadable(
        self, server: str, tools: Sequence[mcp_types.Tool], exc: PinStoreCorrupt
    ) -> tuple[mcp_types.Tool, ...]:
        """Apply `on_pin_error` to a whole listing that could not be verified.

        Nothing is pinned: writing fresh pins over a store that failed to load
        would overwrite whatever evidence it still holds, and would turn a
        damaged pin file into a clean trust-on-first-use in one step -- the
        exact silent reset `PinStoreCorrupt` exists to prevent.
        """
        self.pin_errors[server] = str(exc)
        action = self.policy.on_pin_error
        for tool in tools:
            self._record_unverified(server, tool.name, action, str(exc))
        if action is DeclarationAction.BLOCK:
            return ()
        return tuple(tools)

    def _record(self, report: DeclarationReport, decision: DeclarationDecision) -> None:
        if self.log is None:
            return
        contradicts = report.pin.verdict is DeclarationVerdict.NEW and self.log.declaration_seen(
            report.server, report.tool
        )
        note = report.summary()
        if decision.condition:
            note = f"{note} action={decision.action.value}:{decision.condition}"
        if contradicts:
            # A first sighting for a tool this log already pinned means the pin
            # file and the log disagree. See `DecisionLog.declaration_seen`.
            note = f"{note} contradicts-log"
        self.log.append(
            DecisionRecord(
                correlation_id=uuid.uuid4().hex,
                mcp_server_id=report.server,
                tool_name=report.tool,
                # A digest, not content -- the column's existing meaning.
                raw_result_hash=report.pin.combined or "",
                fused_decision=_AUDIT_DECISION[decision.action],
                latency_ms=0.0,
                outcome=Outcome.TOOL_DECLARATION,
                detector_scores={
                    "verdict": report.pin.verdict.value,
                    "changed": list(report.pin.changed),
                    "concealed": list(report.pin.concealed),
                    "shadowed_by": report.shadowed_by,
                    "conditions": list(decision.conditions),
                    "contradicts_log": contradicts,
                },
                note=note,
            )
        )

    def _record_unverified(
        self, server: str, tool: str, action: DeclarationAction, reason: str
    ) -> None:
        if self.log is None:
            return
        self.log.append(
            DecisionRecord(
                correlation_id=uuid.uuid4().hex,
                mcp_server_id=server,
                tool_name=tool,
                raw_result_hash="",
                fused_decision=_AUDIT_DECISION[action],
                latency_ms=0.0,
                outcome=Outcome.TOOL_DECLARATION,
                detector_scores={"verdict": "pin_store_error"},
                # The exception text names a path and a parse failure, never a
                # declaration's content.
                note=f"pin store unreadable: {reason}",
            )
        )

    def save(self) -> None:
        for store in self.stores.values():
            if store.dirty:
                store.save()

    def actionable(self) -> tuple[DeclarationReport, ...]:
        """Every report an operator would want to see."""
        return tuple(report for report in self.reports if report.is_actionable)


__all__ = [
    "BlockPredicate",
    "DeclarationGate",
    "DeclarationReport",
]
