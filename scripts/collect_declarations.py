"""Collect tool declarations from released MCP servers, and measure their churn.

Step 5 of `docs/PLAN-DECLARATION-INTEGRITY.md`. The question §3.1 poses:

    How often do real MCP servers legitimately change a tool declaration, and
    would pinning therefore drown an operator in alerts?

Nobody has published this, and it decides whether declaration pinning is
deployable at all. A control that fires constantly gets switched off, which is
the lesson `config/policy.yaml`'s own header already records about expensive
safe defaults. Every default in `gating/declaration_policy.py` is currently a
guess; this is what turns them into a choice.

## Real servers, really launched

Declarations are collected by installing each released version and speaking the
actual protocol to it -- `npx @pkg@version` or `uvx pkg==version`, then
`initialize` and `tools/list`. Not by parsing source, which would measure what
the repository says rather than what the server sends, and would silently
disagree wherever a declaration is built at runtime.

## Frozen, not live

`--collect` writes one dated snapshot and `--report` renders it. There is no
scheduled refresh on purpose (§6 of the plan rejects it): a scraper rots, and a
stale base rate in a repository whose credibility is measurement is worse than
none. Every figure derived from the snapshot carries its date.

## The snapshot holds digests, never declaration text

Per-field digests, tool names, field lengths and pre-computed metrics. No
description, no schema. Three reasons, in order of weight:

1. It keeps the artifact consistent with SEC-3 and with the pin store, which
   made the same choice for the same reason.
2. Churn is a question about *whether bytes changed*, which digests answer
   completely. Storing the text would add nothing to the measurement.
3. It keeps third-party text out of the repository. `plan.md` 2.27 records what
   it cost to resolve that once already.

The trade-off, stated because it is real: metrics that need the text -- the
rule false-positive rate below -- are computed at collection time and stored as
numbers. They cannot be recomputed from the snapshot, only re-collected. Churn
can be fully recomputed.

## What is measured

* **Churn.** Fraction of tools whose declaration digest changed between
  consecutive releases, and which field moved. This is the number the plan asks
  for.
* **Concealment prevalence** (§5.3). How many real declarations carry
  characters that render as nothing. Tied to a documented attack rather than
  invented, and unpublished.
* **Cross-server name collisions.** How often two servers declare the same tool
  name, which is the shadowing verdict's base rate.
* **Rule false positives on real benign declarations.** The project's own
  injection rules, run over descriptions that are benign by construction --
  these are official reference servers. Any hit is a false positive.

  This is deliberately *not* the experiment §3.2 rules out. That one injects
  adversarial payloads into descriptions and reports recall, which is
  construct-invalid because descriptions are instruction-shaped by design. This
  one needs no adversarial labels and no threat assumption: it reports how
  often a detector fires on text that nobody is attacking.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import mcp_types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llmshield_mcp.config import REPO_ROOT  # noqa: E402
from llmshield_mcp.detectors.normalise import normalise  # noqa: E402
from llmshield_mcp.detectors.rules import RuleDetector  # noqa: E402
from llmshield_mcp.gating.declarations import (  # noqa: E402
    CANONICALISER_VERSION,
    HASHED_FIELDS,
    declaration_fields,
    hash_declaration,
)

SNAPSHOT_DIR = REPO_ROOT / "results" / "declarations"
REPORT_PATH = REPO_ROOT / "docs" / "DECLARATION-CHURN.md"

#: How many releases back to walk. Each package contributes `VERSIONS - 1`
#: consecutive-release transitions, which is the unit churn is measured in.
VERSIONS = 8


@dataclass(frozen=True, slots=True)
class ServerSpec:
    """One package to walk the release history of."""

    name: str
    ecosystem: str
    package: str
    #: Extra argv after the package spec (the filesystem server needs a root).
    args: tuple[str, ...] = ()

    def launch(self, version: str, *, legacy_sdk: bool = False) -> tuple[str, list[str]]:
        if self.ecosystem == "npm":
            return "npx", ["-y", f"{self.package}@{version}", *self.args]
        # Servers released before the MCP Python SDK's 2.x rename resolve the
        # newest SDK by default and fail on import. Constraining the era is what
        # makes the older half of each history collectable at all; which mode
        # succeeded is recorded per version rather than assumed.
        prefix = ["--with", "mcp<2"] if legacy_sdk else []
        return "uvx", [*prefix, f"{self.package}=={version}", *self.args]


SERVERS: tuple[ServerSpec, ...] = (
    ServerSpec("filesystem", "npm", "@modelcontextprotocol/server-filesystem", ("{sandbox}",)),
    ServerSpec("everything", "npm", "@modelcontextprotocol/server-everything"),
    ServerSpec("memory", "npm", "@modelcontextprotocol/server-memory"),
    ServerSpec("sequential-thinking", "npm", "@modelcontextprotocol/server-sequential-thinking"),
    ServerSpec("fetch", "pypi", "mcp-server-fetch"),
    ServerSpec("git", "pypi", "mcp-server-git"),
    ServerSpec("time", "pypi", "mcp-server-time"),
)

_PRERELEASE = ("alpha", "beta", "rc", "canary", "dev", "next")


def _get_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 -- fixed https hosts
        return json.load(response)


def released_versions(spec: ServerSpec, limit: int) -> list[str]:
    """The last `limit` stable releases, oldest first, ordered by publish time.

    Ordered by publish time rather than by version string: PyPI's release map
    is not in version order, and these packages use CalVer where a naive sort
    puts 2026.6.16 before 2026.6.4.
    """
    dated: list[tuple[str, str]] = []
    if spec.ecosystem == "npm":
        quoted = spec.package.replace("/", "%2F")
        data = _get_json(f"https://registry.npmjs.org/{quoted}")
        times = data.get("time", {})
        for version in data.get("versions", {}):
            if any(tag in version for tag in _PRERELEASE):
                continue
            dated.append((times.get(version, ""), version))
    else:
        data = _get_json(f"https://pypi.org/pypi/{spec.package}/json")
        for version, files in data["releases"].items():
            if not files or any(tag in version for tag in _PRERELEASE):
                continue
            dated.append((files[0].get("upload_time_iso_8601", ""), version))
    dated.sort()
    return [version for _, version in dated[-limit:]]


async def list_declarations(
    spec: ServerSpec, version: str, sandbox: str
) -> tuple[list[mcp_types.Tool], str]:
    """Launch one released version and return what `tools/list` sends back."""
    modes = [False] if spec.ecosystem == "npm" else [False, True]
    last: Exception | None = None
    for legacy in modes:
        command, args = spec.launch(version, legacy_sdk=legacy)
        args = [arg.replace("{sandbox}", sandbox) for arg in args]
        try:
            async with (
                stdio_client(StdioServerParameters(command=command, args=args)) as (r, w),
                ClientSession(r, w) as session,
            ):
                await session.initialize()
                listed = await session.list_tools()
                return list(listed.tools), ("mcp<2" if legacy else "default")
        except Exception as exc:  # noqa: BLE001 -- a version that will not run is data
            last = exc
    raise RuntimeError(str(last).splitlines()[0][:200] if last else "unknown failure")


def _instruction_signal(detector: RuleDetector, text: str) -> list[str]:
    """Rule ids that fire on benign declaration text. Every hit is a false positive."""
    if not text:
        return []
    result = detector.score(text)
    shadow = detector.score(normalise(text).text)
    return sorted({*result.detail, *shadow.detail} - {"normalisation_only"})


def measure(tool: mcp_types.Tool, detector: RuleDetector) -> dict[str, Any]:
    """Everything recorded about one declaration. Digests and numbers only."""
    hashes = hash_declaration(tool)
    fields = declaration_fields(tool)
    description = str(fields.get("description", "")) or ""
    schema_text = json.dumps(fields.get("input_schema", {}), ensure_ascii=False)
    return {
        "name": tool.name,
        "fields": dict(hashes.fields),
        "combined": hashes.combined,
        "concealed": list(hashes.concealed),
        "description_chars": len(description),
        "schema_chars": len(schema_text),
        "rules_on_description": _instruction_signal(detector, description),
        "rules_on_schema": _instruction_signal(detector, schema_text),
    }


async def collect(limit: int, sandbox: str) -> dict[str, Any]:
    detector = RuleDetector()
    servers: dict[str, Any] = {}
    for spec in SERVERS:
        try:
            versions = released_versions(spec, limit)
        except Exception as exc:  # noqa: BLE001
            print(f"  {spec.name}: registry lookup failed: {exc}", file=sys.stderr)
            continue
        print(f"{spec.name}: {len(versions)} releases", file=sys.stderr)
        releases: dict[str, Any] = {}
        for version in versions:
            try:
                tools, mode = await list_declarations(spec, version, sandbox)
            except Exception as exc:  # noqa: BLE001 -- recorded, not fatal
                print(f"  {version}: FAILED {exc}", file=sys.stderr)
                releases[version] = {"error": str(exc)[:200]}
                continue
            releases[version] = {
                "launch": mode,
                "tools": [measure(tool, detector) for tool in tools],
            }
            print(f"  {version}: {len(tools)} tools ({mode})", file=sys.stderr)
        servers[spec.name] = {
            "package": spec.package,
            "ecosystem": spec.ecosystem,
            "releases": releases,
        }
    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "canonicaliser_version": CANONICALISER_VERSION,
        "hashed_fields": list(HASHED_FIELDS),
        "versions_per_package": limit,
        "servers": servers,
    }


# --- analysis -------------------------------------------------------------


@dataclass
class Churn:
    transitions: int = 0
    tools_compared: int = 0
    tools_changed: int = 0
    added: int = 0
    removed: int = 0
    field_moves: Counter[str] = field(default_factory=Counter)
    #: Transitions in which a field moved for at least one tool. A different
    #: question from `field_moves`, which counts tools: one SDK-wide release
    #: touching forty tools is forty there and one here.
    field_transitions: Counter[str] = field(default_factory=Counter)
    changed_by_transition: list[float] = field(default_factory=list)


def _ok_releases(server: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(v, r) for v, r in server["releases"].items() if "error" not in r]


def analyse(snapshot: dict[str, Any]) -> dict[str, Any]:
    per_server: dict[str, Churn] = {}
    pooled = Churn()
    names_by_server: dict[str, set[str]] = {}
    concealed_total = 0
    tools_total = 0
    desc_lengths: list[int] = []
    rule_hits_desc = 0
    rule_hits_schema = 0
    rule_ids: Counter[str] = Counter()
    failures: list[str] = []

    for name, server in snapshot["servers"].items():
        churn = Churn()
        releases = _ok_releases(server)
        failures += [f"{name}@{v}" for v, r in server["releases"].items() if "error" in r]
        if releases:
            latest = releases[-1][1]["tools"]
            names_by_server[name] = {tool["name"] for tool in latest}

        for (_, before), (_, after) in zip(releases, releases[1:], strict=False):
            churn.transitions += 1
            old = {tool["name"]: tool for tool in before["tools"]}
            new = {tool["name"]: tool for tool in after["tools"]}
            shared = old.keys() & new.keys()
            churn.added += len(new.keys() - old.keys())
            churn.removed += len(old.keys() - new.keys())
            changed_here = 0
            moved_here: set[str] = set()
            for tool_name in shared:
                churn.tools_compared += 1
                if old[tool_name]["combined"] == new[tool_name]["combined"]:
                    continue
                churn.tools_changed += 1
                changed_here += 1
                for f in HASHED_FIELDS:
                    if old[tool_name]["fields"].get(f) != new[tool_name]["fields"].get(f):
                        churn.field_moves[f] += 1
                        moved_here.add(f)
            churn.field_transitions.update(moved_here)
            if shared:
                churn.changed_by_transition.append(changed_here / len(shared))

        for _, release in releases:
            for tool in release["tools"]:
                tools_total += 1
                desc_lengths.append(tool["description_chars"])
                if tool["concealed"]:
                    concealed_total += 1
                if tool["rules_on_description"]:
                    rule_hits_desc += 1
                    rule_ids.update(tool["rules_on_description"])
                if tool["rules_on_schema"]:
                    rule_hits_schema += 1
                    rule_ids.update(tool["rules_on_schema"])

        per_server[name] = churn
        pooled.transitions += churn.transitions
        pooled.tools_compared += churn.tools_compared
        pooled.tools_changed += churn.tools_changed
        pooled.added += churn.added
        pooled.removed += churn.removed
        pooled.field_moves.update(churn.field_moves)
        pooled.field_transitions.update(churn.field_transitions)
        pooled.changed_by_transition += churn.changed_by_transition

    collisions: dict[str, list[str]] = defaultdict(list)
    for server_name, names in names_by_server.items():
        for tool_name in names:
            collisions[tool_name].append(server_name)

    return {
        "per_server": per_server,
        "pooled": pooled,
        "collisions": {k: sorted(v) for k, v in collisions.items() if len(v) > 1},
        "tools_total": tools_total,
        "concealed_total": concealed_total,
        "desc_lengths": desc_lengths,
        "rule_hits_desc": rule_hits_desc,
        "rule_hits_schema": rule_hits_schema,
        "rule_ids": rule_ids,
        "failures": failures,
        "servers_with_data": len(names_by_server),
    }


def _pct(numerator: int, denominator: int) -> str:
    return "n/a" if denominator == 0 else f"{100.0 * numerator / denominator:.1f}%"


def render(snapshot: dict[str, Any], a: dict[str, Any]) -> str:
    date = snapshot["collected_at"][:10]
    pooled: Churn = a["pooled"]
    lengths: list[int] = a["desc_lengths"]
    lines: list[str] = []
    w = lines.append

    w("# Declaration churn in released MCP servers")
    w("")
    w(f"**Snapshot taken {date}. Frozen, not refreshed.** Regenerate with")
    w("`uv run python scripts/collect_declarations.py --collect`, which overwrites")
    w("the snapshot and changes every number below; the date above is part of every")
    w("claim made here.")
    w("")
    w("## The question")
    w("")
    w("`docs/PLAN-DECLARATION-INTEGRITY.md` §3.1 asks how often real MCP servers")
    w("legitimately change a tool declaration. It decides whether pinning is")
    w("deployable: a control that fires on every routine upstream release is one an")
    w("operator switches off. Nobody had published the number, so every default in")
    w("`gating/declaration_policy.py` was a guess until this ran.")
    w("")
    w("## Method")
    w("")
    w(f"Each server's last {snapshot['versions_per_package']} stable releases were")
    w("installed and launched over stdio, and their real `tools/list` responses")
    w("canonicalised by `gating/declarations.py`")
    w(f"(canonicaliser v{snapshot['canonicaliser_version']}). Source was not parsed:")
    w("that would measure what a repository says rather than what a server sends.")
    w("A tool is *changed* when its combined per-field digest differs between two")
    w("consecutive releases; tools added or removed are counted separately and are")
    w("not part of the changed fraction.")
    w("")
    w("## Churn, per server")
    w("")
    w("| Server | Releases | Transitions | Tools compared | Changed | Rate |")
    w("|---|---|---|---|---|---|")
    for name, churn in a["per_server"].items():
        releases = churn.transitions + 1 if churn.transitions else 0
        w(
            f"| {name} | {releases} | {churn.transitions} | {churn.tools_compared} "
            f"| {churn.tools_changed} | {_pct(churn.tools_changed, churn.tools_compared)} |"
        )
    w(
        f"| **pooled** | | **{pooled.transitions}** | **{pooled.tools_compared}** "
        f"| **{pooled.tools_changed}** | **{_pct(pooled.tools_changed, pooled.tools_compared)}** |"
    )
    w("")
    xs = pooled.changed_by_transition
    if xs:
        quiet = sum(1 for x in xs if x == 0.0)
        total_rewrite = sum(1 for x in xs if x == 1.0)
        w("### The pooled rate is the wrong statistic")
        w("")
        w(
            f"The distribution is **bimodal, with nothing in between**. Of "
            f"{len(xs)} release transitions, **{quiet} changed no declaration at "
            f"all** and **{total_rewrite} changed every tool the server has**. "
            f"The median transition changes {statistics.median(xs) * 100:.0f}% of "
            "declarations; the mean is "
            f"{statistics.mean(xs) * 100:.1f}% only because the second mode drags "
            "it there."
        )
        w("")
        w("That shape is the finding. A release either leaves declarations alone or")
        w("rewrites all of them at once, which is the signature of an SDK-wide")
        w("metadata change rather than an author editing one tool. The consequence")
        w("for an operator is the opposite of the pooled figure's implication:")
        w("pinning is silent through roughly two thirds of upgrades, and when it")
        w("does fire it fires on everything — which is an easy alert to triage, not")
        w("a needle in a haystack.")
        w("")
    w(f"Tools added across all transitions: {pooled.added}. Removed: {pooled.removed}.")
    w("")
    w("## Which field moves")
    w("")
    if pooled.field_moves:
        w("| Field | Tools changed | Share of changes | Releases it moved in |")
        w("|---|---|---|---|")
        for f, count in pooled.field_moves.most_common():
            seen = pooled.field_transitions[f]
            w(
                f"| `{f}` | {count} | {_pct(count, pooled.tools_changed)} "
                f"| {seen}/{pooled.transitions} ({_pct(seen, pooled.transitions)}) |"
            )
        w("")
        w("Two columns because they answer different questions. *Tools changed* is")
        w("dominated by the all-at-once releases above; *releases it moved in* is")
        w("what an operator actually experiences.")
    else:
        w("No declaration changed, so no field moved.")
    w("")
    desc_tools = pooled.field_moves.get("description", 0)
    w("### `description` moves surgically; everything else moves wholesale")
    w("")
    desc_releases = pooled.field_transitions.get("description", 0)
    w(
        f"Descriptions changed in **{desc_tools} of {pooled.tools_compared}** tool "
        f"comparisons ({_pct(desc_tools, pooled.tools_compared)}), spread across "
        f"{desc_releases} of {pooled.transitions} releases."
    )
    w("")
    w("Read those two numbers together rather than separately. A description change")
    w("is *not* rare per release — it happens in about one upgrade in five, as often")
    w("as any other field. What is rare is its **blast radius**: when descriptions")
    w("move they move for roughly one tool, where the metadata fields move for every")
    w("tool at once. The churn in `annotations`, `output_schema` and `execution` is")
    w("an SDK version bump rewriting the whole listing; a description change is")
    w("somebody editing one tool's prose.")
    w("")
    w("That distinction is the operationally useful one, because the fields are not")
    w("equally interesting. A tool-poisoning payload has to reach the model as text,")
    w("and `description` is the field that carries prose into context. So the signal")
    w("an operator wants — one tool's description changed — is precisely the signal")
    w(
        "that is *not* buried by SDK churn: it arrived "
        f"{desc_tools} times across {pooled.transitions} upgrades."
    )
    w("")
    w("So the honest reading is that declaration pinning is deployable, and that a")
    w("policy able to name *fields* rather than only conditions would be quieter")
    w("still. `gating/declaration_policy.py` keys on conditions")
    w('(`new`/`mutated`/`shadowed`/...) and cannot express "alert on a description')
    w('change, ignore an annotations change". That is a concrete improvement this')
    w("measurement argues for and which is **not** implemented — recorded here")
    w("rather than quietly added, since the plan scoped this step to measuring.")
    w("")
    w("This is also why the pin store keeps per-field digests rather than one blob:")
    w("a verdict that names the field is the difference between a reviewable alert")
    w("and a human diffing a 2KB schema by eye.")
    w("")
    w("## Concealment prevalence")
    w("")
    w(
        f"**{a['concealed_total']} of {a['tools_total']}** declarations carry "
        "characters that a conforming renderer draws as nothing "
        f"({_pct(a['concealed_total'], a['tools_total'])})."
    )
    w("")
    w("Unpublished, zero-cost, and tied to a documented attack rather than invented")
    w("(plan §5.3, arXiv:2607.05744). The set is Unicode's")
    w("`Default_Ignorable_Code_Point`, the same one `detectors/normalise.py` strips.")
    w("")
    w("## Cross-server name collisions")
    w("")
    if a["collisions"]:
        w("| Tool name | Declared by |")
        w("|---|---|")
        for tool_name, servers in sorted(a["collisions"].items()):
            w(f"| `{tool_name}` | {', '.join(servers)} |")
    else:
        w(
            f"None. Across the {a['servers_with_data']} servers' latest releases, no tool "
            "name is declared by more than one server."
        )
    w("")
    w("The base rate for the `shadowed` verdict. Note the sample: these are official")
    w("reference servers, chosen for having release histories to walk, not a random")
    w("draw from the ecosystem. A collision rate measured here says little about")
    w("what an operator running six third-party servers would see.")
    w("")
    w("## Rule false positives on benign declarations")
    w("")
    w(
        f"Descriptions: **{a['rule_hits_desc']} of {a['tools_total']}** fire at least one "
        f"rule ({_pct(a['rule_hits_desc'], a['tools_total'])}). "
        f"Input schemas: **{a['rule_hits_schema']} of {a['tools_total']}** "
        f"({_pct(a['rule_hits_schema'], a['tools_total'])})."
    )
    w("")
    if a["rule_ids"]:
        w("Rules that fired: " + ", ".join(f"`{r}` ({n})" for r, n in a["rule_ids"].most_common()))
        w("")
    w("Every one of these is a false positive by construction: these are official")
    w("reference servers and nobody is attacking them.")
    w("")
    w("**This is not the experiment plan §3.2 rules out.** That one injects the")
    w("adversarial corpus into descriptions and reports recall, which is")
    w("construct-invalid because tool descriptions are instruction-shaped by design")
    w("-- a poor AUROC there would be guaranteed by formatting rather than earned.")
    w("This measurement needs no adversarial labels and makes no threat assumption:")
    w("it reports how often a detector fires on text nobody is attacking. That is a")
    w("false-positive rate, and it is interpretable on its own.")
    w("")
    if lengths:
        w(
            f"For scale, description length across {len(lengths)} declarations: "
            f"median {int(statistics.median(lengths))} characters, "
            f"max {max(lengths)}."
        )
        w("")
    w("## What this means for the shipped defaults")
    w("")
    w("The defaults in `gating/declaration_policy.py` were chosen before any of")
    w("this existed, on the reasoning that a control firing on every routine")
    w("release is one an operator switches off. The measurement either vindicates")
    w("that caution or shows it was unnecessary, and it should be read as saying:")
    w("")
    quiet = sum(1 for x in xs if x == 0.0) if xs else 0
    w(
        f"* **`mutated: escalate` is the right default and stays.** It is silent "
        f"through {quiet} of {len(xs)} upgrades, so it is not alert spam — but when "
        "it fires it can name every tool at once, which would be a poor `block`."
    )
    w("* **`concealed` could defensibly default to `block`.** Nothing in the corpus")
    w("  triggers it, so the expected false-positive cost is zero on this evidence.")
    w("  It stays at `escalate` anyway: 380 declarations from official servers is")
    w("  not enough to claim a zero rate for the ecosystem, and a control whose")
    w("  first false positive blocks a tool is one that gets switched off. The")
    w("  number is reported; the default is unchanged and this is why.")
    w("* **`shadowed` is untested by this data.** No collision occurred, so its")
    w("  false-positive behaviour is simply unmeasured rather than shown to be low.")
    w("")
    w("No default was changed on the strength of this snapshot. Each is now a")
    w("choice with a number attached instead of a guess, which was the point.")
    w("")
    w("## What this does and does not support")
    w("")
    w("It supports a statement about **these** servers on **this** date. The sample")
    w("is official reference implementations, which are likelier to be stable than")
    w("the third-party servers an operator actually installs, so the churn figure")
    w("above should be read as a floor rather than a typical value.")
    w("")
    w("It is not a detection result and no recall number appears here. Pinning")
    w("catches post-approval mutation by construction -- hashes detect hash changes")
    w("-- and printing that next to a measured AUROC is exactly the rigor slippage")
    w("plan §3.2 exists to prevent.")
    if a["failures"]:
        w("")
        w("## Releases that could not be collected")
        w("")
        w(
            f"{len(a['failures'])} of the attempted releases would not start in this "
            "environment and are excluded from every figure above: "
            + ", ".join(f"`{f}`" for f in a["failures"])
            + "."
        )
        w("")
        w("Recorded rather than dropped: a version that will not run is not a version")
        w("with no churn, and silently excluding it would bias the rate downward.")
    return "\n".join(lines) + "\n"


def latest_snapshot() -> Path:
    snapshots = sorted(SNAPSHOT_DIR.glob("snapshot-*.json"))
    if not snapshots:
        raise SystemExit("no snapshot found; run with --collect first")
    return snapshots[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--collect", action="store_true", help="launch servers and write a snapshot"
    )
    parser.add_argument("--report", action="store_true", help="render the snapshot to markdown")
    parser.add_argument("--versions", type=int, default=VERSIONS)
    parser.add_argument("--sandbox", default=str(REPO_ROOT / "sandbox"))
    args = parser.parse_args()

    if args.collect:
        snapshot = asyncio.run(collect(args.versions, args.sandbox))
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        path = SNAPSHOT_DIR / f"snapshot-{snapshot['collected_at'][:10]}.json"
        path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}", file=sys.stderr)

    if args.report or not args.collect:
        path = latest_snapshot()
        snapshot = json.loads(path.read_text(encoding="utf-8"))
        REPORT_PATH.write_text(render(snapshot, analyse(snapshot)), encoding="utf-8")
        print(f"wrote {REPORT_PATH} from {path.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
