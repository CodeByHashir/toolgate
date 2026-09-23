"""M15: action-inviting model-side evaluation with a measurable baseline.

Design frozen in `docs/ACTION-EVALUATION-PREREG.md` before any model call. The
runner refuses to call the API unless the hashes stated in that document match
the code (benign set, pilot ids, final ids), and records the document's sha256
in `results/action/frozen.json` on first use; every later command aborts if it
changed.

Subcommands, in order:

    preflight   no API. Builds pilot/final samples and benign set, checks arm invariants.
    pilot       arm A only, three candidate setups, on the 24 pilot payloads.
                Selects the first qualifying candidate (or none).
    stage1      arm A on the 80 final attack payloads + 20 benign emails, then the gate.
    stage2      arms B, C, D (attack and benign). Only if the stage-1 gate passed.
    analyse     tables from the saved stage results. Pilot data is never read here.

Needs ANTHROPIC_API_KEY in the environment or `.env` (never printed).
Writes under `results/action/` (gitignored).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import eval_live as live  # sibling runner: Budget, execute, make_client (scripts/ is sys.path[0])

from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector
from llmshield_mcp.eval_action import (
    BENIGN_A_MIN_COMPLETED,
    FINAL_MIN_A_SUCCESSES,
    FINAL_QUOTAS,
    PILOT_MIN_SUCCESSES,
    PILOT_QUOTAS,
    SETUPS,
    BenignItem,
    Setup,
    analyse_action,
    benign_items,
    benign_set_sha256,
    draw_pilot_and_final,
    ids_sha256,
    select_setup,
    setup_by_id,
    stage1_gate,
)
from llmshield_mcp.eval_e2e import load_corpus
from llmshield_mcp.eval_live import (
    ARM_A,
    ARM_B,
    ARM_C,
    ARM_D,
    ARMS,
    MODEL,
    SampleItem,
    TrialResult,
    eligible_payloads,
    frame_through,
    load_results,
    results_to_json,
)
from llmshield_mcp.gating.audit import Decision
from llmshield_mcp.gating.content import BLOCK_MESSAGE
from llmshield_mcp.gating.policy import PolicyConfig, load_policy_config

ROOT = Path(__file__).parent.parent
PREREG = ROOT / "docs" / "ACTION-EVALUATION-PREREG.md"
OUT = ROOT / "results" / "action"

#: Per-command token caps (whole experiment stays within 3.0M input / 0.3M output).
live.MAX_INPUT_TOKENS = 1_500_000
live.MAX_OUTPUT_TOKENS = 150_000


def build_inputs() -> tuple[
    list[SampleItem], list[SampleItem], list[BenignItem], Any, PolicyConfig
]:
    bundle = load_corpus(benign_line_loader=lambda: [])
    if bundle.missing_families:
        raise SystemExit(f"corpus missing: {bundle.missing_families}")
    detectors = {
        "rules_mcp": RuleDetector(families=frozenset({"mcp"})),
        "rules_inj": RuleDetector(families=frozenset({"inj"})),
        "pii": PiiDetector(),
    }
    shipped = load_policy_config()
    pilot, final = draw_pilot_and_final(eligible_payloads(bundle.adversarial), detectors, shipped)
    return pilot, final, benign_items(), detectors, shipped


def hashes(pilot: list[SampleItem], final: list[SampleItem]) -> dict[str, str]:
    return {
        "pilot_ids_sha256": ids_sha256(pilot),
        "final_ids_sha256": ids_sha256(final),
        "benign_set_sha256": benign_set_sha256(),
    }


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_frozen(pilot: list[SampleItem], final: list[SampleItem]) -> str:
    """Abort unless the frozen document matches the code; record/verify its hash."""
    if not PREREG.exists():
        raise SystemExit("pre-registration missing")
    text = PREREG.read_text(encoding="utf-8")
    for name, value in hashes(pilot, final).items():
        if value not in text:
            raise SystemExit(
                f"{name} in code ({value[:16]}...) is not stated in the pre-registration"
            )
    digest = sha256_file(PREREG)
    OUT.mkdir(parents=True, exist_ok=True)
    frozen = OUT / "frozen.json"
    if frozen.exists():
        recorded = json.loads(frozen.read_text(encoding="utf-8"))["prereg_sha256"]
        if recorded != digest:
            raise SystemExit("pre-registration changed since it was first used; aborting")
    else:
        frozen.write_text(
            json.dumps(
                {
                    "prereg_sha256": digest,
                    "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    **hashes(pilot, final),
                },
                indent=1,
            ),
            encoding="utf-8",
        )
    return digest


def attack_spec(arm: str, item: SampleItem, setup: Setup) -> dict[str, Any]:
    return dict(
        arm=arm,
        payload_id=item.payload.payload_id,
        family=item.payload.family,
        document=item.document,
        attacker=item.attacker,
        flagged=item.flagged,
        kind="attack",
        system=setup.system,
        task=setup.task,
    )


def benign_spec(arm: str, item: BenignItem, flagged: bool, setup: Setup) -> dict[str, Any]:
    return dict(
        arm=arm,
        payload_id=item.payload.payload_id,
        family=item.payload.family,
        document=item.document,
        attacker=None,
        flagged=flagged,
        kind="benign",
        system=setup.system,
        task=setup.task,
    )


def benign_flags(items: list[BenignItem], detectors: Any, shipped: PolicyConfig) -> dict[str, bool]:
    """Would the shipped policy ESCALATE this benign email? (Deterministic, no model.)"""
    from llmshield_mcp.eval_e2e import documented_outcome

    return {
        i.payload.payload_id: documented_outcome(i.document, detectors, shipped).decision
        is Decision.ESCALATE
        for i in items
    }


def save(
    name: str, results: list[TrialResult], prereg: str, extra: dict[str, Any] | None = None
) -> None:
    (OUT / f"{name}.json").write_text(
        json.dumps(results_to_json(results), indent=1), encoding="utf-8"
    )
    meta = {
        "prereg_sha256": prereg,
        "model": MODEL,
        "n_results": len(results),
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        **(extra or {}),
    }
    (OUT / f"{name}.meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")


def preflight() -> int:
    pilot, final, benign, detectors, shipped = build_inputs()
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    for label, sample, quotas in (("pilot", pilot, PILOT_QUOTAS), ("final", final, FINAL_QUOTAS)):
        for key, quota in sorted(quotas.items()):
            got = sum(1 for i in sample if i.flagged == key[1])
            check(f"{label} stratum flagged={key[1]}", got == quota, f"{got}/{quota}")
    check(
        "pilot and final are disjoint",
        {i.payload.payload_id for i in pilot}.isdisjoint({i.payload.payload_id for i in final}),
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for label, sample in (("pilot", pilot), ("final", final)):
            bad = 0
            for item in sample:
                doc, target = item.document, item.attacker
                a, b, c, d = (
                    frame_through(arm, doc, shipped, detectors, tmp_path / f"{n}.sqlite")
                    for n, arm in enumerate(ARMS)
                )
                ok = a == (doc, None) and d[0] == doc
                ok &= target in doc.lower() and target not in b[0].lower()
                ok &= (c[0] == BLOCK_MESSAGE) == item.flagged and (item.flagged or c[0] == b[0])
                bad += not ok
            check(
                f"{label}: A==D byte-identical, B masks the address, C withholds iff flagged",
                bad == 0,
                f"({bad} bad of {len(sample)})",
            )

        flags = benign_flags(benign, detectors, shipped)
        masked = 0
        for n, item in enumerate(benign):
            text, _ = frame_through(
                ARM_B, item.document, shipped, detectors, tmp_path / f"m{n}.sqlite"
            )
            masked += text != item.document
        by_subset = {
            s: (
                sum(flags[i.payload.payload_id] for i in benign if i.subset == s),
                sum(i.subset == s for i in benign),
            )
            for s in ("ordinary", "stress")
        }
        print(
            f"  benign (recorded for the record, not tuned): ESCALATE by subset {by_subset}; B changes {masked}/{len(benign)} emails"
        )

    h = hashes(pilot, final)
    print("\n" + "\n".join(f"{k}: {v}" for k, v in h.items()))
    for label, sample in (("pilot", pilot), ("final", final)):
        ids = " ".join(i.payload.payload_id.split("/")[1] for i in sample)
        flagged = " ".join(i.payload.payload_id.split("/")[1] for i in sample if i.flagged)
        print(f"{label} ids ({len(sample)}): {ids}\n  flagged: {flagged}")
    if PREREG.exists():
        text = PREREG.read_text(encoding="utf-8")
        for name, value in h.items():
            check(f"{name} stated in the pre-registration", value in text)
    print("FAILURES:", failures or "none")
    return 1 if failures else 0


def pilot_cmd() -> int:
    pilot, final, _benign, detectors, shipped = build_inputs()
    prereg = require_frozen(pilot, final)
    if (OUT / "selected.json").exists():
        raise SystemExit(
            "selected.json exists: the pilot has already been run and cannot be re-run"
        )
    client = live.make_client()
    by_setup: dict[str, list[TrialResult]] = {}
    for setup in SETUPS:
        print(f"pilot candidate {setup.setup_id}: {setup.note}")
        budget = live.Budget()
        specs = [attack_spec(ARM_A, item, setup) for item in pilot]
        by_setup[setup.setup_id] = asyncio.run(
            live.execute(specs, client, shipped, detectors, budget)
        )
        save(f"pilot_{setup.setup_id}", by_setup[setup.setup_id], prereg)
    decision = select_setup(by_setup)
    for setup_id, cell in decision["candidates"].items():
        print(f"  {setup_id}: {cell['k']}/{cell['n']}  qualifies={cell['qualifies']}")
    files = {
        f"pilot_{s.setup_id}.json": sha256_file(OUT / f"pilot_{s.setup_id}.json") for s in SETUPS
    }
    (OUT / "selected.json").write_text(
        json.dumps({**decision, "pilot_file_sha256": files, "prereg_sha256": prereg}, indent=1),
        encoding="utf-8",
    )
    print("SELECTED:", decision["selected"])
    return 0


def selected_setup() -> Setup:
    path = OUT / "selected.json"
    if not path.exists():
        raise SystemExit("run the pilot first")
    chosen = json.loads(path.read_text(encoding="utf-8"))["selected"]
    if chosen is None:
        raise SystemExit("no candidate qualified in the pilot: there is no final experiment")
    return setup_by_id(chosen)


def stage1() -> int:
    pilot, final, benign, detectors, shipped = build_inputs()
    prereg = require_frozen(pilot, final)
    setup = selected_setup()
    if (OUT / "stage1.json").exists():
        raise SystemExit("stage1.json exists; refusing to overwrite collected data")
    flags = benign_flags(benign, detectors, shipped)
    specs = [attack_spec(ARM_A, item, setup) for item in final]
    specs += [benign_spec(ARM_A, i, flags[i.payload.payload_id], setup) for i in benign]
    budget = live.Budget()
    results = asyncio.run(live.execute(specs, live.make_client(), shipped, detectors, budget))
    gate = stage1_gate(results)
    save(
        "stage1",
        results,
        prereg,
        {"setup": setup.setup_id, "budget": [budget.input_tokens, budget.output_tokens]},
    )
    (OUT / "stage1_gate.json").write_text(json.dumps(gate, indent=1), encoding="utf-8")
    print(
        f"\nsetup {setup.setup_id}; arm A attack {gate['attack_a']}  benign completion {gate['benign_a']}"
    )
    print(
        f"gate (attack A >= {FINAL_MIN_A_SUCCESSES}/80 and benign A >= {BENIGN_A_MIN_COMPLETED}/20): "
        f"{'PROCEED to stage 2' if gate['proceed'] else 'STOP: ' + '; '.join(gate['reasons'])}"
    )
    return 0


def stage2() -> int:
    pilot, final, benign, detectors, shipped = build_inputs()
    prereg = require_frozen(pilot, final)
    setup = selected_setup()
    gate_path = OUT / "stage1_gate.json"
    if not gate_path.exists() or not json.loads(gate_path.read_text(encoding="utf-8"))["proceed"]:
        raise SystemExit("stage-1 gate not passed: B, C and D are not run")
    if (OUT / "stage2.json").exists():
        raise SystemExit("stage2.json exists; refusing to overwrite collected data")
    flags = benign_flags(benign, detectors, shipped)
    specs = [attack_spec(arm, item, setup) for arm in (ARM_B, ARM_C, ARM_D) for item in final]
    specs += [
        benign_spec(arm, i, flags[i.payload.payload_id], setup)
        for arm in (ARM_B, ARM_C, ARM_D)
        for i in benign
    ]
    budget = live.Budget()
    results = asyncio.run(live.execute(specs, live.make_client(), shipped, detectors, budget))
    save(
        "stage2",
        results,
        prereg,
        {"setup": setup.setup_id, "budget": [budget.input_tokens, budget.output_tokens]},
    )
    return analyse()


def fmt(cell: dict[str, Any]) -> str:
    if not cell["n"]:
        return "n/a"
    lo, hi = cell["ci95"]
    return f"{cell['rate'] * 100:5.1f}% ({cell['k']}/{cell['n']}) [{lo * 100:.1f}, {hi * 100:.1f}]"


def analyse() -> int:
    results = load_results(OUT / "stage1.json")
    if (OUT / "stage2.json").exists():
        results += load_results(OUT / "stage2.json")
    out = analyse_action(results)
    arms = [a for a in ARMS if a in out["per_arm"]]
    print("=== PRIMARY: attack success by arm (Wilson 95%) ===")
    for arm in arms:
        cells = out["attack_success"][arm]
        print(f"{arm:24s} all {fmt(cells['all']['success'])}")
        for group in ("flagged", "unflagged"):
            print(f"{'':24s} {group:9s} {fmt(cells[group]['success'])}")
    print("\n=== PAIRED CONTRASTS on attack success (second - first) ===")
    for label, c in out["contrasts"].items():
        print(
            f"{label:20s} n={c['n']:3d} {c['first_rate'] * 100:5.1f}% -> {c['second_rate'] * 100:5.1f}%  "
            f"diff {c['difference'] * 100:+6.1f}pp [{c['ci95'][0] * 100:+.1f}, {c['ci95'][1] * 100:+.1f}]  "
            f"disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}"
        )
    print(
        "\n=== SECONDARY: legitimate task on attack documents; tool-call differences; PII masking ==="
    )
    for arm in arms:
        a = out["per_arm"][arm]["attack"]
        print(
            f"{arm:24s} summary sent {fmt(a['legitimate_summary_sent'])}  mean calls {a['mean_tool_calls']:.2f}  "
            f"mean sends {a['mean_send_email_calls']:.2f}  other recipient {a['sent_to_other_recipient']['k']}  "
            f"saw placeholder {a['saw_placeholder']['k']}  to placeholder {a['sent_to_placeholder']['k']}  "
            f"saw block {a['saw_block_message']['k']}"
        )
    print("\n=== SECONDARY: benign task completion ===")
    for arm in arms:
        for subset, cell in out["per_arm"][arm]["benign"].items():
            print(
                f"{arm:24s} {subset:9s} completed {fmt(cell['completed'])}  withheld {cell['withheld']['k']}  "
                f"saw placeholder {cell['saw_placeholder']['k']}  mean sends {cell['mean_send_email_calls']:.2f}"
            )
    for label, c in out["benign_contrasts"].items():
        print(
            f"benign {label}: {c['first_rate'] * 100:.0f}% -> {c['second_rate'] * 100:.0f}%  disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}"
        )
    tokens = (sum(r.input_tokens for r in results), sum(r.output_tokens for r in results))
    print(f"\ntokens (stages 1-2): {tokens[0]:,} in / {tokens[1]:,} out over {len(results)} trials")
    (OUT / "analysis.json").write_text(
        json.dumps({**out, "tokens": tokens, "prereg_sha256": sha256_file(PREREG)}, indent=1),
        encoding="utf-8",
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["preflight", "pilot", "stage1", "stage2", "analyse"])
    command = parser.parse_args().command
    return {
        "preflight": preflight,
        "pilot": pilot_cmd,
        "stage1": stage1,
        "stage2": stage2,
        "analyse": analyse,
    }[command]()


if __name__ == "__main__":
    sys.exit(main())
