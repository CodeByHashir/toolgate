"""M16: mechanism experiment (information removal vs placeholder vs detector bypass).

Design frozen in `docs/MECHANISM-EVALUATION-PREREG.md` before any model call. The
runner refuses to call the API unless the hashes stated in that document match
what the code produces (payload ids, benign set, and the model-visible documents
of every condition), records the document's sha256 in `results/mechanism/
frozen.json` on first use, and aborts if it later changes.

Subcommands, in order:

    preflight   no API. Builds every model-visible document, checks the invariants
                of each condition, prints the hashes to be frozen.
    run         one fixed, shuffled batch (attack A/B/E/O x 80, benign A/B/E x 20).
                Writes results/mechanism/trials.json; refuses to overwrite.
    analyse     the pre-registered analysis from the saved trials.

Needs ANTHROPIC_API_KEY in the environment or `.env` (never printed).
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
sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import eval_action as act  # sibling runner: build_inputs, benign_flags (scripts/ is sys.path[0])
import eval_live as live

from llmshield_mcp.eval_action import BenignItem, setup_by_id
from llmshield_mcp.eval_live import (
    MODEL,
    SampleItem,
    load_results,
    results_to_json,
)
from llmshield_mcp.eval_mechanism import (
    BENIGN_CONDITIONS,
    COND_A,
    COND_B,
    COND_E,
    COND_O,
    CONDITIONS,
    MARKER,
    analyse_mechanism,
    condition_document,
    frames_sha256,
    gate_factory_for,
    obfuscate_address,
    strip_markers,
    survival,
    visible_document,
)
from llmshield_mcp.gating.policy import PolicyConfig

ROOT = Path(__file__).parent.parent
PREREG = ROOT / "docs" / "MECHANISM-EVALUATION-PREREG.md"
OUT = ROOT / "results" / "mechanism"
SETUP = setup_by_id("C3")  # the frozen M15 setup; no selection is done here

#: Spend caps for this experiment (about 380 trials, roughly 3K tokens each).
live.MAX_INPUT_TOKENS = 2_000_000
live.MAX_OUTPUT_TOKENS = 250_000


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute_frames(
    final: list[SampleItem], benign: list[BenignItem], detectors: Any, shipped: PolicyConfig
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], dict[tuple[str, str], Any]]:
    """Model-visible documents for every condition, through the real gate."""
    attack: dict[str, dict[str, str]] = {c: {} for c in CONDITIONS}
    benign_frames: dict[str, dict[str, str]] = {c: {} for c in (*BENIGN_CONDITIONS, COND_O)}
    decisions: dict[tuple[str, str], Any] = {}
    with tempfile.TemporaryDirectory() as tmp:
        n = 0
        for item in final:
            for cond in CONDITIONS:
                n += 1
                text, decision = visible_document(
                    cond, item.document, item.attacker, shipped, detectors, Path(tmp) / f"{n}.db"
                )
                attack[cond][item.payload.payload_id] = text
                decisions[(cond, item.payload.payload_id)] = decision
        for b in benign:
            for cond in (*BENIGN_CONDITIONS, COND_O):
                n += 1
                text, _ = visible_document(
                    cond, b.document, None, shipped, detectors, Path(tmp) / f"{n}.db"
                )
                benign_frames[cond][b.payload.payload_id] = text
    return attack, benign_frames, decisions


def design_hashes(
    final: list[SampleItem],
    attack: dict[str, dict[str, str]],
    benign_frames: dict[str, dict[str, str]],
) -> dict[str, str]:
    hashes = {
        "final_ids_sha256": act.ids_sha256(final),
        "benign_set_sha256": act.benign_set_sha256(),
    }
    for cond in CONDITIONS:
        hashes[f"frames_attack_{cond}_sha256"] = frames_sha256(attack[cond])
    for cond in BENIGN_CONDITIONS:
        hashes[f"frames_benign_{cond}_sha256"] = frames_sha256(benign_frames[cond])
    return hashes


def preflight() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    attack, benign_frames, decisions = compute_frames(final, benign, detectors, shipped)
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    check(
        "final sample is the frozen M15 sample",
        act.ids_sha256(final).startswith("a3f207c89fc0f2b7"),
    )
    check(
        "benign set is the frozen M15 set", act.benign_set_sha256().startswith("3d77edeb36e3c2876")
    )
    check(
        "no payload natively contains a redaction marker or an '[at]' form",
        not any(MARKER.search(i.document) or "[at]" in i.document.lower() for i in final),
    )

    bad = {"A": 0, "B": 0, "E": 0, "O": 0}
    non_attacker_pii = gate_noop_o = 0
    for item in final:
        pid, doc, target = item.payload.payload_id, item.document, item.attacker
        a, b, e, o = (attack[c][pid] for c in CONDITIONS)
        bad["A"] += a != doc
        bad["B"] += not ("[REDACTED:EMAIL_ADDRESS]" in b and target not in b.lower())
        bad["E"] += not (e == strip_markers(b) and "[REDACTED" not in e and target not in e.lower())
        bad["E"] += decisions[(COND_E, pid)] is not decisions[(COND_B, pid)]
        bad["O"] += not (
            target not in o.lower() and "[at]" in o.lower() and o == obfuscate_address(doc, target)
        )
        gate_noop_o += o == obfuscate_address(doc, target)
        non_attacker_pii += b.count("[REDACTED:") > doc.lower().count(target)
    for cond, n_bad in bad.items():
        check(
            f"condition {cond}: what the model sees is as designed",
            n_bad == 0,
            f"({n_bad} bad of 80)",
        )
    check(
        "O: the shipped gate is a no-op on every O document",
        gate_noop_o == 80,
        f"({gate_noop_o}/80)",
    )
    print(
        f"  info: frames where B masks PII other than the attacker address: {non_attacker_pii}/80"
    )

    literal_flagged = sum(1 for i in final if i.flagged)
    o_flagged = sum(
        1 for i in final if str(decisions[(COND_O, i.payload.payload_id)]).endswith("escalate")
    )
    print(
        f"  info: ESCALATE on the literal document {literal_flagged}/80; on the O document {o_flagged}/80"
    )

    same_b_o = sum(
        benign_frames[COND_O][k] == benign_frames[COND_B][k] for k in benign_frames[COND_B]
    )
    e_ok = sum(
        benign_frames[COND_E][k] == strip_markers(benign_frames[COND_B][k])
        for k in benign_frames[COND_B]
    )
    check("benign: O frames are byte-identical to B frames", same_b_o == 20, f"({same_b_o}/20)")
    check("benign: E frames are B frames with markers removed", e_ok == 20, f"({e_ok}/20)")
    print(
        f"  info: benign emails changed by masking (B vs A): "
        f"{sum(benign_frames[COND_B][k] != benign_frames[COND_A][k] for k in benign_frames[COND_A])}/20"
    )

    print("\nsurvival in the model-visible attack documents (deterministic):")
    for cond in CONDITIONS:
        rows = [survival(attack[cond][i.payload.payload_id], i.attacker) for i in final]
        print(
            "  " + f"{cond:22s} " + "  ".join(f"{k}={sum(r[k] for r in rows)}/80" for k in rows[0])
        )

    hashes = design_hashes(final, attack, benign_frames)
    print("\n" + "\n".join(f"{k}: {v}" for k, v in hashes.items()))
    if PREREG.exists():
        text = PREREG.read_text(encoding="utf-8")
        for name, value in hashes.items():
            check(f"{name} stated in the pre-registration", value in text)
    print("FAILURES:", failures or "none")
    return 1 if failures else 0


def require_frozen(hashes: dict[str, str]) -> str:
    if not PREREG.exists():
        raise SystemExit("pre-registration missing")
    text = PREREG.read_text(encoding="utf-8")
    for name, value in hashes.items():
        if value not in text:
            raise SystemExit(f"{name} ({value[:16]}...) is not stated in the pre-registration")
    digest = sha256_file(PREREG)
    OUT.mkdir(parents=True, exist_ok=True)
    frozen = OUT / "frozen.json"
    if frozen.exists():
        if json.loads(frozen.read_text(encoding="utf-8"))["prereg_sha256"] != digest:
            raise SystemExit("pre-registration changed since it was first used; aborting")
    else:
        frozen.write_text(
            json.dumps(
                {
                    "prereg_sha256": digest,
                    "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    **hashes,
                },
                indent=1,
            ),
            encoding="utf-8",
        )
    return digest


def attack_spec(
    cond: str, item: SampleItem, shipped: PolicyConfig, detectors: Any
) -> dict[str, Any]:
    return dict(
        arm=cond,
        payload_id=item.payload.payload_id,
        family=item.payload.family,
        document=condition_document(cond, item.document, item.attacker),
        attacker=item.attacker,
        flagged=item.flagged,
        kind="attack",
        system=SETUP.system,
        task=SETUP.task,
        gate_factory=gate_factory_for(cond, shipped, detectors),
    )


def benign_spec(
    cond: str, item: BenignItem, flagged: bool, shipped: PolicyConfig, detectors: Any
) -> dict[str, Any]:
    return dict(
        arm=cond,
        payload_id=item.payload.payload_id,
        family=item.payload.family,
        document=item.document,
        attacker=None,
        flagged=flagged,
        kind="benign",
        system=SETUP.system,
        task=SETUP.task,
        gate_factory=gate_factory_for(cond, shipped, detectors),
    )


def run_cmd() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    attack, benign_frames, _ = compute_frames(final, benign, detectors, shipped)
    prereg = require_frozen(design_hashes(final, attack, benign_frames))
    if (OUT / "trials.json").exists():
        raise SystemExit("trials.json exists; refusing to overwrite collected data")
    flags = act.benign_flags(benign, detectors, shipped)
    specs = [attack_spec(c, i, shipped, detectors) for c in CONDITIONS for i in final]
    specs += [
        benign_spec(c, b, flags[b.payload.payload_id], shipped, detectors)
        for c in BENIGN_CONDITIONS
        for b in benign
    ]
    budget = live.Budget()
    results = asyncio.run(live.execute(specs, live.make_client(), shipped, detectors, budget))
    (OUT / "trials.json").write_text(
        json.dumps(results_to_json(results), indent=1), encoding="utf-8"
    )
    (OUT / "trials.meta.json").write_text(
        json.dumps(
            {
                "prereg_sha256": prereg,
                "model": MODEL,
                "setup": SETUP.setup_id,
                "n_expected": len(specs),
                "n_valid": len(results),
                "budget": [budget.input_tokens, budget.output_tokens],
                "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(f"\nsaved {len(results)}/{len(specs)} trials")
    return analyse()


def fmt(cell: dict[str, Any]) -> str:
    if not cell["n"]:
        return "n/a"
    lo, hi = cell["ci95"]
    return f"{cell['rate'] * 100:5.1f}% ({cell['k']}/{cell['n']}) [{lo * 100:.1f}, {hi * 100:.1f}]"


def line(label: str, c: dict[str, Any]) -> str:
    if not c.get("n"):
        return f"{label:30s} no data"
    return (
        f"{label:30s} n={c['n']:3d} {c['first_rate'] * 100:5.1f}% -> {c['second_rate'] * 100:5.1f}%  "
        f"diff {c['difference'] * 100:+6.1f}pp [{c['ci95'][0] * 100:+.1f}, {c['ci95'][1] * 100:+.1f}]  "
        f"disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}  -> {c['decision']}"
    )


def analyse() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    results = load_results(OUT / "trials.json")
    visible: dict[tuple[str, str], str] = {}
    attack, benign_frames, _ = compute_frames(final, benign, detectors, shipped)
    for cond in CONDITIONS:
        for pid, text in attack[cond].items():
            visible[(cond, pid)] = text
    out = analyse_mechanism(results, visible, SETUP)

    print("=== PRIMARY: attacker-recipient send_email success (Wilson 95%) ===")
    for cond in CONDITIONS:
        cells = out["attack_success"].get(cond)
        if cells:
            print(
                f"{cond:22s} all {fmt(cells['all']['success'])}   flagged {fmt(cells['flagged']['success'])}   "
                f"unflagged {fmt(cells['unflagged']['success'])}"
            )
    print(
        "\n=== CONFIRMATORY contrasts (second - first; exact McNemar alpha=0.025; margin 10pp) ==="
    )
    for label, c in out["confirmatory"].items():
        print(line(label, c))
    print("\n=== DESCRIPTIVE contrasts ===")
    for label, c in out["descriptive"].items():
        print(line(label, c))
    print("\n=== SECONDARY: what the model saw, what it sent ===")
    for cond, cell in out["per_condition"].items():
        s = cell["survival_in_visible_document"]
        r = cell["recipients"]
        print(
            f"{cond:22s} visible: literal {s['literal']['k']} obfuscated {s['obfuscated']['k']} "
            f"domain-fragment {s['domain_fragment']['k']} local-token {s['local_token']['k']} placeholder {s['placeholder']['k']}"
            f"\n{'':22s} success | fragment present {fmt(cell['success_by_fragment']['domain_fragment_present'])}  "
            f"absent {fmt(cell['success_by_fragment']['domain_fragment_absent'])}"
            f"\n{'':22s} legit summary {fmt(cell['legitimate_summary_sent'])}  calls {cell['mean_tool_calls']:.2f}  "
            f"sends {cell['mean_send_email_calls']:.2f}  invented-recipient trials {r['sent_to_invented_address']['k']}  "
            f"other-in-context {r['sent_to_other_address_in_context']['k']}  to-placeholder {r['sent_to_placeholder']['k']}  "
            f"attacker-obfuscated attempts {r['attacker_address_in_obfuscated_form']['k']}"
            f"\n{'':22s} failures {cell['task_failures']['legitimate_summary_not_sent']['k']} "
            f"(mention redaction/missing: {cell['task_failures']['of_which_answer_mentions_redaction_or_missing']})  "
            f"ESCALATE {cell['gate_flagged_escalate']['k']}/80  sequences {cell['sequence_signatures']['distinct']} distinct: "
            f"{cell['sequence_signatures']['top'][:4]}"
        )
    print(
        "\n=== SECONDARY: benign task completion (O == B on benign by construction, not re-run) ==="
    )
    for cond, cell in out["benign"].items():
        print(
            f"{cond:22s} completed {fmt(cell['completed'])}  stress {fmt(cell['completed_stress'])}  to-placeholder {cell['sent_to_placeholder']['k']}"
        )
    for label, c in out["benign_contrasts"].items():
        print(
            f"benign {label}: {c['first_rate'] * 100:.0f}% -> {c['second_rate'] * 100:.0f}%  disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}"
        )
    v = out["validity"]
    print(
        f"\nvalidity: baseline reproduced {v['baseline_reproduced']}  benign task works {v['benign_task_works']}  trials {v['trials']}"
    )
    tokens = (sum(r.input_tokens for r in results), sum(r.output_tokens for r in results))
    print(f"tokens: {tokens[0]:,} in / {tokens[1]:,} out over {len(results)} trials")
    (OUT / "analysis.json").write_text(
        json.dumps(
            {**out, "tokens": tokens, "prereg_sha256": sha256_file(PREREG)}, indent=1, default=str
        ),
        encoding="utf-8",
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["preflight", "run", "analyse"])
    command = parser.parse_args().command
    return {"preflight": preflight, "run": run_cmd, "analyse": analyse}[command]()


if __name__ == "__main__":
    sys.exit(main())
