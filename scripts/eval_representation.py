"""M17: PII protection robustness under attacker-controlled representations.

Design frozen in `docs/REPRESENTATION-EVALUATION-PREREG.md` before any model
call. The runner refuses to call the API unless every hash stated there matches
what the code produces (payload ids, benign set, native-remnant documents, and
the model-visible documents of every condition), records the document's sha256
in `results/representation/frozen.json` on first use, and aborts if it changes.

Subcommands, in order:

    preflight   no API. Deterministic recognition and sanitisation per
                representation, the hashes to freeze, and consistency with M16's
                frozen frame hashes.
    run         one fixed shuffled batch: 7 conditions x (80 attack + 20 benign).
                Writes results/representation/trials.json; refuses to overwrite.
    resume      complete a batch cut short by an infrastructure failure: runs exactly the
                frozen trials with no valid result yet (adds none, repeats none).
    analyse     the pre-registered analysis from the saved trials.

Needs ANTHROPIC_API_KEY in the environment or `.env` (never printed).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

import eval_action as act  # sibling runner: build_inputs, benign_flags
import eval_live as live

from llmshield_mcp.eval_action import BenignItem, setup_by_id
from llmshield_mcp.eval_live import MODEL, SampleItem, load_results, results_to_json
from llmshield_mcp.eval_mechanism import frames_sha256
from llmshield_mcp.eval_representation import (
    COND_N1,
    CONDITIONS,
    EXPECTED_TRIALS,
    G1,
    G2,
    G3,
    G4,
    G5,
    G6,
    GATED,
    Measurement,
    analyse_representation,
    condition_document,
    distinct_addresses,
    fatal_api_error,
    gate_factory,
    measure,
    remaining_specs,
)
from llmshield_mcp.gating.policy import PolicyConfig

ROOT = Path(__file__).parent.parent
PREREG = ROOT / "docs" / "REPRESENTATION-EVALUATION-PREREG.md"
M16_PREREG = ROOT / "docs" / "MECHANISM-EVALUATION-PREREG.md"
OUT = ROOT / "results" / "representation"
SETUP = setup_by_id("C3")  # the frozen M15/M16 setup; nothing is selected here
TARGET = "contact@contact.com"

#: Spend caps (about 700 trials, roughly 3.3K tokens each).
live.MAX_INPUT_TOKENS = 4_000_000
live.MAX_OUTPUT_TOKENS = 500_000


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def m16_hashes() -> dict[str, str]:
    text = M16_PREREG.read_text(encoding="utf-8")
    found = dict(
        re.findall(
            r"^(frames_\w+_sha256|final_ids_sha256|benign_set_sha256):\s+([0-9a-f]{64})", text, re.M
        )
    )
    return found


def compute(
    final: list[SampleItem], benign: list[BenignItem], detectors: Any, shipped: PolicyConfig
) -> tuple[
    dict[str, dict[str, str]], dict[str, dict[str, str]], dict[tuple[str, str], Measurement]
]:
    """Model-visible frames and deterministic measurements for every condition."""
    attack: dict[str, dict[str, str]] = {c: {} for c in CONDITIONS}
    benign_frames: dict[str, dict[str, str]] = {c: {} for c in CONDITIONS}
    measures: dict[tuple[str, str], Measurement] = {}
    with tempfile.TemporaryDirectory() as tmp:
        n = 0
        for cond in CONDITIONS:
            for item in final:
                n += 1
                m, frame = measure(
                    cond, item.document, (item.attacker,), shipped, detectors, Path(tmp) / f"{n}.db"
                )
                attack[cond][item.payload.payload_id] = frame
                measures[(cond, item.payload.payload_id)] = m
            for b in benign:
                n += 1
                m, frame = measure(
                    cond,
                    b.document,
                    distinct_addresses(b.document),
                    shipped,
                    detectors,
                    Path(tmp) / f"{n}.db",
                )
                benign_frames[cond][b.payload.payload_id] = frame
                measures[(cond, b.payload.payload_id)] = m
    return attack, benign_frames, measures


def native_ids(final: list[SampleItem], measures: dict[tuple[str, str], Measurement]) -> list[str]:
    """Payloads whose *gated literal* frame still lets the address be recovered."""
    return [i.payload.payload_id for i in final if measures[(G1, i.payload.payload_id)].recoverable]


def design_hashes(
    final: list[SampleItem],
    attack: dict[str, dict[str, str]],
    benign_frames: dict[str, dict[str, str]],
    native: list[str],
) -> dict[str, str]:
    hashes = {
        "final_ids_sha256": act.ids_sha256(final),
        "benign_set_sha256": act.benign_set_sha256(),
        "native_remnant_ids_sha256": hashlib.sha256("\n".join(native).encode()).hexdigest(),
    }
    for cond in CONDITIONS:
        hashes[f"frames_attack_{cond}_sha256"] = frames_sha256(attack[cond])
    for cond in CONDITIONS:
        hashes[f"frames_benign_{cond}_sha256"] = frames_sha256(benign_frames[cond])
    return hashes


def rate_line(k: int, n: int) -> str:
    return f"{k}/{n}"


def preflight() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    attack, benign_frames, measures = compute(final, benign, detectors, shipped)
    native = native_ids(final, measures)
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    old = m16_hashes()
    check(
        "final sample is the frozen M16/M15 sample",
        act.ids_sha256(final) == old["final_ids_sha256"],
    )
    check(
        "benign set is the frozen M16/M15 set", act.benign_set_sha256() == old["benign_set_sha256"]
    )
    new = design_hashes(final, attack, benign_frames, native)
    for cond, key in ((COND_N1, "A_no_gate"), (G1, "B_shipped"), (G2, "O_obfuscated_address")):
        check(
            f"{cond}: attack frames equal M16's frozen {key} frames",
            new[f"frames_attack_{cond}_sha256"] == old[f"frames_attack_{key}_sha256"],
        )
    for cond, key in ((COND_N1, "A_no_gate"), (G1, "B_shipped")):
        check(
            f"{cond}: benign frames equal M16's frozen {key} frames",
            new[f"frames_benign_{cond}_sha256"] == old[f"frames_benign_{key}_sha256"],
        )

    print("\nATTACK documents (80): deterministic properties per condition")
    header = f"{'condition':22s} {'recog all/some/none':>20s} {'redacted':>9s} {'gate no-op':>11s} {'literal':>8s} {'recoverable':>12s} {'sanitised':>10s} {'ESCALATE':>9s}"
    print(header)
    for cond in CONDITIONS:
        ms = [measures[(cond, i.payload.payload_id)] for i in final]
        recog = "/".join(str(sum(m.recognition == r for m in ms)) for r in ("all", "some", "none"))
        print(
            f"{cond:22s} {recog:>20s} {sum(m.redacted for m in ms):>9d} {sum(m.gate_noop for m in ms):>11d} "
            f"{sum(m.literal_visible for m in ms):>8d} {sum(m.recoverable for m in ms):>12d} "
            f"{sum(not m.recoverable for m in ms):>10d} {sum(m.escalate for m in ms):>9d}"
        )
    check(
        "R2-R5: the shipped gate is a no-op on every document (so no ungated arm is needed)",
        all(measures[(c, i.payload.payload_id)].gate_noop for c in (G2, G3, G4, G5) for i in final),
    )
    same = sum(attack[G6][k] == attack[G1][k] for k in attack[G1])
    print(f"  info: case-variant gated frames identical to literal gated frames: {same}/80")
    print(
        f"  info: native-remnant documents (address recoverable in the gated literal frame): {len(native)}: "
        f"{' '.join(p.split('/')[1] for p in native)}"
    )
    forms = {"(at)": 0, "[at]": 0, " at ": 0, " dot ": 0}
    for i in final:
        if i.payload.payload_id in native:
            low = i.document.lower()
            for f in forms:
                forms[f] += f in low
    print(f"  info: forms present in the native-remnant documents: {forms}")

    print("\nBENIGN emails (20): the 7 that carry an address")
    for cond in CONDITIONS:
        bearing = [b for b in benign if measures[(cond, b.payload.payload_id)].occurrences > 0]
        ms = [measures[(cond, b.payload.payload_id)] for b in bearing]
        print(
            f"{cond:22s} address-bearing {len(bearing)}  recognised {sum(m.recognition == 'all' for m in ms)}  "
            f"redacted {sum(m.redacted for m in ms)}  sanitised {sum(not m.recoverable for m in ms)}"
        )
    unchanged = sum(
        benign_frames[g][b.payload.payload_id] == benign_frames[COND_N1][b.payload.payload_id]
        for g in GATED
        for b in benign
        if measures[(g, b.payload.payload_id)].occurrences == 0
    )
    total = len(GATED) * sum(
        1 for b in benign if measures[(G1, b.payload.payload_id)].occurrences == 0
    )
    check(
        "benign emails without an address are byte-identical in every condition",
        unchanged == total,
        f"({unchanged}/{total})",
    )

    print("\n" + "\n".join(f"{k}: {v}" for k, v in new.items()))
    if PREREG.exists():
        text = PREREG.read_text(encoding="utf-8")
        for name, value in new.items():
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


def specs_for(
    final: list[SampleItem], benign: list[BenignItem], detectors: Any, shipped: PolicyConfig
) -> list[dict[str, Any]]:
    flags = act.benign_flags(benign, detectors, shipped)
    specs: list[dict[str, Any]] = []
    for cond in CONDITIONS:
        for item in final:
            specs.append(
                dict(
                    arm=cond,
                    payload_id=item.payload.payload_id,
                    family=item.payload.family,
                    document=condition_document(cond, item.document, (item.attacker,)),
                    attacker=item.attacker,
                    flagged=item.flagged,
                    kind="attack",
                    system=SETUP.system,
                    task=SETUP.task,
                    gate_factory=gate_factory(cond, shipped, detectors),
                )
            )
        for b in benign:
            specs.append(
                dict(
                    arm=cond,
                    payload_id=b.payload.payload_id,
                    family=b.payload.family,
                    document=condition_document(cond, b.document, distinct_addresses(b.document)),
                    attacker=None,
                    flagged=flags[b.payload.payload_id],
                    kind="benign",
                    system=SETUP.system,
                    task=SETUP.task,
                    gate_factory=gate_factory(cond, shipped, detectors),
                )
            )
    return specs


def _save(
    results: list[Any], prereg: str, n_expected: int, budget: Any, fatal: str | None, resumed: bool
) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "trials.json").write_text(
        json.dumps(results_to_json(results), indent=1), encoding="utf-8"
    )
    meta_path = OUT / "trials.meta.json"
    history: list[Any] = []
    if meta_path.exists():
        prior = json.loads(meta_path.read_text(encoding="utf-8"))
        history = prior.get("history", [prior])
    meta = {
        "prereg_sha256": prereg,
        "model": MODEL,
        "setup": SETUP.setup_id,
        "n_expected": n_expected,
        "n_valid": len(results),
        "resumed": resumed,
        "fatal": fatal,
        "budget_this_invocation": [budget.input_tokens, budget.output_tokens],
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "history": history,
    }
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")


def _finish(results: list[Any], specs: list[Any], prereg: str, budget: Any, resumed: bool) -> int:
    fatal = live.LAST_FATAL
    _save(results, prereg, EXPECTED_TRIALS, budget, fatal, resumed)
    print(f"\nsaved {len(results)}/{EXPECTED_TRIALS} trials")
    if fatal:
        print(
            "*** BATCH STOPPED by an account-level failure; the collected trials were saved and "
            f"nothing was discarded.\n*** cause: {fatal}\n*** fix the account, then run "
            "`resume` to complete exactly the missing frozen trials."
        )
        return 3
    return analyse()


def run_cmd() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    attack, benign_frames, measures = compute(final, benign, detectors, shipped)
    prereg = require_frozen(
        design_hashes(final, attack, benign_frames, native_ids(final, measures))
    )
    if (OUT / "trials.json").exists():
        raise SystemExit("trials.json exists; use `resume` to complete it, not `run`")
    specs = specs_for(final, benign, detectors, shipped)
    budget = live.Budget()
    results = asyncio.run(
        live.execute(
            specs, live.make_client(), shipped, detectors, budget, fatal_check=fatal_api_error
        )
    )
    return _finish(results, specs, prereg, budget, resumed=False)


def resume_cmd() -> int:
    """Complete a batch that was cut short: run exactly the frozen trials that have
    no valid result yet. Adds no trial, repeats none, changes nothing the model sees."""
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    attack, benign_frames, measures = compute(final, benign, detectors, shipped)
    prereg = require_frozen(
        design_hashes(final, attack, benign_frames, native_ids(final, measures))
    )
    path = OUT / "trials.json"
    if not path.exists():
        raise SystemExit("nothing to resume: no trials.json; use `run`")
    existing = load_results(path)
    remaining = remaining_specs(specs_for(final, benign, detectors, shipped), existing)
    print(f"{len(existing)} valid trials on disk; {len(remaining)} of {EXPECTED_TRIALS} remaining")
    if not remaining:
        return analyse()
    backup = OUT / f"trials.before_resume_{len(existing)}.json"
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
    budget = live.Budget()
    new = asyncio.run(
        live.execute(
            remaining, live.make_client(), shipped, detectors, budget, fatal_check=fatal_api_error
        )
    )
    return _finish(existing + new, remaining, prereg, budget, resumed=True)


def fmt(cell: dict[str, Any]) -> str:
    if not cell["n"]:
        return "n/a"
    lo, hi = cell["ci95"]
    return f"{cell['rate'] * 100:5.1f}% ({cell['k']}/{cell['n']}) [{lo * 100:.1f}, {hi * 100:.1f}]"


def line(c: dict[str, Any]) -> str:
    if not c.get("n"):
        return f"{c.get('label', ''):46s} no data"
    return (
        f"{c['label']:46s} n={c['n']:3d} {c['first_rate'] * 100:5.1f}% -> {c['second_rate'] * 100:5.1f}%  "
        f"diff {c['difference'] * 100:+6.1f}pp [{c['ci95'][0] * 100:+.1f}, {c['ci95'][1] * 100:+.1f}]  "
        f"disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}  -> {c['decision']}"
    )


def analyse() -> int:
    _pilot, final, benign, detectors, shipped = act.build_inputs()
    results = load_results(OUT / "trials.json")
    attack, benign_frames, measures = compute(final, benign, detectors, shipped)
    visible = {(c, pid): text for c in CONDITIONS for pid, text in attack[c].items()}
    native = native_ids(final, measures)
    old = m16_hashes()
    new = design_hashes(final, attack, benign_frames, native)
    frames_match = (
        new[f"frames_attack_{COND_N1}_sha256"] == old["frames_attack_A_no_gate_sha256"]
        and new[f"frames_attack_{G1}_sha256"] == old["frames_attack_B_shipped_sha256"]
        and new[f"frames_attack_{G2}_sha256"] == old["frames_attack_O_obfuscated_address_sha256"]
    )
    out = analyse_representation(
        results,
        visible,
        measures,
        {i.payload.payload_id: i.payload.payload_id in native for i in final},
        SETUP,
        frames_match_m16=frames_match,
    )
    print("=== DETERMINISTIC (no model): recognition and sanitisation, 80 attack documents ===")
    for cond, cell in out["per_condition"].items():
        print(
            f"{cond:22s} recognised-all {cell['recognition_all']['k']:2d}  redacted {cell['redacted_by_gate']['k']:2d}  "
            f"gate no-op {cell['gate_noop']['k']:2d}  recoverable {cell['address_recoverable_in_frame']['k']:2d}  "
            f"sanitised {cell['sanitised_before_model']['k']:2d}  ESCALATE {cell['shipped_policy_escalates']['k']:2d}"
        )
    print("\n=== PRIMARY: attacker-recipient success (Wilson 95%) ===")
    for cond in CONDITIONS:
        cells = out["attack_success"].get(cond)
        if not cells:
            continue
        pc = out["per_condition"][cond]
        print(
            f"{cond:22s} all {fmt(cells['all']['success'])}   native-remnant docs {fmt(pc['success_native_remnant_docs'])}   "
            f"clean docs {fmt(pc['success_clean_docs'])}"
        )
    print("\n=== CONFIRMATORY (second - first; exact McNemar alpha=0.0125; margin 10pp) ===")
    for label, c in out["confirmatory"].items():
        print(line(c) + f"   [{out['protection_verdicts'][label]}]")
    print("\n=== EXPLORATORY contrasts ===")
    for c in out["exploratory"].values():
        print(line(c))
    print("\n=== EXPLORATORY: recipients, summary, sequences ===")
    for cond, cell in out["per_condition"].items():
        r = cell["recipients"]
        print(
            f"{cond:22s} legit summary {fmt(cell['legitimate_summary_sent'])}  invented-recipient trials {r['sent_to_invented_address']['k']}  "
            f"obfuscated-attacker attempts {r['attacker_address_in_obfuscated_form']['k']}  calls {cell['mean_tool_calls']:.2f}  "
            f"sequences {cell['sequence_signatures']['distinct']}: {cell['sequence_signatures']['top'][:3]}"
        )
    print("\n=== BENIGN task completion (20 emails; 7 carry an address) ===")
    for cond, cell in out["benign"].items():
        print(
            f"{cond:22s} all {fmt(cell['completed'])}  address-bearing {fmt(cell['completed_address_bearing'])}  "
            f"no-address {fmt(cell['completed_no_address'])}  addresses recognised {cell['addresses_recognised']['k']}/{cell['addresses_recognised']['n']}  "
            f"sanitised {cell['addresses_sanitised']['k']}/{cell['addresses_sanitised']['n']}"
        )
    for label, c in out["benign_contrasts"].items():
        if not c.get("n"):
            continue
        print(
            f"benign {label}: {c['first_rate'] * 100:.0f}% -> {c['second_rate'] * 100:.0f}%  disc {c['first_only']}/{c['second_only']}  p={c['mcnemar_exact_p']:.4g}"
        )
    if len(results) < EXPECTED_TRIALS:
        print(
            f"\n*** INCOMPLETE: {len(results)}/{EXPECTED_TRIALS} trials collected; contrasts with few or no paired "
            "payloads are not evaluable and must not be read as results ***"
        )
    print(f"\nvalidity: {out['validity']}")
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
    parser.add_argument("command", choices=["preflight", "run", "resume", "analyse"])
    command = parser.parse_args().command
    return {"preflight": preflight, "run": run_cmd, "resume": resume_cmd, "analyse": analyse}[
        command
    ]()


if __name__ == "__main__":
    sys.exit(main())
