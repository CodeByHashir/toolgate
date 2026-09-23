"""M13: end-to-end evaluation of the live gate against real adversarial payloads.

Delivers BIPIA, InjecAgent and LLMail-Inject payloads through the real `Gate`
(real detectors, real `PolicyEngine`, real SQLite audit log) inside synthetic
MCP tool results at 0 / 50 / 75 / 90% dilution, records detector scores, the
fused decision and the forwarded frame, and checks every call against the
documented policy contract. No API key, no model, no network.

Run:
    uv run python scripts/eval_e2e.py

Needs the cached corpus under `corpus/external/` (gitignored). Fetch it once
(this downloads BIPIA, InjecAgent and sampled LLMail-Inject pages):

    uv run python -c "from llmshield_mcp.corpus.sources import fetch, \
fetch_llmail_inject; fetch(); fetch_llmail_inject()"

(`mcp-shield corpus-ingest` also fetches, but then decontaminates against the
unpublished V0/V3 training corpus, which this evaluation does not need.)
Without the LLMail-Inject cache the run aborts, because the MCP-* recall on
that family is part of what this measures; pass `--allow-missing-llmail` to
run without it.

Writes `results/e2e/e2e_results.json` (gitignored) and prints the tables that
`docs/E2E-EVALUATION.md` reports. Exit status: 0 clean, 1 contract violation or
audit-log mismatch, 2 corpus missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llmshield_mcp.detectors.pii import PiiDetector
from llmshield_mcp.detectors.rules import RuleDetector
from llmshield_mcp.dilution import load_neutral_filler
from llmshield_mcp.eval_e2e import (
    ARM_BASE64,
    ARM_BENIGN,
    ARM_PLAIN,
    DILUTION_RATIOS,
    POLICY_COUNTERFACTUAL,
    POLICY_SHIPPED,
    counterfactual_policy,
    load_corpus,
    raw_isolated_recall,
    results_digest,
    rule_hits,
    run_evaluation,
    summarise,
)
from llmshield_mcp.gating.audit import Decision
from llmshield_mcp.gating.policy import load_policy_config

DEFAULT_OUT_DIR = Path(__file__).parent.parent / "results" / "e2e"
ADVERSARIAL = ("bipia", "injecagent", "llmail_inject")


def fmt(rate: dict[str, Any]) -> str:
    if not rate["n"]:
        return "n/a"
    low, high = rate["ci95"]
    return (
        f"{rate['rate'] * 100:5.1f}% ({rate['k']}/{rate['n']}) [{low * 100:.1f}, {high * 100:.1f}]"
    )


def header(title: str) -> None:
    print(f"\n{'=' * 78}\n  {title}\n{'=' * 78}")


def print_by_ratio(summary: dict[str, Any]) -> None:
    header("Shipped policy, plain payloads: decision by dilution ratio (all families)")
    print(
        f"{'ratio':>6} {'n':>5} {'allow':>6} {'redact':>7} {'escalate':>9} {'block':>6}   "
        "injection flag [95% CI]"
    )
    for ratio, cells in summary[POLICY_SHIPPED][ARM_PLAIN].items():
        cell = cells["all"]
        d = cell["decisions"]
        print(
            f"{float(ratio):>6.2f} {cell['n']:>5} {d['allow']:>6} {d['redact']:>7} "
            f"{d['escalate']:>9} {d['block']:>6}   {fmt(cell['injection_flag'])}"
        )


def print_by_family(summary: dict[str, Any], raw: dict[str, Any]) -> None:
    header("Shipped policy, isolated payloads (ratio 0.00): per source family")
    cells = summary[POLICY_SHIPPED][ARM_PLAIN]["0.00"]
    print(
        "MCP-* recall = share of payloads on which rules_mcp fired (the only injection detector)\n"
    )
    for name in (*ADVERSARIAL, "all"):
        if name not in cells:
            print(f"{name:14s} NOT MEASURED (family absent from corpus)")
            continue
        cell = cells[name]
        line = f"{name:14s} MCP-* recall {fmt(cell['mcp_recall'])}"
        if name in raw:
            line += f"   raw-payload control {fmt(raw[name])}"
        print(line)
        print(
            f"{'':14s} frames with PII masked {fmt(cell['frames_redacted'])}   "
            f"payload verbatim {fmt(cell['payload_verbatim'])}"
        )


def print_survival(summary_calls: list[Any]) -> None:
    header("Shipped policy: does the payload text reach the agent? (plain arm, all ratios)")
    print(f"{'decision':>9} {'n':>6} {'verbatim':>10} {'modulo PII mask':>17}")
    for decision in (Decision.ALLOW, Decision.REDACT, Decision.ESCALATE, Decision.BLOCK):
        rows = [
            c
            for c in summary_calls
            if c.policy == POLICY_SHIPPED and c.arm == ARM_PLAIN and c.decision is decision
        ]
        if not rows:
            print(f"{decision.value:>9} {0:>6} {'-':>10} {'-':>17}")
            continue
        verbatim = sum(1 for c in rows if c.payload_verbatim)
        modulo = sum(1 for c in rows if c.payload_modulo_pii)
        print(f"{decision.value:>9} {len(rows):>6} {verbatim:>10} {modulo:>17}")


def print_block_arm(summary: dict[str, Any], calls: list[Any]) -> None:
    header("Block-path arm: rules_mcp-detected payloads, base64-encoded, isolated")
    print(
        "BLOCK needs normalisation_only AND calibrated:true. "
        "'counterfactual' is NOT the shipped policy.\n"
    )
    for policy in (POLICY_SHIPPED, POLICY_COUNTERFACTUAL):
        cell = summary[policy][ARM_BASE64]["0.00"]["all"]
        rows = [c for c in calls if c.policy == policy and c.arm == ARM_BASE64]
        d = cell["decisions"]
        survive = sum(1 for c in rows if c.payload_verbatim)
        replaced = sum(1 for c in rows if c.forwarded_is_error and not c.payload_verbatim)
        print(
            f"{policy:26s} n={cell['n']:>3} escalate={d['escalate']:>3} block={d['block']:>3} "
            f"encoded payload reaches agent={survive:>3}/{len(rows)}  block-replaced={replaced:>3}"
        )
    plain = summary[POLICY_COUNTERFACTUAL][ARM_PLAIN]["0.00"]["all"]["decisions"]
    print(
        f"\ncounterfactual policy, plain payloads (ratio 0.00): {plain}  "
        "(BLOCK stays unreachable without obfuscation)"
    )


def print_benign(summary: dict[str, Any]) -> None:
    header("Benign controls (unmodified recorded tool results / repository lines)")
    for policy in (POLICY_SHIPPED, POLICY_COUNTERFACTUAL):
        cells = summary[policy][ARM_BENIGN]["0.00"]
        for name in ("all", "benign_chain", "benign_lines"):
            cell = cells[name]
            print(
                f"{policy:26s} {name:13s} n={cell['n']:>3}  "
                f"injection flag {fmt(cell['injection_flag'])}  "
                f"any action {fmt(cell['any_action'])}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--allow-missing-llmail", action="store_true")
    args = parser.parse_args()
    started = time.perf_counter()

    try:
        corpus = load_corpus()
    except FileNotFoundError as exc:
        print(
            f"corpus missing: {exc}\n"
            "fetch it with corpus.sources.fetch() and fetch_llmail_inject() "
            "(see this script's docstring)"
        )
        return 2
    if corpus.missing_families:
        print(f"MISSING adversarial family: {', '.join(corpus.missing_families)}")
        print("fetch it with corpus.sources.fetch_llmail_inject() (see this script's docstring).")
        if not args.allow_missing_llmail:
            return 2

    header("Corpus")
    print(f"adversarial {corpus.manifest['adversarial_counts']}")
    print(
        f"benign      {corpus.manifest['benign_counts']} "
        f"(line pool {corpus.manifest['benign_lines']['pool_size']})"
    )

    detectors = {
        "rules_mcp": RuleDetector(families=frozenset({"mcp"})),
        "rules_inj": RuleDetector(families=frozenset({"inj"})),
        "pii": PiiDetector(),
    }
    filler = load_neutral_filler(detectors)
    shipped = load_policy_config()
    policies = {POLICY_SHIPPED: shipped, POLICY_COUNTERFACTUAL: counterfactual_policy(shipped)}

    run = run_evaluation(
        adversarial=corpus.adversarial,
        benign=corpus.benign,
        detectors=detectors,
        policies=policies,
        filler=filler,
        log_dir=args.out_dir / "audit",
    )
    calls = list(run.calls)
    summary = summarise(calls)
    raw = raw_isolated_recall(corpus.adversarial, detectors["rules_mcp"])
    digest = results_digest(calls)
    pinned_digest = results_digest(calls, exclude_families=("benign_lines",))

    print_by_ratio(summary)
    print_by_family(summary, raw)
    print_survival(calls)
    print_block_arm(summary, calls)
    print_benign(summary)

    violations = [c for c in calls if c.violations]
    audit_ok = all(
        report["matches"] and report["rows"] == report["calls"] for report in run.audit.values()
    )
    header("Integrity")
    print(f"gate calls              {len(calls)}")
    print(f"contract violations     {len(violations)}")
    print(f"audit log complete      {audit_ok}  {run.audit}")
    print(f"results digest (pinned) {pinned_digest}   [excludes the repo-line benign sample]")
    print(f"results digest (all)    {digest}")
    for call in violations[:20]:
        print(
            f"  VIOLATION [{call.policy}/{call.arm}/{call.payload_id}/{call.ratio}] "
            f"{'; '.join(call.violations)}"
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.out_dir / "e2e_results.json"
    out_path.write_text(
        json.dumps(
            {
                "meta": {
                    "manifest": corpus.manifest,
                    "missing_families": list(corpus.missing_families),
                    "ratios": list(DILUTION_RATIOS),
                    "filler_words": len(filler.split()),
                    "filler_sha256": hashlib.sha256(filler.encode()).hexdigest(),
                    "policies": {
                        POLICY_SHIPPED: "config/policy.yaml unchanged",
                        POLICY_COUNTERFACTUAL: (
                            "config/policy.yaml with calibrated=true only (NOT shipped)"
                        ),
                    },
                    "detectors": sorted(detectors),
                    "results_digest": digest,
                    "results_digest_pinned": pinned_digest,
                    "audit": run.audit,
                    "elapsed_seconds": round(time.perf_counter() - started, 2),
                },
                "summary": summary,
                "raw_isolated_mcp_recall": raw,
                "mcp_rule_hits": rule_hits(calls),
                "calls": [c.to_json() for c in calls],
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(f"\nwrote {out_path}  ({time.perf_counter() - started:.1f}s)")
    return 1 if violations or not audit_ok else 0


if __name__ == "__main__":
    sys.exit(main())
