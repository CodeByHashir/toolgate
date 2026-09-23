"""Check that the paid model-side runs (M15-M17) still describe the current gate.

M14-M17 made real model calls. They were run on the code as of commit
`4f99241` and integrated into `main` later, after nine further commits. Re-running
them would cost money, so this checks the one thing that could have changed a
model's behaviour -- the bytes the model was shown -- without calling a model.

Every model-visible frame is rebuilt with the gate code in this checkout, using
the evaluations' own frame-building functions, and hashed exactly as the runs
hashed it before any model call:

* M16 and M17 froze a SHA-256 of every model-visible document per condition in
  `results/{mechanism,representation}/frozen.json`. They must all be reproduced.
* M15 froze its sample but not its frames, so its gated arms are compared with
  hashes computed from the original code on 2026-09-23, recorded below. Arm C
  shows the withheld-content placeholder, which names the product; the product
  was renamed after the run, so the placeholder is mapped back to the old name
  before hashing and must then match exactly.
* M14's reported trials are all arm A, which has no gate, so the gate cannot
  affect them and there is nothing to check.

    uv run python scripts/verify_eval_frames.py

Needs the fetched corpora in `corpus/external/` (the evaluation scripts fetch
them, pinned and checksummed). Makes no model calls and needs no API key.
Exits non-zero on any mismatch.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import eval_action as act_runner  # noqa: E402  (sibling runner: build_inputs)
import eval_mechanism as mechanism  # noqa: E402
import eval_representation as representation  # noqa: E402

from llmshield_mcp.eval_action import ids_sha256  # noqa: E402
from llmshield_mcp.eval_live import frame_through  # noqa: E402

RESULTS = ROOT / "results"

#: M15's gated arms, hashed from the original code (commit `4f99241` plus the
#: then-uncommitted evaluation modules) on 2026-09-23, over the frozen sample.
M15_ORIGINAL = {
    "B_shipped": "348e22059f3ddcaf29df7d05b88f1852e4222a0a94353a49766324cc0e5bd725",
    "C_withhold_on_escalate": "615a39f23b27b509236010f4fb74230d11b0c8a64539b121f96a9b413a73a8ba",
    "D_pii_masking_off": "aa50e2ff05e15351a4369eca632b3050c02da8a478599dd7dd6d4608a0656f38",
}
#: The product was renamed after the runs; this is the only textual change the
#: withheld-content placeholder underwent.
RENAMED = ("content withheld by toolgate]", "content withheld by LLMShield-MCP]")


def frames_hash(frames: dict[str, str]) -> str:
    joined = "\n".join(f"{pid}\t{frames[pid]}" for pid in sorted(frames))
    return hashlib.sha256(joined.encode("utf-8", errors="surrogatepass")).hexdigest()


def main() -> int:
    failures = 0

    def report(label: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        failures += not ok
        print(f"  [{'ok' if ok else 'MISMATCH'}] {label} {detail}".rstrip())

    _pilot, final, benign, detectors, shipped = act_runner.build_inputs()

    def against_frozen(name: str, hashes: dict[str, str], frozen_file: Path) -> None:
        frozen = json.loads(frozen_file.read_text(encoding="utf-8"))
        keys = [k for k in hashes if k in frozen]
        same = sum(hashes[k] == frozen[k] for k in keys)
        report(f"{name}: frozen hashes reproduced", same == len(keys), f"{same}/{len(keys)}")

    attack, benign_frames, _ = mechanism.compute_frames(final, benign, detectors, shipped)
    against_frozen(
        "M16",
        mechanism.design_hashes(final, attack, benign_frames),
        RESULTS / "mechanism" / "frozen.json",
    )

    attack, benign_frames, measures = representation.compute(final, benign, detectors, shipped)
    native = representation.native_ids(final, measures)
    against_frozen(
        "M17",
        representation.design_hashes(final, attack, benign_frames, native),
        RESULTS / "representation" / "frozen.json",
    )

    frozen_ids = json.loads((RESULTS / "action" / "frozen.json").read_text(encoding="utf-8"))
    report("M15: sample is the frozen sample", ids_sha256(final) == frozen_ids["final_ids_sha256"])
    with tempfile.TemporaryDirectory() as tmp:
        n = 0
        for arm, original in M15_ORIGINAL.items():
            frames: dict[str, str] = {}
            for item in final:
                n += 1
                log = Path(tmp) / f"{n}.db"
                text, _ = frame_through(arm, item.document, shipped, detectors, log)
                frames[item.payload.payload_id] = text.replace(*RENAMED)
            report(f"M15: arm {arm} frames match the original run", frames_hash(frames) == original)

    print("all checks passed" if not failures else f"{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
