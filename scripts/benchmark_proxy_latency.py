"""Latency the `toolgate wrap` proxy adds to a tool call (design success criterion).

The same N `tools/call` round-trips are timed against a local fake server
(tests/fixtures/fake_mcp_server.py) twice: once talking to the server
directly, once through `toolgate wrap` with the light path the design names
-- `evaluate_tool_call` on an egress rule, plus the `rules_mcp` and `pii`
detectors on every result, plus an audit row per call written to a WAL
SQLite file. Results of 1 KB and 100 KB.

Reported per size: p50/p95/p99 of each mode and the difference of those
percentiles ("added"). The difference of percentiles is not the percentile
of a per-call difference -- the two runs are separate -- but it is what a
user sees: how much slower the 99th-percentile call becomes. Target from the
design: p99 added under 5 ms at 1 KB. The 100 KB figure is reported, not
gated.

Each call waits for its reply before the next is sent, as a host does. A
warm-up of 50 calls per mode is discarded. Timing is wall-clock from writing
the request to reading the full reply line, measured in this process.

    uv run python scripts/benchmark_proxy_latency.py [--calls 1000] [--out FILE]
        [--network off|audit|enforce]

`--network` sets the policy's network mode (default off). The fake server makes
no HTTP requests, so with it on this measures what network mode adds to the
stdio path (the forward proxy beside the pump, and the in-flight bookkeeping),
not the cost of proxied connections.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "tests" / "fixtures" / "fake_mcp_server.py"
SIZES = {"1 KB": 1024, "100 KB": 100 * 1024}
WARMUP = 50

POLICY = """
calibrated: false
on_detector_failure: escalate
detectors:
  injection: [rules_mcp]
  redaction: [pii]
  inert: []
thresholds:
  rules_mcp:
    escalate: 1.0
    block: 1.0
  pii:
    redact: 0.7
tool_calls:
  default: allow
  rules:
    bench.fetch:
      egress: ["docs.example.com"]
audit_path: "{audit}"
network: {network}
"""


def _line(message: Any) -> bytes:
    return json.dumps(message).encode() + b"\n"


def _session(command: list[str], calls: int) -> list[float]:
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    assert process.stdin is not None and process.stdout is not None

    def roundtrip(message: dict[str, Any]) -> float:
        assert process.stdin is not None and process.stdout is not None
        start = time.perf_counter()
        process.stdin.write(_line(message))
        process.stdin.flush()
        while True:
            reply = json.loads(process.stdout.readline())
            if reply.get("id") == message["id"]:
                return (time.perf_counter() - start) * 1000.0

    roundtrip(
        {"jsonrpc": "2.0", "id": "init", "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}
    )  # fmt: skip
    process.stdin.write(_line({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    roundtrip({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
    timings = []
    for i in range(WARMUP + calls):
        elapsed = roundtrip(
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": "https://docs.example.com/x"}},
            }
        )
        if i >= WARMUP:
            timings.append(elapsed)
    process.stdin.close()
    process.wait(timeout=60)
    return timings


def _percentiles(values: list[float]) -> dict[str, float]:
    cuts = statistics.quantiles(values, n=100, method="inclusive")
    return {"p50": statistics.median(values), "p95": cuts[94], "p99": cuts[98]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--calls", type=int, default=1000)
    parser.add_argument("--out", type=Path, default=None, help="also write the results as JSON")
    parser.add_argument("--network", choices=["off", "audit", "enforce"], default="off")
    args = parser.parse_args(argv)

    report: dict[str, Any] = {
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "calls": args.calls,
        "warmup": WARMUP,
        "network": args.network,
        "sizes": {},
    }
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "bench.yaml"
        config.write_text(
            POLICY.replace("{audit}", (Path(tmp) / "audit.sqlite").as_posix()).replace(
                "{network}", f'"{args.network}"'
            ),
            encoding="utf-8",
        )
        for label, size in SIZES.items():
            server = [sys.executable, str(FAKE), "--payload", str(size)]
            wrapped = [sys.executable, "-m", "toolgate", "wrap", "--name", "bench",
                       "--config", str(config), "--", *server]  # fmt: skip
            direct = _percentiles(_session(server, args.calls))
            through = _percentiles(_session(wrapped, args.calls))
            added = {key: through[key] - direct[key] for key in direct}
            report["sizes"][label] = {"direct": direct, "wrapped": through, "added": added}

    print(
        f"{report['platform']}, Python {report['python']}, {args.calls} calls per mode, "
        f"network {args.network}"
    )
    print(f"{'size':<8}{'mode':<9}{'p50 ms':>9}{'p95 ms':>9}{'p99 ms':>9}")
    for label, rows in report["sizes"].items():
        for mode in ("direct", "wrapped", "added"):
            row = rows[mode]
            print(f"{label:<8}{mode:<9}{row['p50']:>9.3f}{row['p95']:>9.3f}{row['p99']:>9.3f}")
    target = report["sizes"]["1 KB"]["added"]["p99"]
    print(
        f"target p99 added < 5 ms at 1 KB: {'met' if target < 5.0 else 'NOT met'} ({target:.3f} ms)"
    )
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
