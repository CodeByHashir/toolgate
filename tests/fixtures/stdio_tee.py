"""Record the exact bytes crossing a stdio pipe. Test fixture only.

    python stdio_tee.py <log prefix> -- <command> [args...]

Starts `<command>`, copies this process's stdin to the command's stdin and
the command's stdout to this process's stdout, unchanged, and appends every
chunk to `<log prefix>.in` (what the command received) and `<log prefix>.out`
(what it sent). Put between `toolgate wrap` and a server, it shows exactly
which bytes the proxy forwarded in each direction -- the transparency test
compares these files with what the host sent and received, byte for byte.

Binary throughout; nothing is decoded or newline-translated. The command's
stderr is inherited. Exits with the command's exit status.

`--respace` (before `--`): rewrite each JSON line the command sends into
valid but deliberately non-canonical JSON (` , ` and ` : ` separators, every
other line ending in `\\r\\n`) before passing it on, and log the rewritten
bytes. A server that already writes compact JSON would otherwise make a
proxy that re-serialises indistinguishable from one that forwards bytes.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from typing import IO


def _copy(source: IO[bytes], sink: IO[bytes], log_path: str, close_sink: bool) -> None:
    read = getattr(source, "read1", source.read)
    with open(log_path, "ab") as log:
        while True:
            chunk = read(65536)
            if not chunk:
                break
            log.write(chunk)
            log.flush()
            sink.write(chunk)
            sink.flush()
    if close_sink:
        sink.close()


def _copy_respaced(source: IO[bytes], sink: IO[bytes], log_path: str) -> None:
    with open(log_path, "ab") as log:
        for count, raw in enumerate(source):
            try:
                message = json.loads(raw)
            except ValueError:
                out = raw
            else:
                ending = b"\r\n" if count % 2 else b"\n"
                text = json.dumps(message, ensure_ascii=False, separators=(" , ", " : "))
                out = text.encode("utf-8") + ending
            log.write(out)
            log.flush()
            sink.write(out)
            sink.flush()


def main(argv: list[str]) -> int:
    prefix = argv[0]
    respace = "--respace" in argv[: argv.index("--")]
    command = argv[argv.index("--") + 1 :]
    command[0] = shutil.which(command[0]) or command[0]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert child.stdin is not None and child.stdout is not None
    to_child = threading.Thread(
        target=_copy, args=(sys.stdin.buffer, child.stdin, prefix + ".in", True), daemon=True
    )
    to_child.start()
    if respace:
        _copy_respaced(child.stdout, sys.stdout.buffer, prefix + ".out")
    else:
        _copy(child.stdout, sys.stdout.buffer, prefix + ".out", False)
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
