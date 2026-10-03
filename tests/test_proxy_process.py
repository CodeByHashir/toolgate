"""Process management for `toolgate wrap` (T6) and the environment proof (C6).

Every test here uses real subprocesses. Child servers are tiny stdlib Python
scripts written to `tmp_path` and run with the *base* interpreter
(`sys._base_executable`): on Windows a venv's `python.exe` is a launcher that
starts the real interpreter as a second process, which would add a process
level the tests do not mean to have. The proxy itself is either driven
in-process through `run_session` (fast; used for exit codes and the shutdown
escalation) or run as a separate helper process through `run_proxy`, the way
`toolgate wrap` will run it (used wherever the real stdin, stdout, job object
or a hard kill matter).

In-process tests pass `on_child_closed=` a recorder, because the default
closes file descriptor 1, which here belongs to pytest.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from collections.abc import Callable
from pathlib import Path

import anyio
import pytest

from toolgate.proxy import (
    ChildProcess,
    ExitCode,
    JobStatus,
    SessionEnd,
    ShutdownTimeouts,
    run_session,
    shutdown_child,
    spawn_child,
)

WINDOWS = sys.platform == "win32"
BASE_PYTHON = getattr(sys, "_base_executable", None) or sys.executable

# Short shutdown bounds so escalation tests take about a second, not seven.
FAST = ShutdownTimeouts(stdin_close_grace=0.5, terminate_grace=0.5, child_exit_drain=0.2)

# Reads the raw environment block of the current process. On Windows this is
# GetEnvironmentStringsW, because os.environ upper-cases names and so cannot
# show whether the child received `Path` or `PATH`; on POSIX it is environb.
RAW_ENV = textwrap.dedent(
    """
    import os, sys
    def raw_env():
        if sys.platform == "win32":
            import ctypes
            k = ctypes.WinDLL("kernel32")
            k.GetEnvironmentStringsW.restype = ctypes.c_void_p
            k.FreeEnvironmentStringsW.argtypes = [ctypes.c_void_p]
            block = k.GetEnvironmentStringsW()
            out, p = [], block
            while True:
                entry = ctypes.wstring_at(p)
                if not entry:
                    break
                out.append(entry)
                p += (len(entry) + 1) * ctypes.sizeof(ctypes.c_wchar)
            k.FreeEnvironmentStringsW(block)
            return sorted(out)
        return sorted(
            (k + b"=" + v).decode("latin-1") for k, v in os.environb.items()
        )
    """
)


def _script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(RAW_ENV + textwrap.dedent(body), encoding="utf-8")
    return path


def _child(tmp_path: Path, name: str, body: str, *args: str) -> list[str]:
    return [BASE_PYTHON, str(_script(tmp_path, name, body)), *args]


ECHO_CHILD = """
    import sys
    for line in sys.stdin.buffer:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    sys.exit(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
"""

EXIT_CHILD = """
    import sys
    sys.exit(int(sys.argv[1]))
"""

# Ignores stdin EOF. With "ignore-term" it also ignores SIGTERM (POSIX only).
STUBBORN_CHILD = """
    import signal, sys, time
    if len(sys.argv) > 1 and sys.argv[1] == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    sys.stdout.buffer.write(b"ready\\n")
    sys.stdout.buffer.flush()
    sys.stdin.read()
    time.sleep(60)
"""

# Closes its stdout and keeps running: the server looks dead to the host.
CLOSE_STDOUT_CHILD = """
    import os, sys, time
    sys.stdout.close()
    os.close(1)
    time.sleep(60)
"""

# Starts a grandchild (as uvx/npx start the real server), records both pids,
# then echoes like a server. The grandchild holds no pipe to the proxy.
LAUNCHER_CHILD = """
    import os, subprocess, sys, time
    pids = sys.argv[1]
    grandchild = subprocess.Popen(
        [sys.executable, "-c",
         "import os, sys, time\\n"
         "open(sys.argv[1], 'w').write(str(os.getpid()))\\n"
         "time.sleep(120)\\n",
         pids + ".grandchild"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    )
    with open(pids + ".child", "w") as f:
        f.write(str(os.getpid()))
    for line in sys.stdin.buffer:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    time.sleep(120)
"""

ENV_CHILD = """
    import json, sys
    with open(sys.argv[1], "w", encoding="utf-8") as f:
        json.dump(raw_env(), f)
    for line in sys.stdin.buffer:
        pass
"""

# The proxy as `toolgate wrap` will run it: run_proxy with a byte pump between
# the real stdin/stdout and the child. Config arrives as JSON in argv[1].
PROXY_HELPER = """
    import json, os, sys
    import anyio
    from toolgate.proxy import SessionEnd, ShutdownTimeouts, run_proxy

    cfg = json.loads(sys.argv[1])
    argv = sys.argv[2:]
    if cfg.get("pid_file"):
        with open(cfg["pid_file"], "w") as f:
            f.write(str(os.getpid()))
    if cfg.get("env_file"):
        with open(cfg["env_file"], "w", encoding="utf-8") as f:
            json.dump(raw_env(), f)

    async def pump(child):
        # On host EOF, close the child's stdin and keep forwarding its output
        # until it closes stdout, so replies already in flight still arrive.
        if cfg.get("raise"):
            raise RuntimeError("deliberate pump failure")
        host_closed = anyio.Event()

        async def host_to_child():
            while True:
                data = await anyio.to_thread.run_sync(
                    sys.stdin.buffer.read1, 65536, abandon_on_cancel=True
                )
                if not data:
                    host_closed.set()
                    await child.stdin.aclose()
                    return
                try:
                    await child.stdin.send(data)
                except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                    return

        async with anyio.create_task_group() as tg:
            tg.start_soon(host_to_child)
            async for chunk in child.stdout:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            tg.cancel_scope.cancel()
        return SessionEnd.HOST_CLOSED if host_closed.is_set() else SessionEnd.CHILD_CLOSED

    code = run_proxy(argv, pump, timeouts=ShutdownTimeouts(**cfg.get("timeouts", {})))
    sys.stderr.flush()
    # A worker thread may still be blocked reading stdin; do not wait for it.
    os._exit(int(code))
"""


def _start_proxy(
    tmp_path: Path,
    child_argv: list[str],
    cfg: dict[str, object] | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    helper = _script(tmp_path, "proxy_helper.py", PROXY_HELPER)
    return subprocess.Popen(
        [sys.executable, str(helper), json.dumps(cfg or {}), *child_argv],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def _alive(pid: int) -> bool:
    if WINDOWS:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return bool(kernel32.WaitForSingleObject(handle, 0) == 0x102)  # WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    try:
        return stat.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


def _wait_for(predicate: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def _read_pid(path: Path) -> int:
    assert _wait_for(lambda: path.exists() and path.read_text().strip() != "", 20), path
    return int(path.read_text())


def _force_kill(pid: int) -> None:
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGTERM if WINDOWS else signal.SIGKILL)


class Recorder:
    """Stands in for `close_host_stdout` and notes what the child was doing."""

    def __init__(self) -> None:
        self.calls = 0
        self.child: ChildProcess | None = None
        self.child_running_at_close: bool | None = None

    def __call__(self) -> None:
        self.calls += 1
        if self.child is not None:
            self.child_running_at_close = self.child.returncode is None


# --------------------------------------------------------------------------
# Exit codes and the shutdown sequence, in-process
# --------------------------------------------------------------------------


def test_default_shutdown_bounds_match_the_design() -> None:
    # R2-13: close stdin, wait up to 5 s, terminate, wait 2 s, kill the tree.
    timeouts = ShutdownTimeouts()
    assert timeouts.stdin_close_grace == 5.0
    assert timeouts.terminate_grace == 2.0


def test_exit_codes_are_the_documented_values() -> None:
    assert int(ExitCode.HOST_CLOSED) == 0
    assert int(ExitCode.CONFIG_ERROR) == 1
    assert int(ExitCode.CHILD_FAILED) == 2
    assert int(ExitCode.INTERNAL_ERROR) == 3


async def test_host_eof_exits_zero_even_when_the_child_then_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = Recorder()

    async def pump(child: ChildProcess) -> SessionEnd:
        await child.stdin.send(b'{"jsonrpc":"2.0"}\n')
        assert await child.stdout.receive() == b'{"jsonrpc":"2.0"}\n'
        return SessionEnd.HOST_CLOSED

    code = await run_session(
        _child(tmp_path, "echo.py", ECHO_CHILD, "7"),
        pump,
        timeouts=FAST,
        on_child_closed=recorder,
    )
    assert code is ExitCode.HOST_CLOSED
    assert recorder.calls == 0  # host stdout is the host's to close, not ours
    err = capsys.readouterr().err
    assert "exit status 7" in err  # R3-9: the child's status is logged


async def test_child_exit_first_exits_two_and_closes_host_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = Recorder()

    async def pump(child: ChildProcess) -> SessionEnd:
        async for _ in child.stdout:
            pass
        return SessionEnd.CHILD_CLOSED

    code = await run_session(
        _child(tmp_path, "exit.py", EXIT_CHILD, "5"), pump, timeouts=FAST, on_child_closed=recorder
    )
    assert code is ExitCode.CHILD_FAILED
    assert recorder.calls == 1
    assert "exit status 5" in capsys.readouterr().err


async def test_child_exit_is_noticed_even_if_the_pump_never_sees_eof(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A grandchild holding the stdout pipe would hide EOF from the pump; the
    # process-exit watcher still ends the session.
    recorder = Recorder()

    async def pump(child: ChildProcess) -> SessionEnd:
        await anyio.sleep_forever()
        raise AssertionError("unreachable")

    with anyio.fail_after(10):
        code = await run_session(
            _child(tmp_path, "exit.py", EXIT_CHILD, "4"),
            pump,
            timeouts=FAST,
            on_child_closed=recorder,
        )
    assert code is ExitCode.CHILD_FAILED
    assert recorder.calls == 1
    assert "exit status 4" in capsys.readouterr().err


async def test_host_stdout_is_closed_before_the_shutdown_sequence_runs(tmp_path: Path) -> None:
    # The child closes stdout but stays alive: the host must see the server as
    # dead at once, not after the up-to-7 s shutdown.
    recorder = Recorder()

    async def pump(child: ChildProcess) -> SessionEnd:
        recorder.child = child
        async for _ in child.stdout:
            pass
        return SessionEnd.CHILD_CLOSED

    code = await run_session(
        _child(tmp_path, "close.py", CLOSE_STDOUT_CHILD),
        pump,
        timeouts=FAST,
        on_child_closed=recorder,
    )
    assert code is ExitCode.CHILD_FAILED
    assert recorder.calls == 1
    assert recorder.child_running_at_close is True
    assert recorder.child is not None and recorder.child.returncode is not None


async def test_command_that_cannot_start_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = Recorder()

    async def pump(child: ChildProcess) -> SessionEnd:
        raise AssertionError("pump must not run without a child")

    code = await run_session(
        [str(tmp_path / "no-such-server")], pump, timeouts=FAST, on_child_closed=recorder
    )
    assert code is ExitCode.CHILD_FAILED
    assert recorder.calls == 1
    assert "could not start" in capsys.readouterr().err


async def test_internal_error_runs_shutdown_and_exits_three(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[ChildProcess] = []

    async def pump(child: ChildProcess) -> SessionEnd:
        seen.append(child)
        raise RuntimeError("deliberate pump failure")

    recorder = Recorder()
    code = await run_session(
        _child(tmp_path, "echo.py", ECHO_CHILD), pump, timeouts=FAST, on_child_closed=recorder
    )
    assert code is ExitCode.INTERNAL_ERROR
    assert seen and seen[0].returncode == 0  # stdin closed, echo child exited cleanly
    assert recorder.calls == 0
    err = capsys.readouterr().err
    assert "internal error" in err
    assert "deliberate pump failure" in err


async def test_child_ignoring_stdin_close_is_terminated_within_the_bound(tmp_path: Path) -> None:
    seen: list[ChildProcess] = []

    async def pump(child: ChildProcess) -> SessionEnd:
        seen.append(child)
        assert await child.stdout.receive() == b"ready\n"
        return SessionEnd.HOST_CLOSED

    start = time.monotonic()
    code = await run_session(
        _child(tmp_path, "stubborn.py", STUBBORN_CHILD), pump, timeouts=FAST, on_child_closed=None
    )
    elapsed = time.monotonic() - start
    assert code is ExitCode.HOST_CLOSED
    # Waited the stdin grace, then the terminate step ended it.
    assert FAST.stdin_close_grace <= elapsed < FAST.stdin_close_grace + FAST.terminate_grace + 3
    assert seen[0].returncode is not None
    if not WINDOWS:
        assert seen[0].returncode == -signal.SIGTERM


@pytest.mark.skipif(WINDOWS, reason="TerminateProcess is already a hard kill on Windows")
async def test_child_ignoring_sigterm_is_killed_within_the_bound(tmp_path: Path) -> None:
    seen: list[ChildProcess] = []

    async def pump(child: ChildProcess) -> SessionEnd:
        seen.append(child)
        assert await child.stdout.receive() == b"ready\n"
        return SessionEnd.HOST_CLOSED

    start = time.monotonic()
    code = await run_session(
        _child(tmp_path, "stubborn.py", STUBBORN_CHILD, "ignore-term"),
        pump,
        timeouts=FAST,
        on_child_closed=None,
    )
    elapsed = time.monotonic() - start
    assert code is ExitCode.HOST_CLOSED
    bound = FAST.stdin_close_grace + FAST.terminate_grace
    assert bound <= elapsed < bound + 3
    assert seen[0].returncode == -signal.SIGKILL


async def test_spawned_child_gets_byte_pipes(tmp_path: Path) -> None:
    child = await spawn_child(_child(tmp_path, "echo.py", ECHO_CHILD))
    try:
        payload = b'{"a":"\\u00e9\\r"}\r\n'  # no newline translation either way
        await child.stdin.send(payload)
        with anyio.fail_after(10):
            received = b""
            while len(received) < len(payload):
                received += await child.stdout.receive()
        assert received == payload
    finally:
        await child.stdin.aclose()
        with anyio.fail_after(10):
            assert await child.wait() == 0


# --------------------------------------------------------------------------
# The proxy as its own process (run_proxy), as `toolgate wrap` will run it
# --------------------------------------------------------------------------


def test_proxy_host_eof_exits_zero_and_writes_only_child_bytes(tmp_path: Path) -> None:
    proxy = _start_proxy(tmp_path, _child(tmp_path, "echo.py", ECHO_CHILD, "3"))
    out, err = proxy.communicate(b'{"id":1}\n{"id":2}\n', timeout=30)
    assert proxy.returncode == 0
    assert out == b'{"id":1}\n{"id":2}\n'  # nothing of the proxy's own on stdout
    assert b"exit status 3" in err


def test_proxy_closes_stdout_promptly_when_the_child_dies_first(tmp_path: Path) -> None:
    cfg = {"timeouts": {"stdin_close_grace": 2.0, "terminate_grace": 0.5}}
    proxy = _start_proxy(tmp_path, _child(tmp_path, "close.py", CLOSE_STDOUT_CHILD), cfg)
    assert proxy.stdout is not None and proxy.stdin is not None
    start = time.monotonic()
    assert proxy.stdout.read() == b""
    eof_after = time.monotonic() - start
    assert proxy.poll() is None, "stdout should close before the shutdown sequence ends"
    proxy.stdin.close()
    proxy.wait(timeout=30)
    assert proxy.returncode == 2
    assert eof_after < 2.0
    assert proxy.stderr is not None and b"server exited first" in proxy.stderr.read()


def test_proxy_exits_two_when_the_command_cannot_start(tmp_path: Path) -> None:
    proxy = _start_proxy(tmp_path, [str(tmp_path / "no-such-server")])
    out, err = proxy.communicate(b"", timeout=30)
    assert proxy.returncode == 2
    assert out == b""
    assert b"could not start" in err


def test_proxy_exits_three_on_internal_error(tmp_path: Path) -> None:
    proxy = _start_proxy(tmp_path, _child(tmp_path, "echo.py", ECHO_CHILD), {"raise": True})
    out, err = proxy.communicate(b"", timeout=30)
    assert proxy.returncode == 3
    assert out == b""
    assert b"deliberate pump failure" in err


def test_child_receives_exactly_the_proxy_environment(tmp_path: Path) -> None:
    # C6: no filtering (the SDK's stdio_client keeps only a short allowlist),
    # no additions, and on Windows no change to the case of names.
    env = dict(os.environ)
    env["ToolGate_C6_Sentinel"] = "sentinel-value-1f6b"
    env["GITHUB_TOKEN"] = "not-a-real-token"
    proxy_env, child_env = tmp_path / "proxy_env.json", tmp_path / "child_env.json"
    proxy = _start_proxy(
        tmp_path,
        _child(tmp_path, "env.py", ENV_CHILD, str(child_env)),
        {"env_file": str(proxy_env)},
        env=env,
    )
    _, err = proxy.communicate(b"", timeout=30)
    assert proxy.returncode == 0, err
    seen_by_proxy = json.loads(proxy_env.read_text(encoding="utf-8"))
    seen_by_child = json.loads(child_env.read_text(encoding="utf-8"))
    assert "ToolGate_C6_Sentinel=sentinel-value-1f6b" in seen_by_child
    assert "GITHUB_TOKEN=not-a-real-token" in seen_by_child
    assert seen_by_child == seen_by_proxy


def test_grandchild_dies_when_the_proxy_is_killed(tmp_path: Path) -> None:
    # Windows: a hard kill (TerminateProcess). The kill-on-close job the proxy
    # put itself in takes the child and grandchild with it.
    # POSIX: SIGTERM, which the proxy turns into the shutdown sequence; a
    # SIGKILL on POSIX is not covered (see the module docstring).
    pids = tmp_path / "pids"
    proxy_pid_file = tmp_path / "proxy.pid"
    proxy = _start_proxy(
        tmp_path,
        _child(tmp_path, "launcher.py", LAUNCHER_CHILD, str(pids)),
        {"pid_file": str(proxy_pid_file), "timeouts": {"stdin_close_grace": 1.0}},
    )
    child_pid = grandchild_pid = None
    try:
        proxy_pid = _read_pid(proxy_pid_file)
        child_pid = _read_pid(Path(str(pids) + ".child"))
        grandchild_pid = _read_pid(Path(str(pids) + ".grandchild"))
        assert _alive(grandchild_pid)
        os.kill(proxy_pid, signal.SIGTERM)  # TerminateProcess on Windows
        assert _wait_for(lambda: not _alive(grandchild_pid), 15), "grandchild survived"
        assert _wait_for(lambda: not _alive(child_pid), 5), "child survived"
    finally:
        for pid in (child_pid, grandchild_pid):
            if pid is not None and _alive(pid):
                _force_kill(pid)
        proxy.kill()
        proxy.communicate(timeout=30)


@pytest.mark.skipif(not WINDOWS, reason="job objects are Windows-only")
def test_job_self_assignment_happens_once_per_process() -> None:
    code = "from toolgate.proxy import ensure_kill_on_close_job as e\nprint(e().name, e().name)\n"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=30, check=True
    ).stdout.split()
    assert out == [JobStatus.ASSIGNED.name, JobStatus.ASSIGNED.name]


def test_importing_the_proxy_stays_slim() -> None:
    heavy = [
        "numpy",
        "scipy",
        "sklearn",
        "joblib",
        "torch",
        "transformers",
        "statsmodels",
        "datasketch",
        "anthropic",
        "sentencepiece",
        "pydantic_settings",
    ]
    code = f"import sys, toolgate.proxy\nprint([m for m in {heavy!r} if m in sys.modules])\n"
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60, check=True
    ).stdout.strip()
    assert out == "[]"


@pytest.mark.skipif(sys.platform != "win32", reason="PATHEXT lookup is a Windows concern")
async def test_a_bare_cmd_launcher_name_is_found_on_windows(tmp_path: Path) -> None:
    """`npx` is `npx.cmd`; CreateProcess alone does not find it (caught by the T9 demo)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "fakelauncher.cmd").write_text("@echo launched\r\n", encoding="ascii")
    env = dict(os.environ)
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
    child = await spawn_child(["fakelauncher"], env=env)
    try:
        output = b""
        with anyio.fail_after(10):
            async for chunk in child.stdout:
                output += chunk
        assert b"launched" in output
    finally:
        await shutdown_child(child)
