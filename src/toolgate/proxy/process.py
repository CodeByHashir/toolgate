"""The server child of `toolgate wrap`: spawn, contain, shut down, exit code.

`toolgate wrap ... -- <command>` sits between an MCP host and a stdio server.
This module owns everything about the server *process*; it does not read or
write a single protocol line. The line pump (`proxy/pump.py`) is passed in as
a coroutine and gets the child's byte pipes. Splitting it this way keeps the
lifetime rules in one place, whatever the pump does.

What the caller gets
--------------------

* `run_proxy(argv, pump)` is the synchronous entry point `wrap` calls after
  its config has loaded: it puts the proxy in a kill-on-close job (Windows),
  runs `run_session` under `anyio.run`, and returns an `ExitCode`.
* `run_session(argv, pump)` spawns the child, runs the pump, decides how the
  session ended, runs the one shutdown sequence and maps the ending to an
  exit code. It is async so it can be driven in-process by tests.
* The pump is `async def pump(child: ChildProcess) -> SessionEnd`. It returns
  `HOST_CLOSED` when the host's stdin reached EOF and `CHILD_CLOSED` when the
  child's stdout did (or a write to the child failed because it is gone).
  If it raises, the session ends as an internal error.
* `spawn_child`, `shutdown_child`, `close_host_stdout` and
  `ensure_kill_on_close_job` are the pieces, public so they can be tested
  and reused.

Exit codes (design "Failure behaviour of `toolgate wrap`", R3-9 correction)
---------------------------------------------------------------------------

* `0` the host closed stdin first, whatever the child's status; that status
  is written to stderr. On POSIX, SIGTERM, SIGINT or SIGHUP to the proxy
  count as the host ending the session too, since that is how hosts stop a
  server that did not exit on EOF.
* `1` config missing or invalid; the child never started. Defined here for
  `wrap`, which returns it before calling `run_proxy`.
* `2` the child could not be started, or it exited (or closed its stdout)
  first. The proxy's own stdout is closed straight away so the host sees the
  server as dead, and the child's exit status goes to stderr.
* `3` internal error in the proxy: the shutdown sequence still runs.

The shutdown sequence (R2-13)
-----------------------------

One sequence for every exit path. Bounds are `ShutdownTimeouts`; the
defaults are the design's 5 s and 2 s::

    close child stdin --> wait <= 5 s --exited--------------------+
                             | still running                      |
                             v                                    |
                         terminate --> wait <= 2 s --exited-------+
                                          | still running         |
                                          v                       v
                                       kill child   -->   kill the rest of the tree

The last step always runs, also when the child exited cleanly, because a
launcher (`uvx`, `npx`) can exit and leave the real server running. "Kill
the tree" means: POSIX, SIGKILL to the child's process group; Windows,
TerminateProcess on every other process in the proxy's job (all of them
descend from the proxy). "Terminate" is SIGTERM to the process group on
POSIX and TerminateProcess on the child on Windows, which has no general
equivalent of SIGTERM for a console process; on Windows the terminate step
is therefore already a hard kill of the direct child.

How each ending reaches it::

    host EOF                  child exit / stdout EOF     internal error
    --------                  -----------------------     --------------
    pump returns              pump returns CHILD_CLOSED,  pump (or this
    HOST_CLOSED (or POSIX     or the child process exits  module) raises
    SIGTERM/INT/HUP)          and the pump has not        |
       |                      finished within             |
       |                      child_exit_drain            |
       |                         |                        |
       |                      close proxy stdout          log the error
       |                      (host sees server dead)     with traceback
       |                         |                        |
       v                         v                        v
    shutdown sequence         shutdown sequence        shutdown sequence
       |                         |                        |
    log child status          log child status         log child status
    exit 0                    exit 2                   exit 3

    child cannot start: no pump, no sequence; log why, close proxy stdout,
    exit 2.

Containment of the process tree
-------------------------------

Hosts often start servers through a launcher (`uvx`, `npx`) that starts the
real server as *its* child, so killing the direct child is not enough.

* Windows (eng review D2, removing the R3-12 race): before spawning, the
  proxy creates a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (ctypes,
  no pywin32) and assigns **itself** to it, once per process. Processes
  created afterwards start inside the job, so there is no window in which a
  launcher's child is outside it. The proxy holds the only handle; when the
  proxy dies for any reason, including a hard kill by the host, Windows
  closes the handle and kills every process left in the job. The job allows
  no breakaway. A child that deliberately creates its processes outside the
  job is not covered: it cannot do that under this job's limits, but a
  process could still ask some other service (for example the task
  scheduler) to start one.
* If self-assignment fails, the proxy writes a warning to stderr and
  **continues**. Gating is unaffected; what is lost is the hard-kill
  guarantee, and the graceful path then stops only the direct child. Refusing
  to start would turn an environment quirk (a host that runs servers in a job
  that forbids nesting) into a server that never starts. Windows 8 and later
  support nested jobs, so this should be rare; it has not been observed in
  testing.
* POSIX: the child starts in a new session, so it leads its own process
  group, and the shutdown sequence signals the whole group. The proxy turns
  SIGTERM, SIGINT and SIGHUP into the shutdown sequence. There is no POSIX
  equivalent of kill-on-close here: a SIGKILL to the proxy leaves the group
  running until the server notices stdin EOF, which a well-behaved MCP
  server does. A grandchild that starts its own session or group escapes
  the group kill on POSIX.

Environment (C6)
----------------

The child is spawned with `env=None`, so it inherits the proxy's own
environment block unchanged: no filtering (the SDK's `stdio_client` keeps
only a short allowlist, which drops tokens like GITHUB_TOKEN), no additions,
and on Windows no case change to names (copying `os.environ` would
upper-case them). This module never modifies the environment.

Streams
-------

The child's stdin and stdout are byte pipes; nothing is decoded or
newline-translated here. The child's stderr is inherited, so it lands in the
same place as the proxy's: the host's server log. This module writes only
to stderr. Nothing here writes to stdout, which carries only lines from the
child or produced by the gate.
"""

from __future__ import annotations

import contextlib
import enum
import os
import shutil
import signal
import subprocess
import sys
import threading
import traceback
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass

import anyio
from anyio.abc import ByteReceiveStream, ByteSendStream, Process

__all__ = [
    "ChildProcess",
    "ChildStartError",
    "ExitCode",
    "JobStatus",
    "Pump",
    "SessionEnd",
    "ShutdownTimeouts",
    "close_host_stdout",
    "ensure_kill_on_close_job",
    "run_proxy",
    "run_session",
    "shutdown_child",
    "spawn_child",
]


class ExitCode(enum.IntEnum):
    """Exit status of `toolgate wrap`."""

    HOST_CLOSED = 0
    """The host closed stdin first (or, on POSIX, signalled the proxy)."""
    CONFIG_ERROR = 1
    """Config missing or invalid; the child was never started. Used by `wrap`."""
    CHILD_FAILED = 2
    """The child could not start, or it exited or closed stdout first."""
    INTERNAL_ERROR = 3
    """An error inside the proxy; the shutdown sequence still ran."""


class SessionEnd(enum.Enum):
    """How the pump saw the session end."""

    HOST_CLOSED = "host closed stdin"
    CHILD_CLOSED = "server closed its stdout"


class JobStatus(enum.Enum):
    """Result of `ensure_kill_on_close_job`."""

    ASSIGNED = "assigned"
    """This process is in a kill-on-close job it created."""
    FAILED = "failed"
    """Creating or joining the job failed; a warning went to stderr."""
    UNSUPPORTED = "unsupported"
    """Not Windows; the POSIX process group is used instead."""


@dataclass(frozen=True)
class ShutdownTimeouts:
    """Bounds, in seconds, for the shutdown sequence."""

    stdin_close_grace: float = 5.0
    """How long the child gets to exit after its stdin is closed."""
    terminate_grace: float = 2.0
    """How long the child gets to exit after it is terminated."""
    child_exit_drain: float = 1.0
    """After the child process exits, how long the pump gets to forward what
    the child wrote before it exited and return on its own. This matters only
    when something else (a grandchild) still holds the child's stdout open, so
    the pump would otherwise never see EOF."""
    reap_grace: float = 2.0
    """How long to wait for the child to be reaped after the final kill."""


DEFAULT_TIMEOUTS = ShutdownTimeouts()
"""The design's bounds (5 s, 2 s). Frozen, so sharing one instance is safe."""


class ChildStartError(Exception):
    """The server command could not be started (not found, not executable)."""


@dataclass
class ChildProcess:
    """The running server: its byte pipes, for the pump, and its status."""

    process: Process
    stdin: ByteSendStream
    stdout: ByteReceiveStream

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def returncode(self) -> int | None:
        return self.process.returncode

    async def wait(self) -> int:
        return await self.process.wait()


Pump = Callable[[ChildProcess], Awaitable[SessionEnd]]
"""Forwards bytes between the host and `ChildProcess`; returns how it ended."""


# --------------------------------------------------------------------------
# stderr
# --------------------------------------------------------------------------


def _say(message: str) -> None:
    """Write one diagnostic line to stderr; never raise, never touch stdout."""
    try:
        sys.stderr.write(f"toolgate: {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError, AttributeError):
        pass


def _describe_status(returncode: int | None) -> str:
    if returncode is None:
        return "still running after the final kill (could not be reaped)"
    if returncode < 0 and sys.platform != "win32":
        try:
            name = signal.Signals(-returncode).name
        except ValueError:
            name = "unknown signal"
        return f"killed by {name} ({-returncode})"
    if sys.platform == "win32" and returncode > 0xFFFF:
        return f"exit status {returncode} (0x{returncode:08X})"
    return f"exit status {returncode}"


# --------------------------------------------------------------------------
# Windows job object
# --------------------------------------------------------------------------

_job_lock = threading.Lock()
_job_status: JobStatus | None = None
_job_handle: int | None = None  # held for the life of the process, never closed

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
    _JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS = 3
    _PROCESS_TERMINATE = 0x0001
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _ERROR_MORE_DATA = 234
    _CREATE_NO_WINDOW = 0x08000000

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    _kernel32.IsProcessInJob.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetConsoleWindow.argtypes = []
    _kernel32.GetConsoleWindow.restype = wintypes.HWND

    def _win_error(what: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")

    def _win_create_self_job() -> int:
        """Create a kill-on-close job and put this process in it; return its handle."""
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _win_error("CreateJobObjectW")
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = _kernel32.SetInformationJobObject(
            job,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            error = _win_error("SetInformationJobObject")
            _kernel32.CloseHandle(job)
            raise error
        if not _kernel32.AssignProcessToJobObject(job, _kernel32.GetCurrentProcess()):
            error = _win_error("AssignProcessToJobObject")
            _kernel32.CloseHandle(job)
            raise error
        return int(job)

    def _win_job_pids(job: int) -> list[int]:
        capacity = 256
        while True:

            class _PidList(ctypes.Structure):
                _fields_ = [
                    ("NumberOfAssignedProcesses", wintypes.DWORD),
                    ("NumberOfProcessIdsInList", wintypes.DWORD),
                    ("ProcessIdList", ctypes.c_size_t * capacity),
                ]

            pid_list = _PidList()
            ok = _kernel32.QueryInformationJobObject(
                job,
                _JOB_OBJECT_BASIC_PROCESS_ID_LIST_CLASS,
                ctypes.byref(pid_list),
                ctypes.sizeof(pid_list),
                None,
            )
            if ok:
                return [int(p) for p in pid_list.ProcessIdList[: pid_list.NumberOfProcessIdsInList]]
            if ctypes.get_last_error() != _ERROR_MORE_DATA or capacity >= 1 << 16:
                raise _win_error("QueryInformationJobObject")
            capacity *= 4

    def _win_kill_job_members(job: int) -> int:
        """TerminateProcess every process in `job` except this one; return the count.

        Each pid is opened and then checked with IsProcessInJob before it is
        terminated, so a pid reused by an unrelated process between the query
        and the open is left alone.
        """
        killed = 0
        own = os.getpid()
        for pid in _win_job_pids(job):
            if pid == own:
                continue
            handle = _kernel32.OpenProcess(
                _PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if not handle:
                continue
            try:
                in_job = wintypes.BOOL(False)
                if (
                    _kernel32.IsProcessInJob(handle, job, ctypes.byref(in_job))
                    and in_job.value
                    and _kernel32.TerminateProcess(handle, 1)
                ):
                    killed += 1
            finally:
                _kernel32.CloseHandle(handle)
        return killed


def ensure_kill_on_close_job() -> JobStatus:
    """Put this process in a Windows kill-on-close job, once per process.

    Must run before the child is spawned; children inherit the job. On
    failure, warns on stderr and returns `JobStatus.FAILED`; the caller goes
    on (see the module docstring for why). Repeated calls return the first
    result without doing anything.
    """
    global _job_status, _job_handle
    with _job_lock:
        if _job_status is not None:
            return _job_status
        if sys.platform == "win32":
            try:
                _job_handle = _win_create_self_job()
            except OSError as exc:
                _job_status = JobStatus.FAILED
                _say(
                    "warning: could not place this process in a kill-on-close job object "
                    f"({exc}). If the host kills toolgate abruptly, the server it started "
                    "and that server's own child processes may keep running. A normal "
                    "shutdown still stops the server process itself."
                )
            else:
                _job_status = JobStatus.ASSIGNED
        else:
            _job_status = JobStatus.UNSUPPORTED
        return _job_status


# --------------------------------------------------------------------------
# Spawning and shutdown
# --------------------------------------------------------------------------


def _resolve_windows_command(argv: Sequence[str], env: Mapping[str, str] | None) -> Sequence[str]:
    """Windows: find a bare command name the way a shell would.

    CreateProcess only finds `.exe` files on its own, and the launchers hosts
    use for MCP servers are not: `npx` is `npx.cmd`. Hosts resolve that
    themselves before they spawn, so a host config that says `npx` works
    until `toolgate wrap --` is put in front of it -- caught by the T9 demo,
    which failed with "cannot find the file specified". The name is looked up
    with `shutil.which` on the PATH the child will get, honouring PATHEXT.
    A name with a directory part, or one that is not found, is left as it
    is, so the start fails with the operating system's own message. POSIX
    `exec` already searches PATH, so nothing changes there.

    Written as one `if sys.platform == "win32":` block rather than an early
    return on the other platforms: mypy checks for one platform at a time and
    reported the lines after an early return as unreachable on Linux.
    """
    if sys.platform == "win32" and not os.path.dirname(argv[0]):
        search_path = (env if env is not None else os.environ).get("PATH")
        found = shutil.which(argv[0], path=search_path)
        if found:
            return [found, *argv[1:]]
    return argv


async def spawn_child(argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> ChildProcess:
    """Start the server with byte pipes on stdin/stdout and inherited stderr.

    `env=None` (the default, and what `wrap` uses) passes the proxy's own
    environment block through untouched (C6). On POSIX the child leads a new
    session and process group. On Windows, a proxy that has no console (as
    when a host starts it with CREATE_NO_WINDOW) starts the child the same
    way, so a console-subsystem server does not open a visible window.

    Raises `ChildStartError` if the command cannot be started.
    """
    if not argv:
        raise ChildStartError("no server command given")
    argv = _resolve_windows_command(argv, env)
    creationflags = 0
    if sys.platform == "win32" and not _kernel32.GetConsoleWindow():
        creationflags = _CREATE_NO_WINDOW
    try:
        process = await anyio.open_process(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            env=env,
            creationflags=creationflags,
            start_new_session=sys.platform != "win32",
        )
    except OSError as exc:
        raise ChildStartError(f"could not start {argv[0]!r}: {exc}") from exc
    if process.stdin is None or process.stdout is None:  # pragma: no cover - pipes requested
        raise ChildStartError("child pipes were not created")
    return ChildProcess(process=process, stdin=process.stdin, stdout=process.stdout)


async def _wait(child: ChildProcess, seconds: float) -> bool:
    """Wait up to `seconds` for the child to exit; return whether it did."""
    with anyio.move_on_after(seconds):
        await child.wait()
    return child.returncode is not None


def _signal_group(child: ChildProcess, sig: int) -> None:
    if sys.platform != "win32":
        # The child leads its own group (start_new_session), so its pid is the
        # group id. ESRCH means the group is already empty.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(child.pid, sig)


def _terminate(child: ChildProcess) -> None:
    if sys.platform == "win32":
        with contextlib.suppress(OSError):
            child.process.terminate()
    else:
        _signal_group(child, signal.SIGTERM)


def _kill_tree(child: ChildProcess) -> None:
    if sys.platform == "win32":
        if child.returncode is None:
            with contextlib.suppress(OSError):
                child.process.kill()
        if _job_handle is not None:
            try:
                _win_kill_job_members(_job_handle)
            except OSError as exc:
                _say(f"could not stop the server's child processes: {exc}")
    else:
        _signal_group(child, signal.SIGKILL)


async def shutdown_child(
    child: ChildProcess, timeouts: ShutdownTimeouts = DEFAULT_TIMEOUTS
) -> int | None:
    """Run the shutdown sequence (R2-13) and return the child's exit status.

    Close stdin, wait, terminate, wait, kill the child and the rest of its
    tree. Shielded from cancellation, so it completes even when the session
    around it is being cancelled. Returns None only if the child could not be
    reaped after the final kill.
    """
    stream_errors = (OSError, anyio.BrokenResourceError, anyio.ClosedResourceError)
    with anyio.CancelScope(shield=True):
        with contextlib.suppress(*stream_errors):
            await child.stdin.aclose()
        if not await _wait(child, timeouts.stdin_close_grace):
            _terminate(child)
            await _wait(child, timeouts.terminate_grace)
        _kill_tree(child)
        await _wait(child, timeouts.reap_grace)
        with contextlib.suppress(*stream_errors):
            await child.stdout.aclose()
    return child.returncode


def close_host_stdout() -> None:
    """Close the proxy's stdout so the host sees the server as gone.

    Flushes what the pump already wrote, then points file descriptor 1 at the
    null device. Re-pointing rather than closing means a file opened later can
    never be given descriptor 1 and receive stray writes; the pipe to the host
    is closed either way, because this process held its only descriptor.
    """
    with contextlib.suppress(OSError, ValueError, AttributeError):
        sys.stdout.flush()
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, 1)
        finally:
            os.close(devnull)
    except OSError as exc:
        _say(f"could not close stdout: {exc}")


async def _watch_signals(stop: anyio.Event) -> None:
    """POSIX: turn SIGTERM, SIGINT and SIGHUP into a host-initiated stop.

    The receiver stays open until the session, shutdown included, is over, so
    a second signal during shutdown cannot fall back to the default handler
    and kill the proxy before the process group is stopped.
    """
    if sys.platform != "win32":
        with anyio.open_signal_receiver(signal.SIGTERM, signal.SIGINT, signal.SIGHUP) as signals:
            async for signum in signals:
                if not stop.is_set():
                    _say(f"received {signal.Signals(signum).name}; stopping the server")
                stop.set()


async def _supervise(
    child: ChildProcess, pump: Pump, timeouts: ShutdownTimeouts, stop: anyio.Event
) -> SessionEnd:
    """Run the pump until it returns, the child exits, or a stop signal arrives."""
    ending: list[SessionEnd] = []

    async with anyio.create_task_group() as tg:

        def finish(end: SessionEnd) -> None:
            if not ending:
                ending.append(end)
            tg.cancel_scope.cancel()

        async def run_pump() -> None:
            finish(await pump(child))

        async def watch_exit() -> None:
            await child.wait()
            await anyio.sleep(timeouts.child_exit_drain)
            finish(SessionEnd.CHILD_CLOSED)

        async def watch_stop() -> None:
            await stop.wait()
            finish(SessionEnd.HOST_CLOSED)

        tg.start_soon(run_pump)
        tg.start_soon(watch_exit)
        tg.start_soon(watch_stop)
    return ending[0]


async def run_session(
    argv: Sequence[str],
    pump: Pump,
    *,
    timeouts: ShutdownTimeouts = DEFAULT_TIMEOUTS,
    env: Mapping[str, str] | None = None,
    on_child_closed: Callable[[], None] | None = close_host_stdout,
) -> ExitCode:
    """Spawn the server, run `pump`, shut down, and return the exit code.

    `on_child_closed` runs as soon as the child is known to be gone or never
    started, before the shutdown sequence; by default it closes the proxy's
    stdout. Tests pass their own. This coroutine does not touch the job
    object; `run_proxy` does that first.
    """
    stop = anyio.Event()
    async with anyio.create_task_group() as signals_tg:
        signals_tg.start_soon(_watch_signals, stop)
        try:
            return await _run_one(argv, pump, timeouts, env, on_child_closed, stop)
        finally:
            signals_tg.cancel_scope.cancel()
    raise AssertionError("unreachable")  # pragma: no cover - for type checkers


async def _run_one(
    argv: Sequence[str],
    pump: Pump,
    timeouts: ShutdownTimeouts,
    env: Mapping[str, str] | None,
    on_child_closed: Callable[[], None] | None,
    stop: anyio.Event,
) -> ExitCode:
    try:
        child = await spawn_child(argv, env=env)
    except ChildStartError as exc:
        _say(f"server failed to start: {exc}")
        if on_child_closed is not None:
            on_child_closed()
        return ExitCode.CHILD_FAILED

    code = ExitCode.INTERNAL_ERROR
    try:
        try:
            end = await _supervise(child, pump, timeouts, stop)
        except Exception:
            _say("internal error; stopping the server\n" + traceback.format_exc().rstrip())
        else:
            if end is SessionEnd.CHILD_CLOSED:
                _say("server exited first (or closed its stdout); closing stdout")
                if on_child_closed is not None:
                    on_child_closed()
                code = ExitCode.CHILD_FAILED
            else:
                code = ExitCode.HOST_CLOSED
    finally:
        status = await shutdown_child(child, timeouts)
        _say(f"server process {child.pid}: {_describe_status(status)}")
    return code


def run_proxy(
    argv: Sequence[str],
    pump: Pump,
    *,
    timeouts: ShutdownTimeouts = DEFAULT_TIMEOUTS,
    env: Mapping[str, str] | None = None,
) -> ExitCode:
    """Synchronous entry point for `wrap`: job object, then `run_session`.

    Call once per process, after the config has loaded (a config failure is
    `ExitCode.CONFIG_ERROR`, returned by `wrap` without calling this). An
    exception escaping the event loop maps to `ExitCode.INTERNAL_ERROR`.
    """
    ensure_kill_on_close_job()

    async def main() -> ExitCode:
        return await run_session(argv, pump, timeouts=timeouts, env=env)

    try:
        return anyio.run(main)
    except Exception:
        _say("internal error\n" + traceback.format_exc().rstrip())
        return ExitCode.INTERNAL_ERROR
