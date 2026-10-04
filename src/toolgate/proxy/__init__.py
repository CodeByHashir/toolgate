"""The `toolgate wrap` stdio proxy.

`process` owns the server child: spawning it with byte pipes, keeping its
whole process tree inside the proxy's lifetime, the shutdown sequence and the
exit code. The line pump that sits between the two pipes lives beside it and
is passed in as a coroutine, so this package's import stays slim: nothing here
loads the detectors or the scientific stack.
"""

from toolgate.proxy.process import (
    ChildProcess,
    ChildStartError,
    ExitCode,
    JobStatus,
    Pump,
    SessionEnd,
    ShutdownTimeouts,
    close_host_stdout,
    ensure_kill_on_close_job,
    run_proxy,
    run_session,
    shutdown_child,
    spawn_child,
)

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
