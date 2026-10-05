"""`toolgate wrap --name N [--config C] -- <server command>`: startup and wiring.

This module turns command-line input into a running proxy and nothing more:
it resolves and validates the config, opens the audit log, builds the pump's
core, and hands both to `proxy.process.run_proxy`. Every decision about
lines is in `proxy.pump`; everything about the child process is in
`proxy.process`.

Failure behaviour (design "Failure behaviour of `toolgate wrap`")
-----------------------------------------------------------------

* **Config resolution:** `--config`, then `$TOOLGATE_CONFIG`. There is no
  working-directory fallback, because hosts start servers from directories
  the user does not choose. No config, an unreadable or invalid one, an
  unexpandable placeholder (D3), an unusable audit path or a detector that
  cannot be built all exit **1** with a one-line reason on stderr, before
  the child starts. There is never an unprotected pass-through.
* Once the config has loaded, the exit codes are `proxy.process.ExitCode`:
  0 host closed stdin first, 2 server failed or exited first, 3 internal
  error (including ten consecutive audit failures, D10).

Config keys `wrap` reads on top of the policy schema (`gating/policy.py`):

* `sandbox:` -- expands `{sandbox}` in `paths` globs (D3);
* `state_dir:` -- default: the platform's user state directory
  (`platformdirs.user_state_dir("toolgate")`);
* `audit_path:` -- default `<state_dir>/audit/<name>.sqlite`, one file per
  server (D9). A path shared by several servers is allowed (WAL).

All three accept `~` and `${NAME}`, and a relative value is resolved against
the config file's directory.

* `network:` -- `off` (default), `audit` or `enforce` (design: network egress
  mode). When on, `wrap` binds a forward proxy on 127.0.0.1 before the child
  starts (a bind failure exits 1), refuses to start if the environment already
  names an upstream proxy (chaining is not supported), and gives the child a
  copy of the environment with the proxy variables pointing at it and every
  `NO_PROXY` removed. Off, the child's environment is passed through untouched
  (`env=None`, C6). Cooperative only: clients that ignore proxy variables, and
  Node's built-in fetch for loopback destinations, are not covered.

stdout carries only lines from the server or produced by the gate; every
diagnostic goes to stderr, which hosts keep as the server's log.
"""

from __future__ import annotations

import dataclasses
import os
import re
import secrets
import socket
import sqlite3
import sys
import uuid
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

import anyio
import anyio.abc
import yaml

from toolgate.gating.audit import (
    AuditWriter,
    Decision,
    DecisionLog,
    DecisionRecord,
    Outcome,
    default_audit_path,
)
from toolgate.gating.policy import PolicyConfig, load_policy_config
from toolgate.gating.tool_calls import PlaceholderError, expand_placeholders, resolve_sandbox
from toolgate.proxy.egress import (
    NetworkMode,
    egress_union,
    network_child_env,
    parent_proxy_variables,
    parse_network_mode,
)
from toolgate.proxy.lines import CHUNK_BYTES
from toolgate.proxy.netproxy import EgressProxy, NetworkEvent
from toolgate.proxy.process import ChildProcess, ExitCode, SessionEnd, run_proxy
from toolgate.proxy.pump import ProxyCore, ProxySettings, run_pump

#: The environment variable read when `--config` is not given.
CONFIG_ENV = "TOOLGATE_CONFIG"

#: `--name` is the `<server>` part of every rule id, so the server is
#: everything before the first dot of a rule id (design "Rule ids").
NAME_RE = re.compile(r"[A-Za-z0-9_-]+\Z")


class WrapConfigError(Exception):
    """The proxy cannot start safely; `wrap` exits 1 with this message."""


@dataclass(frozen=True, slots=True)
class WrapConfig:
    name: str
    config_path: Path
    #: The policy with `paths` placeholders already expanded.
    policy: PolicyConfig
    sandbox: Path | None
    state_dir: Path
    audit_path: Path
    network: NetworkMode = NetworkMode.OFF


def _default_state_dir() -> Path:
    import platformdirs

    return Path(platformdirs.user_state_dir("toolgate", appauthor=False))


def _path_setting(
    raw: dict[str, Any],
    key: str,
    *,
    base_dir: Path,
    environ: Mapping[str, str],
    home: Path,
) -> Path | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise WrapConfigError(f"{key} must be a non-empty path string")
    return resolve_sandbox(value, base_dir=base_dir, environ=environ, home=home, key=key)


def resolve_config_path(argument: str | None, environ: Mapping[str, str]) -> Path:
    """`--config`, else `$TOOLGATE_CONFIG`, else an error. No other fallback."""
    value = argument or environ.get(CONFIG_ENV)
    if not value:
        raise WrapConfigError(f"no config: pass --config <file> or set {CONFIG_ENV}")
    path = Path(value)
    if not path.is_file():
        raise WrapConfigError(f"config file not found: {path}")
    return path.resolve()


def load_wrap_config(
    name: str,
    config_path: Path,
    *,
    environ: Mapping[str, str],
    home: Path,
) -> WrapConfig:
    """Load, validate and expand everything `wrap` needs, or raise `WrapConfigError`."""
    if not NAME_RE.match(name):
        raise WrapConfigError(f"--name {name!r} must match [A-Za-z0-9_-]+")
    try:
        policy = load_policy_config(config_path)
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise WrapConfigError(f"invalid config {config_path}: {exc}") from exc
    assert isinstance(raw, dict)  # load_policy_config already required a mapping

    base_dir = config_path.parent
    try:
        sandbox = (
            resolve_sandbox(policy.sandbox, base_dir=base_dir, environ=environ, home=home)
            if policy.sandbox
            else None
        )
        tool_calls = expand_placeholders(
            policy.tool_calls, sandbox=sandbox, environ=environ, home=home
        )
        state_dir = (
            _path_setting(raw, "state_dir", base_dir=base_dir, environ=environ, home=home)
            or _default_state_dir()
        )
        audit_path = _path_setting(
            raw, "audit_path", base_dir=base_dir, environ=environ, home=home
        ) or default_audit_path(state_dir, name)
        network = parse_network_mode(raw.get("network"))
    except (PlaceholderError, ValueError) as exc:
        raise WrapConfigError(f"invalid config {config_path}: {exc}") from exc

    return WrapConfig(
        name=name,
        config_path=config_path,
        policy=dataclasses.replace(policy, tool_calls=tool_calls),
        sandbox=sandbox,
        state_dir=state_dir,
        audit_path=audit_path,
        network=network,
    )


class StdioHost:
    """The host side of the pump: this process's stdin and stdout, as bytes.

    Reads run in a worker thread because a blocking pipe read is the only
    portable way to read stdin (Windows has no async pipe stdin in anyio).
    The thread may still be blocked in `read1` when the session ends; `wrap`
    therefore leaves with `os._exit` after flushing, rather than waiting for
    interpreter shutdown to join it (`proxy/process.py` notes).
    """

    def __init__(self, stdin: IO[bytes] | None = None, stdout: IO[bytes] | None = None) -> None:
        self._in = stdin if stdin is not None else sys.stdin.buffer
        self._out = stdout if stdout is not None else sys.stdout.buffer

    def _read(self) -> bytes:
        try:
            read1 = getattr(self._in, "read1", None)
            data = read1(CHUNK_BYTES) if read1 is not None else self._in.read(CHUNK_BYTES)
        except (OSError, ValueError):
            return b""
        return bytes(data or b"")

    async def receive(self) -> bytes:
        return await anyio.to_thread.run_sync(self._read, abandon_on_cancel=True)

    def _write(self, data: bytes) -> None:
        self._out.write(data)
        self._out.flush()

    async def send(self, data: bytes) -> None:
        await anyio.to_thread.run_sync(self._write, data)


def _say(name: str, message: str) -> None:
    with suppress(OSError, ValueError, AttributeError):
        sys.stderr.write(f"toolgate[{name}]: {message}\n")
        sys.stderr.flush()


LAUNCHER_HINT = (
    "the server exited before initialize with network mode on; launchers such as "
    "uvx and npx contact their package index through the proxy. Use 'uvx --offline' "
    "or 'npx --offline' (after one run without network mode fills the cache), or a "
    "preinstalled server."
)


def _network_record(name: str, mode: NetworkMode, event: NetworkEvent) -> DecisionRecord:
    """One audit row for a decided connection. Holds host:port, never the token."""
    destination = f"{event.destination.host}:{event.destination.port}"
    rule = f"{name}.network.egress"
    if not event.allowed:
        note = f"rule {rule}: {event.reason}"
    elif event.reason:
        note = f"rule {rule}: audit only, enforce would refuse: {event.reason}"
    else:
        note = f"rule {rule}: allowed"
    scores: dict[str, object] = {
        "destination": destination,
        "address": event.address,
        "divergence": event.divergence.value,
        "mode": mode.value,
    }
    if event.suppressed:
        scores["suppressed_before"] = event.suppressed
    return DecisionRecord(
        correlation_id=uuid.uuid4().hex,
        mcp_server_id=name,
        raw_result_hash="",
        fused_decision=Decision.ALLOW if event.allowed else Decision.BLOCK,
        latency_ms=0.0,
        outcome=Outcome.NETWORK_EGRESS,
        detector_scores=scores,
        note=note,
    )


def _suppressed_record(
    name: str, mode: NetworkMode, key: tuple[str, ...], count: int
) -> DecisionRecord:
    destination, decision, divergence = key
    return DecisionRecord(
        correlation_id=uuid.uuid4().hex,
        mcp_server_id=name,
        raw_result_hash="",
        fused_decision=Decision.ALLOW if decision == "allowed" else Decision.BLOCK,
        latency_ms=0.0,
        outcome=Outcome.NETWORK_EGRESS,
        detector_scores={
            "destination": destination,
            "divergence": divergence,
            "mode": mode.value,
            "suppressed": count,
        },
        note=(
            f"rule {name}.network.egress: {count} further {decision} connection(s) "
            "not logged individually (throttled)"
        ),
    )


def run_wrap(
    name: str,
    config: str | None,
    command: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Start the proxy for one server and return its exit code (see module docstring)."""
    environ = os.environ if environ is None else environ
    if not command:
        _say(name, "no server command: use `toolgate wrap --name N -- <command> [args...]`")
        return int(ExitCode.CONFIG_ERROR)
    try:
        config_path = resolve_config_path(config, environ)
        settings = load_wrap_config(name, config_path, environ=environ, home=Path.home())
    except WrapConfigError as exc:
        _say(name, f"not started: {exc}")
        return int(ExitCode.CONFIG_ERROR)

    network = settings.network
    proxy_socket: socket.socket | None = None
    if network is not NetworkMode.OFF:
        upstream = parent_proxy_variables(environ)
        if upstream:
            _say(
                name,
                f"not started: network mode does not chain to an upstream proxy, and "
                f"{', '.join(upstream)} is set; unset it or set network: off",
            )
            return int(ExitCode.CONFIG_ERROR)
        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.bind(("127.0.0.1", 0))
            proxy_socket.listen(128)
        except OSError as exc:
            if proxy_socket is not None:
                proxy_socket.close()
            _say(name, f"not started: cannot bind the network-mode proxy: {exc}")
            return int(ExitCode.CONFIG_ERROR)

    try:
        return _run_wrapped(name, settings, command, environ, proxy_socket)
    finally:
        if proxy_socket is not None:
            proxy_socket.close()


def _run_wrapped(
    name: str,
    settings: WrapConfig,
    command: Sequence[str],
    environ: Mapping[str, str],
    proxy_socket: socket.socket | None,
) -> int:
    network = settings.network
    try:
        log = DecisionLog(settings.audit_path)
    except (OSError, sqlite3.Error) as exc:
        _say(name, f"not started: cannot open audit log {settings.audit_path}: {exc}")
        return int(ExitCode.CONFIG_ERROR)

    try:
        try:
            core = ProxyCore(
                ProxySettings(
                    name=name,
                    policy=settings.policy,
                    audit_label=str(settings.audit_path),
                    network=network is not NetworkMode.OFF,
                )
            )
        except Exception as exc:  # noqa: BLE001 -- e.g. a detector needing an absent extra
            _say(name, f"not started: cannot build the detectors this policy names: {exc}")
            return int(ExitCode.CONFIG_ERROR)

        writer = AuditWriter(log)
        host = StdioHost()
        env: dict[str, str] | None = None
        egress_proxy: EgressProxy | None = None

        def record_network(event: NetworkEvent) -> None:
            writer.append(_network_record(name, network, event))

        if proxy_socket is not None:
            token = secrets.token_urlsafe(16)
            port = proxy_socket.getsockname()[1]
            entries = egress_union(settings.policy.tool_calls, name)
            egress_proxy = EgressProxy(
                server=name,
                mode=network,
                entries=entries,
                token=token,
                record=record_network,
                in_flight=core.in_flight,
            )
            env = network_child_env(
                environ, f"http://tg:{token}@127.0.0.1:{port}", windows=os.name == "nt"
            )

        async def pump(child: ChildProcess) -> SessionEnd:
            if egress_proxy is None or proxy_socket is None:
                return await run_pump(child, host, core, audit=writer)
            listener = await anyio.abc.SocketListener.from_socket(proxy_socket)
            async with anyio.create_task_group() as tg:
                tg.start_soon(egress_proxy.serve, listener)
                try:
                    return await run_pump(child, host, core, audit=writer)
                finally:
                    tg.cancel_scope.cancel()
            raise AssertionError("unreachable")  # pragma: no cover - for type checkers

        _say(name, f"policy {settings.config_path}; audit {settings.audit_path}")
        if egress_proxy is not None:
            allows = (
                f"allows {len(egress_proxy.entries)} egress entries"
                if egress_proxy.entries
                else "allows no hosts"
            )
            _say(name, f"network mode: cooperative ({network.value}), {allows}")
        code = run_proxy(list(command), pump, env=env)
        if egress_proxy is not None:
            with suppress(Exception):
                for key, count in egress_proxy.flush_suppressed().items():
                    writer.append(_suppressed_record(name, network, key, count))
            if code is ExitCode.CHILD_FAILED and not core.server_spoke:
                _say(name, LAUNCHER_HINT)
        return int(code)
    finally:
        with suppress(Exception):
            log.close()


__all__ = [
    "CONFIG_ENV",
    "NAME_RE",
    "StdioHost",
    "WrapConfig",
    "WrapConfigError",
    "load_wrap_config",
    "resolve_config_path",
    "run_wrap",
]
