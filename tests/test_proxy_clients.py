"""Which HTTP clients network mode actually covers (design: network egress mode).

Network mode is cooperative: it sees a connection only if the server's HTTP
client sends it to the proxy. These tests pin, per client family, what the
README states, by pointing each client at a recording proxy with the exact
environment `wrap` builds (`network_child_env`) and asking it to fetch a
loopback URL, the demo attacker's kind of destination:

* httpx (mcp-server-fetch's client) sends loopback through the proxy, with
  the token as Proxy-Authorization;
* Node's built-in fetch with `NODE_USE_ENV_PROXY=1` sends plain http URLs,
  loopback included, as `CONNECT host:port`, with the token. Run only where
  Node 24 or later is installed; skipped otherwise.

A correction this file records: an earlier probe (2026-10-04) concluded that
Node connected to loopback directly. It had used port 9, which the Fetch
standard lists as a bad port, so Node refused the request before connecting
to anything. With an ordinary port, loopback goes through the proxy.

If a client changes, one of these fails, and the documentation must change
with it.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading

import pytest

from toolgate.proxy.egress import network_child_env

TOKEN = "t0ken-for-the-client-test"


class RecordingProxy:
    """Accepts connections, records each request line and its auth, answers 403."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, bool]] = []
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen()
        self.port = self._socket.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._socket.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
                head = data.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
                auth = any(line.lower().startswith("proxy-authorization:") for line in head[1:])
                self.requests.append((head[0], auth))
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    def env(self) -> dict[str, str]:
        url = f"http://tg:{TOKEN}@127.0.0.1:{self.port}"
        return network_child_env(os.environ, url, windows=os.name == "nt")

    def close(self) -> None:
        self._socket.close()


@pytest.fixture
def proxy() -> RecordingProxy:
    recording = RecordingProxy()
    yield recording  # type: ignore[misc]
    recording.close()


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_httpx_sends_loopback_through_the_proxy_with_the_token(proxy: RecordingProxy) -> None:
    port = _closed_port()
    code = (
        "import httpx\n"
        f"r = httpx.get('http://localhost:{port}/x', timeout=5)\n"
        "print(r.status_code)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], env=proxy.env(), capture_output=True, text=True, timeout=60
    )
    assert completed.stdout.strip() == "403", completed.stderr
    assert proxy.requests == [(f"GET http://localhost:{port}/x HTTP/1.1", True)]


def _node_major() -> int | None:
    node = shutil.which("node")
    if node is None:
        return None
    completed = subprocess.run(
        [node, "--version"], capture_output=True, text=True, timeout=30, check=False
    )
    try:
        return int(completed.stdout.strip().lstrip("v").split(".", 1)[0])
    except ValueError:
        return None


NODE_MAJOR = _node_major()
needs_node_24 = pytest.mark.skipif(
    NODE_MAJOR is None or NODE_MAJOR < 24,
    reason="Node 24 or later is needed for NODE_USE_ENV_PROXY",
)


def _node_fetch(url: str, env: dict[str, str]) -> str:
    script = (
        f"try {{ const r = await fetch({url!r}); console.log('status', r.status) }}"
        " catch (e) { console.log('error', e.cause?.code || e.message) }"
    )
    node = shutil.which("node")
    assert node is not None
    completed = subprocess.run(
        [node, "--input-type=module", "-e", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return completed.stdout.strip()


@needs_node_24
def test_node_sends_public_http_as_connect_port_80(proxy: RecordingProxy) -> None:
    _node_fetch("http://example.com/x", proxy.env())
    assert proxy.requests[:1] == [("CONNECT example.com:80 HTTP/1.1", True)]


@needs_node_24
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_node_sends_loopback_through_the_proxy(proxy: RecordingProxy, host: str) -> None:
    port = _closed_port()
    _node_fetch(f"http://{host}:{port}/x", proxy.env())
    assert proxy.requests == [(f"CONNECT {host}:{port} HTTP/1.1", True)]
