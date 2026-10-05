"""Tests for the network-mode forward proxy (`toolgate.proxy.netproxy`).

Real loopback sockets on both sides; name resolution and the upstream connect
are injected, so a "public" address can be routed to a local fake upstream
and the proxy's choice of address is observable. Limits are shortened so the
timeout paths run in milliseconds.

What is held here: the token is required and never forwarded; CONNECT and
absolute-form plain HTTP are decided on the target, never on Host; the policy
checks refuse in `enforce` and only record in `audit`; the safety and protocol
checks refuse in both; every failure class gets its status and body; a
rebinding name never reaches a refused address; the upstream is connected by
the checked IP.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import anyio
import anyio.abc
import pytest

from toolgate.gating.tool_calls import parse_egress_entry
from toolgate.proxy.egress import Divergence, NetworkMode
from toolgate.proxy.netproxy import EgressProxy, NetworkEvent, ProxyLimits

TOKEN = "s3cret-token"
AUTH = "Proxy-Authorization: Basic " + base64.b64encode(f"tg:{TOKEN}".encode()).decode()
PUBLIC = "93.184.215.14"
FAST = ProxyLimits(
    max_connections=8, connect_timeout=0.5, header_timeout=0.5, header_bytes=2048, idle_timeout=0.5
)


@dataclass
class Upstream:
    """A fake origin: records what it receives, answers with `reply`."""

    reply: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    echo: bool = False
    silent: bool = False
    received: bytearray = field(default_factory=bytearray)
    port: int = 0

    async def handle(self, stream: anyio.abc.ByteStream) -> None:
        async with stream:
            if self.echo:
                try:
                    while True:
                        data = await stream.receive()
                        self.received += data
                        await stream.send(data)
                except (anyio.EndOfStream, anyio.BrokenResourceError):
                    return
            with anyio.move_on_after(0.3):
                while b"\r\n\r\n" not in self.received:
                    self.received += await stream.receive()
            with anyio.move_on_after(0.1):  # a body sent in a later write
                self.received += await stream.receive()
            if self.silent:
                await anyio.sleep(5)
                return
            await stream.send(self.reply)


@dataclass
class Net:
    """Injected DNS and connect: names map to addresses, addresses to `upstream`."""

    upstream: Upstream
    names: dict[str, list[str]] = field(default_factory=dict)
    connected: list[tuple[str, int]] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    connect_delay: float = 0.0

    async def resolve(self, host: str, port: int) -> list[str]:
        self.resolved.append(host)
        if host not in self.names:
            raise OSError("name does not resolve")
        return self.names[host]

    async def connect(self, address: str, port: int) -> anyio.abc.ByteStream:
        self.connected.append((address, port))
        if self.connect_delay:
            await anyio.sleep(self.connect_delay)
        return await anyio.connect_tcp("127.0.0.1", self.upstream.port)


@asynccontextmanager
async def running(
    *entries: str,
    mode: NetworkMode = NetworkMode.ENFORCE,
    upstream: Upstream | None = None,
    names: dict[str, list[str]] | None = None,
    limits: ProxyLimits = FAST,
    in_flight: Callable[[], list[frozenset[tuple[str, int]]]] = list,
    connect_delay: float = 0.0,
) -> AsyncIterator[tuple[int, Net, list[NetworkEvent]]]:
    upstream = upstream or Upstream()
    net = Net(upstream, dict(names or {}), connect_delay=connect_delay)
    events: list[NetworkEvent] = []
    proxy = EgressProxy(
        server="fetch",
        mode=mode,
        entries=tuple(parse_egress_entry(entry) for entry in entries),
        token=TOKEN,
        record=events.append,
        in_flight=in_flight,
        limits=limits,
        resolve=net.resolve,
        connect=net.connect,
    )
    upstream_listener = await anyio.create_tcp_listener(local_host="127.0.0.1")
    upstream.port = upstream_listener.extra(anyio.abc.SocketAttribute.local_port)
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1")
    port = listener.extra(anyio.abc.SocketAttribute.local_port)
    async with anyio.create_task_group() as tg:
        tg.start_soon(upstream_listener.serve, upstream.handle)
        tg.start_soon(proxy.serve, listener)
        yield port, net, events
        tg.cancel_scope.cancel()


async def exchange(port: int, raw: bytes, *, then: bytes = b"", wait: float = 2.0) -> bytes:
    """Send `raw`, read until the proxy closes (or `wait` passes)."""
    received = bytearray()
    async with await anyio.connect_tcp("127.0.0.1", port) as stream:
        await stream.send(raw)
        with anyio.move_on_after(wait):
            try:
                while True:
                    chunk = await stream.receive()
                    received += chunk
                    if then and b"\r\n\r\n" in received:
                        await stream.send(then)
                        then = b""
            except (anyio.EndOfStream, anyio.BrokenResourceError):
                pass
    return bytes(received)


def request(line: str, *headers: str, auth: bool = True, body: bytes = b"") -> bytes:
    lines = [line, *headers, *([AUTH] if auth else [])]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def status(reply: bytes) -> int:
    return int(reply.split(b" ", 2)[1])


def body(reply: bytes) -> str:
    return reply.split(b"\r\n\r\n", 1)[1].decode()


# --- token ------------------------------------------------------------------


async def test_missing_token_is_407() -> None:
    async with running("example.com") as (port, net, events):
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1",
                                             "Host: example.com:443", auth=False))  # fmt: skip
    assert status(reply) == 407
    assert body(reply) == "toolgate: proxy authentication required"
    assert net.connected == [] and events == []


async def test_wrong_token_is_407() -> None:
    wrong = "Proxy-Authorization: Basic " + base64.b64encode(b"tg:nope").decode()
    async with running("example.com") as (port, net, _):
        reply = await exchange(
            port, request("CONNECT example.com:443 HTTP/1.1", "Host: x", wrong, auth=False)
        )
    assert status(reply) == 407
    assert net.connected == []


# --- CONNECT ------------------------------------------------------------------


async def test_allowed_connect_tunnels_to_the_checked_address() -> None:
    upstream = Upstream(echo=True)
    async with running("example.com", upstream=upstream, names={"example.com": [PUBLIC]}) as (
        port,
        net,
        events,
    ):
        reply = await exchange(
            port,
            request("CONNECT example.com:443 HTTP/1.1", "Host: example.com:443"),
            then=b"client hello",
            wait=1.0,
        )
    assert reply.startswith(b"HTTP/1.1 200")
    assert reply.endswith(b"client hello")
    assert net.connected == [(PUBLIC, 443)]
    assert len(events) == 1
    assert events[0].allowed and events[0].reason is None
    assert events[0].address == PUBLIC


async def test_connect_outside_the_union_is_refused_in_enforce() -> None:
    async with running("example.com", names={"evil.test": [PUBLIC]}) as (port, net, events):
        reply = await exchange(port, request("CONNECT evil.test:443 HTTP/1.1", "Host: evil.test"))
    assert status(reply) == 403
    assert body(reply) == "toolgate: evil.test:443 is not in the egress union of server fetch"
    assert net.connected == []
    # Not even resolved: a lookup of <secret>.attacker.test would itself leave.
    assert net.resolved == []
    assert [e.allowed for e in events] == [False]


async def test_audit_mode_records_but_forwards() -> None:
    upstream = Upstream(echo=True)
    async with running(
        "example.com", mode=NetworkMode.AUDIT, upstream=upstream, names={"evil.test": [PUBLIC]}
    ) as (port, net, events):
        reply = await exchange(port, request("CONNECT evil.test:443 HTTP/1.1", "Host: evil.test"),
                               wait=0.5)  # fmt: skip
    assert reply.startswith(b"HTTP/1.1 200")
    assert net.connected == [(PUBLIC, 443)]
    assert events[0].allowed
    assert events[0].reason == "toolgate: evil.test:443 is not in the egress union of server fetch"


async def test_audit_mode_still_requires_the_token() -> None:
    async with running("example.com", mode=NetworkMode.AUDIT) as (port, net, _):
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x",
                                             auth=False))  # fmt: skip
    assert status(reply) == 407 and net.connected == []


async def test_a_rebinding_name_is_refused_with_the_range() -> None:
    async with running("*.example.com", names={"rebind.example.com": ["127.0.0.1"]}) as (
        port,
        net,
        _,
    ):
        reply = await exchange(
            port, request("CONNECT rebind.example.com:443 HTTP/1.1", "Host: rebind.example.com")
        )
    assert status(reply) == 403
    assert body(reply) == (
        "toolgate: rebind.example.com:443 resolves to 127.0.0.1 in a refused range"
    )
    assert net.connected == []


async def test_only_a_passing_address_is_connected() -> None:
    upstream = Upstream(echo=True)
    names = {"example.com": ["10.0.0.1", PUBLIC]}
    async with running("example.com", upstream=upstream, names=names) as (port, net, _):
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x"),
                               wait=0.5)  # fmt: skip
    assert reply.startswith(b"HTTP/1.1 200")
    assert net.connected == [(PUBLIC, 443)]


async def test_localhost_entry_reaches_loopback() -> None:
    upstream = Upstream(echo=True)
    async with running("localhost:8000", upstream=upstream, names={"localhost": ["127.0.0.1"]}) as (
        port,
        net,
        _,
    ):
        reply = await exchange(port, request("CONNECT localhost:8000 HTTP/1.1", "Host: x"),
                               wait=0.5)  # fmt: skip
    assert reply.startswith(b"HTTP/1.1 200")
    assert net.connected == [("127.0.0.1", 8000)]


async def test_connect_to_the_proxy_itself_is_refused_even_in_audit() -> None:
    async with running("localhost:*", mode=NetworkMode.AUDIT) as (port, net, _):
        net.names["localhost"] = ["127.0.0.1"]
        reply = await exchange(port, request(f"CONNECT localhost:{port} HTTP/1.1", "Host: x"))
    assert status(reply) == 400
    assert net.connected == []


@pytest.mark.parametrize("target", ["example.com", "::1:443", "[fe80::1%25eth0]:443", "a@b:443"])
async def test_malformed_connect_targets_are_400(target: str) -> None:
    async with running("*") as (port, net, _):
        reply = await exchange(port, request(f"CONNECT {target} HTTP/1.1", "Host: x"))
    assert status(reply) == 400 and net.connected == []


# --- plain HTTP -----------------------------------------------------------------


async def test_plain_get_is_forwarded_origin_form_with_host_rewritten() -> None:
    upstream = Upstream()
    async with running("example.com", upstream=upstream, names={"example.com": [PUBLIC]}) as (
        port,
        net,
        _,
    ):
        reply = await exchange(
            port,
            request(
                "GET http://example.com/a/b?q=1 HTTP/1.1",
                "Host: attacker.test",
                "Proxy-Connection: keep-alive",
                "Keep-Alive: timeout=5",
                "Connection: keep-alive, X-Secret",
                "X-Secret: drop-me",
                "Accept: */*",
            ),
        )
    assert reply.endswith(b"ok") and status(reply) == 200
    assert net.connected == [(PUBLIC, 80)]
    sent = upstream.received.decode()
    head = sent.split("\r\n")
    assert head[0] == "GET /a/b?q=1 HTTP/1.1"
    lowered = sent.lower()
    assert "host: example.com\r\n" in lowered
    assert "attacker" not in lowered
    assert "proxy-authorization" not in lowered and TOKEN.lower() not in lowered
    assert "proxy-connection" not in lowered and "keep-alive" not in lowered
    assert "x-secret" not in lowered
    assert "connection: close\r\n" in lowered
    assert "accept: */*" in lowered


async def test_the_token_never_reaches_a_refused_upstream_in_audit() -> None:
    upstream = Upstream()
    async with running(
        "example.com", mode=NetworkMode.AUDIT, upstream=upstream, names={"evil.test": [PUBLIC]}
    ) as (port, _, events):
        await exchange(port, request("GET http://evil.test/x HTTP/1.1", "Host: evil.test"))
    assert upstream.received and TOKEN.encode() not in bytes(upstream.received)
    assert b"roxy-authorization" not in bytes(upstream.received)
    assert TOKEN not in repr(events)


async def test_plain_request_with_content_length_body_is_forwarded() -> None:
    upstream = Upstream()
    async with running("example.com", upstream=upstream, names={"example.com": [PUBLIC]}) as (
        port,
        _,
        _,
    ):
        reply = await exchange(
            port,
            request("POST http://example.com/p HTTP/1.1", "Host: example.com",
                    "Content-Length: 5", body=b"hello"),
        )  # fmt: skip
    assert status(reply) == 200
    assert bytes(upstream.received).endswith(b"\r\n\r\nhello")


@pytest.mark.parametrize(
    ("line", "headers"),
    [
        ("GET /x HTTP/1.1", ("Host: example.com",)),  # origin-form
        ("GET https://example.com/x HTTP/1.1", ("Host: example.com",)),
        ("GET http://example.com/x HTTP/1.1", ("Host: example.com", "Upgrade: websocket",
                                                "Connection: Upgrade")),
        ("POST http://example.com/x HTTP/1.1", ("Host: example.com",
                                                 "Transfer-Encoding: chunked")),
        ("POST http://example.com/x HTTP/1.1", ("Host: example.com", "Content-Length: 1",
                                                 "Expect: 100-continue")),
    ],
)  # fmt: skip
async def test_protocol_refusals_are_400(line: str, headers: tuple[str, ...]) -> None:
    async with running("example.com", names={"example.com": [PUBLIC]}) as (port, net, _):
        reply = await exchange(port, request(line, *headers))
    assert status(reply) == 400 and net.connected == []


async def test_a_pipelined_request_in_the_same_write_is_400() -> None:
    first = request("GET http://example.com/a HTTP/1.1", "Host: example.com")
    second = request("GET http://evil.test/b HTTP/1.1", "Host: evil.test")
    async with running("example.com", names={"example.com": [PUBLIC]}) as (port, net, _):
        reply = await exchange(port, first + second)
    assert status(reply) == 400 and net.connected == []


async def test_not_http_1_is_400() -> None:
    async with running("*") as (port, _, _):
        reply = await exchange(port, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    assert status(reply) == 400


# --- limits and upstream failures ---------------------------------------------------


async def test_oversized_headers_are_400() -> None:
    async with running("*") as (port, _, _):
        reply = await exchange(
            port, request("GET http://example.com/ HTTP/1.1", "Host: x", "X-Big: " + "a" * 4096)
        )
    assert status(reply) == 400


async def test_header_deadline_is_408() -> None:
    async with running("*") as (port, _, events):
        reply = await exchange(port, b"CONNECT example.com:443 HTTP/1.1\r\n")
    assert status(reply) == 408
    assert body(reply) == "toolgate: request timeout"
    assert events == []


async def test_connection_cap_is_503() -> None:
    limits = ProxyLimits(max_connections=1, connect_timeout=0.5, header_timeout=2.0,
                         header_bytes=2048, idle_timeout=0.5)  # fmt: skip
    async with (
        running("*", limits=limits) as (port, _, _),
        await anyio.connect_tcp("127.0.0.1", port) as held,
    ):
        await held.send(b"CONNECT ")  # holds the only slot
        await anyio.sleep(0.1)
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x"))
    assert status(reply) == 503
    assert body(reply) == "toolgate: too many connections"


async def test_dns_failure_is_502() -> None:
    async with running("example.com") as (port, _, _):
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x"))
    assert status(reply) == 502
    assert body(reply) == "toolgate: upstream unreachable"


async def test_connect_timeout_is_504() -> None:
    async with running("example.com", names={"example.com": [PUBLIC]}, connect_delay=2.0) as (
        port,
        _,
        _,
    ):
        reply = await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x"))
    assert status(reply) == 504
    assert body(reply) == "toolgate: upstream timed out"


async def test_silent_upstream_on_plain_http_is_408_before_any_response_byte() -> None:
    upstream = Upstream(silent=True)
    async with running("example.com", upstream=upstream, names={"example.com": [PUBLIC]}) as (
        port,
        _,
        _,
    ):
        reply = await exchange(port, request("GET http://example.com/ HTTP/1.1", "Host: x"))
    assert status(reply) == 408


# --- divergence and throttling ----------------------------------------------------


async def test_events_carry_divergence_from_the_calls_in_flight() -> None:
    page = [frozenset({("example.com", 443)})]
    async with running(
        "example.com", names={"example.com": [PUBLIC], "evil.test": [PUBLIC]},
        in_flight=lambda: page, upstream=Upstream(echo=True),
    ) as (port, _, events):  # fmt: skip
        await exchange(port, request("CONNECT example.com:443 HTTP/1.1", "Host: x"), wait=0.3)
        await exchange(port, request("CONNECT evil.test:443 HTTP/1.1", "Host: x"))
    assert [e.divergence for e in events] == [Divergence.MATCHED, Divergence.UNMATCHED]


async def test_repeated_refusals_are_throttled() -> None:
    async with running("example.com", names={"evil.test": [PUBLIC]}) as (port, _, events):
        for _ in range(3):
            await exchange(port, request("CONNECT evil.test:443 HTTP/1.1", "Host: x"))
    assert len(events) == 1
