"""The network-mode forward proxy: HTTP CONNECT and absolute-form plain HTTP.

`wrap` binds this on 127.0.0.1 and points the child's proxy variables at it
(`egress.network_child_env`). Every connection a cooperative HTTP client in
the server makes, redirect hops included, arrives here and is decided by
`egress` on the target it names: the CONNECT authority or the absolute
`http://` URL. The Host header never decides anything; on plain HTTP it is
rewritten to the URL's authority before the request goes upstream.

Two classes of check (design: network egress mode):

* **Safety and protocol checks** apply in `audit` and `enforce` alike: the
  per-run token (407), a connection to this proxy itself, origin-form and
  `https://` absolute-form requests, `Upgrade`, `Transfer-Encoding` and
  `Expect` on plain HTTP, pipelined bytes, anything that is not an HTTP/1.x
  request, oversized headers and the time limits. Audit mode is never an open
  relay.
* **Policy checks**: the server's egress union and the address check. In
  `enforce` a refusal is a 403 naming its cause; in `audit` the connection
  goes through and the event records what enforce would have refused.

A name outside the union is refused in `enforce` *before* it is resolved: a
DNS lookup of `<secret>.attacker.test` is itself a way out. Names inside the
union are resolved once (inside the connect timeout), every address is
checked, and the upstream socket connects to an address that passed, never
to the name, so a second resolution cannot rebind it.

Plain HTTP carries one request per connection. Its body is accepted only with
`Content-Length`; bytes past the framed request are never forwarded. The
upstream request says `Connection: close` and the response is relayed byte for
byte until the upstream closes.

Every connection runs in its own task, so a slow upstream delays only itself;
the pump's ordered stdio loops never wait on the proxy. Expected network
failures end one connection; anything else propagates, ending the session as
an internal error. The token is compared, never logged, and never forwarded.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass

import anyio
import anyio.abc
import h11

from toolgate.gating.tool_calls import Destination, EgressEntry
from toolgate.proxy.egress import (
    AuditThrottle,
    Divergence,
    NetworkMode,
    address_refusal,
    classify_divergence,
    connect_destination,
    matching_entries,
    proxy_url_destination,
    range_refusal_body,
    union_refusal_body,
)

__all__ = ["EgressProxy", "NetworkEvent", "ProxyLimits", "default_connect", "default_resolve"]


@dataclass(frozen=True, slots=True)
class ProxyLimits:
    """Resource limits. Defaults from the design; tests shorten them."""

    max_connections: int = 64
    connect_timeout: float = 10.0
    header_timeout: float = 10.0
    header_bytes: int = 16 * 1024
    idle_timeout: float = 300.0


@dataclass(frozen=True, slots=True)
class NetworkEvent:
    """One decided connection, for the audit log.

    `allowed` says whether it was forwarded. `reason` is the policy refusal
    (in `audit`, what `enforce` would have refused), or None. `suppressed`
    counts rows the throttle skipped for the same key since the last one.
    """

    destination: Destination
    address: str | None
    allowed: bool
    reason: str | None
    divergence: Divergence
    suppressed: int = 0


Resolve = Callable[[str, int], Awaitable[list[str]]]
Connect = Callable[[str, int], Awaitable[anyio.abc.ByteStream]]


async def default_resolve(host: str, port: int) -> list[str]:
    """Addresses for `host`, in resolver order, without duplicates or zone ids."""
    infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for *_, sockaddr in infos:
        address = str(sockaddr[0]).split("%", 1)[0]
        if address not in addresses:
            addresses.append(address)
    return addresses


async def default_connect(address: str, port: int) -> anyio.abc.ByteStream:
    return await anyio.connect_tcp(address, port)


_REASONS = {
    200: "Connection Established",
    400: "Bad Request",
    403: "Forbidden",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

#: Never forwarded on plain HTTP: hop-by-hop headers (RFC 9110 7.6.1), the
#: proxy's own credentials, and Host, which is rebuilt from the URL.
_DROPPED = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authorization",
        b"proxy-authenticate",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
        b"host",
    }
)

_NETWORK_ERRORS = (
    OSError,
    anyio.BrokenResourceError,
    anyio.ClosedResourceError,
    anyio.EndOfStream,
)


class _Refusal(Exception):
    """Ends one connection with a status and a one-line body."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(body)
        self.status = status
        self.body = body


def _response(status: int, body: str = "", *, extra: str = "") -> bytes:
    payload = body.encode()
    return (
        f"HTTP/1.1 {status} {_REASONS[status]}\r\n{extra}"
        f"Content-Type: text/plain\r\nContent-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + payload


def _is_own_address(address: str) -> bool:
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


class EgressProxy:
    """Serves one wrapped server's connections (see module docstring)."""

    def __init__(
        self,
        *,
        server: str,
        mode: NetworkMode,
        entries: Sequence[EgressEntry],
        token: str,
        record: Callable[[NetworkEvent], None],
        in_flight: Callable[[], list[frozenset[tuple[str, int]]]] = list,
        limits: ProxyLimits | None = None,
        resolve: Resolve = default_resolve,
        connect: Connect = default_connect,
        throttle: AuditThrottle | None = None,
    ) -> None:
        if mode is NetworkMode.OFF:
            raise ValueError("the egress proxy runs only in audit or enforce mode")
        self.server = server
        self.mode = mode
        self.entries = tuple(entries)
        self._token = token
        self._record = record
        self._in_flight = in_flight
        self.limits = limits or ProxyLimits()
        self._resolve = resolve
        self._connect = connect
        self._throttle = throttle or AuditThrottle()
        self._active = 0
        self.port = 0

    def proxy_url(self) -> str:
        """The URL for the child's proxy variables. Holds the token: never log it."""
        return f"http://tg:{self._token}@127.0.0.1:{self.port}"

    async def serve(self, listener: anyio.abc.SocketListener) -> None:
        self.port = listener.extra(anyio.abc.SocketAttribute.local_port)
        await listener.serve(self._handle)

    def flush_suppressed(self) -> dict[tuple[str, ...], int]:
        """Rows the throttle skipped since each key's last row (call at shutdown)."""
        return self._throttle.drain()

    # --- one connection -------------------------------------------------

    async def _handle(self, client: anyio.abc.ByteStream) -> None:
        self._active += 1
        try:
            async with client:
                if self._active > self.limits.max_connections:
                    await client.send(_response(503, "toolgate: too many connections"))
                    return
                try:
                    await self._serve_one(client)
                except _Refusal as refusal:
                    extra = (
                        'Proxy-Authenticate: Basic realm="toolgate"\r\n'
                        if refusal.status == 407
                        else ""
                    )
                    with suppress(*_NETWORK_ERRORS):
                        await client.send(_response(refusal.status, refusal.body, extra=extra))
        except _NETWORK_ERRORS:
            pass
        finally:
            self._active -= 1

    async def _read_head(self, client: anyio.abc.ByteStream) -> tuple[bytes, bytes]:
        buffer = b""
        try:
            with anyio.fail_after(self.limits.header_timeout):
                while b"\r\n\r\n" not in buffer:
                    if len(buffer) > self.limits.header_bytes:
                        raise _Refusal(400, "toolgate: request headers too large")
                    buffer += await client.receive()
        except TimeoutError:
            raise _Refusal(408, "toolgate: request timeout") from None
        head, _, rest = buffer.partition(b"\r\n\r\n")
        if len(head) > self.limits.header_bytes:
            raise _Refusal(400, "toolgate: request headers too large")
        return head + b"\r\n\r\n", rest

    def _parse(self, head: bytes) -> h11.Request:
        parser = h11.Connection(h11.SERVER, max_incomplete_event_size=self.limits.header_bytes)
        try:
            parser.receive_data(head)
            event = parser.next_event()
        except h11.RemoteProtocolError:
            raise _Refusal(400, "toolgate: malformed request") from None
        if not isinstance(event, h11.Request) or event.http_version not in (b"1.0", b"1.1"):
            raise _Refusal(400, "toolgate: not an HTTP/1.x request")
        return event

    def _check_token(self, request: h11.Request) -> None:
        for name, value in request.headers:
            if name != b"proxy-authorization":
                continue
            scheme, _, encoded = value.partition(b" ")
            if scheme.lower() != b"basic":
                break
            try:
                decoded = base64.b64decode(encoded.strip(), validate=True)
            except (binascii.Error, ValueError):
                break
            password = decoded.partition(b":")[2]
            if hmac.compare_digest(password, self._token.encode()):
                return
            break
        raise _Refusal(407, "toolgate: proxy authentication required")

    async def _serve_one(self, client: anyio.abc.ByteStream) -> None:
        head, rest = await self._read_head(client)
        request = self._parse(head)
        self._check_token(request)
        target = request.target.decode("ascii", "replace")
        if request.method == b"CONNECT":
            destination = connect_destination(target)
            if destination is None:
                raise _Refusal(400, "toolgate: malformed CONNECT target")
            upstream = await self._open(destination)
            async with upstream:
                await client.send(_response(200))
                if rest:
                    await upstream.send(rest)
                await self._tunnel(client, upstream)
            return

        destination = proxy_url_destination(target)
        if destination is None:
            raise _Refusal(400, "toolgate: only absolute-form http:// requests (use CONNECT)")
        names = {name for name, _ in request.headers}
        for refused in (b"upgrade", b"transfer-encoding", b"expect"):
            if refused in names:
                raise _Refusal(400, f"toolgate: {refused.decode()} is not supported")
        length = 0
        for name, value in request.headers:
            if name == b"content-length":
                length = int(value)
        if len(rest) > length:
            raise _Refusal(400, "toolgate: one request per connection")
        upstream = await self._open(destination)
        async with upstream:
            await upstream.send(_upstream_request(request, target, destination))
            body = rest
            try:
                while len(body) < length:
                    with anyio.fail_after(self.limits.idle_timeout):
                        body += await client.receive()
            except TimeoutError:
                raise _Refusal(408, "toolgate: request timeout") from None
            if len(body) > length:
                raise _Refusal(400, "toolgate: one request per connection")
            if body:
                await upstream.send(body)
            await self._relay_response(client, upstream)

    async def _open(self, destination: Destination) -> anyio.abc.ByteStream:
        """Decide one destination and connect to it, or raise a refusal."""
        matches = matching_entries(self.entries, destination)
        reason = None if matches else union_refusal_body(destination, self.server)
        divergence = classify_divergence(destination, self._in_flight())
        if reason is not None and self.mode is NetworkMode.ENFORCE:
            # Refused before resolving: the lookup itself would leave.
            self._emit(destination, None, allowed=False, reason=reason, divergence=divergence)
            raise _Refusal(403, reason)
        try:
            with anyio.fail_after(self.limits.connect_timeout):
                host = destination.host.strip("[]")
                try:
                    addresses = await self._resolve(host, destination.port)
                except OSError:
                    addresses = []
                if destination.port == self.port and any(map(_is_own_address, addresses)):
                    raise _Refusal(400, "toolgate: refused a connection to the proxy itself")
                passing = [a for a in addresses if address_refusal(a, matches) is None]
                if reason is None and addresses and not passing:
                    reason = range_refusal_body(destination, addresses[0])
                refused = reason is not None and self.mode is NetworkMode.ENFORCE
                candidates = passing if self.mode is NetworkMode.ENFORCE else passing or addresses
                self._emit(
                    destination,
                    candidates[0] if candidates and not refused else None,
                    allowed=not refused,
                    reason=reason,
                    divergence=divergence,
                )
                if refused:
                    raise _Refusal(403, reason or "")
                for address in candidates:
                    with suppress(OSError):
                        return await self._connect(address, destination.port)
        except TimeoutError:
            raise _Refusal(504, "toolgate: upstream timed out") from None
        raise _Refusal(502, "toolgate: upstream unreachable")

    def _emit(
        self,
        destination: Destination,
        address: str | None,
        *,
        allowed: bool,
        reason: str | None,
        divergence: Divergence,
    ) -> None:
        key = (
            f"{destination.host}:{destination.port}",
            "allowed" if allowed else "refused",
            divergence.value,
        )
        suppressed = self._throttle.admit(key)
        if suppressed is None:
            return
        self._record(NetworkEvent(destination, address, allowed, reason, divergence, suppressed))

    async def _tunnel(self, client: anyio.abc.ByteStream, upstream: anyio.abc.ByteStream) -> None:
        last = [time.monotonic()]
        idle = self.limits.idle_timeout

        async def pipe(source: anyio.abc.ByteStream, sink: anyio.abc.ByteStream) -> None:
            with suppress(*_NETWORK_ERRORS):
                while True:
                    data = await source.receive()
                    last[0] = time.monotonic()
                    await sink.send(data)
            with suppress(*_NETWORK_ERRORS):
                await sink.send_eof()

        async with anyio.create_task_group() as tg:

            async def both() -> None:
                async with anyio.create_task_group() as pipes:
                    pipes.start_soon(pipe, client, upstream)
                    pipes.start_soon(pipe, upstream, client)
                tg.cancel_scope.cancel()

            async def watchdog() -> None:
                while True:
                    remaining = idle - (time.monotonic() - last[0])
                    if remaining <= 0:
                        tg.cancel_scope.cancel()
                        return
                    await anyio.sleep(remaining)

            tg.start_soon(both)
            tg.start_soon(watchdog)

    async def _relay_response(
        self, client: anyio.abc.ByteStream, upstream: anyio.abc.ByteStream
    ) -> None:
        sent = False
        while True:
            try:
                with anyio.fail_after(self.limits.idle_timeout):
                    data = await upstream.receive()
            except TimeoutError:
                if not sent:
                    raise _Refusal(408, "toolgate: request timeout") from None
                return
            except (anyio.EndOfStream, anyio.BrokenResourceError, anyio.ClosedResourceError):
                return
            await client.send(data)
            sent = True


def _upstream_request(request: h11.Request, target: str, destination: Destination) -> bytes:
    """The origin-form request the upstream sees: Host from the URL, no hop-by-hop."""
    after_scheme = target.split("://", 1)[1]
    slash = min((i for i in (after_scheme.find(c) for c in "/?#") if i >= 0), default=-1)
    path = after_scheme[slash:] if slash >= 0 else "/"
    path = path.split("#", 1)[0] or "/"
    if path.startswith("?"):
        path = "/" + path
    listed: set[bytes] = set()
    for name, value in request.headers:
        if name == b"connection":
            listed.update(token.strip().lower() for token in value.split(b","))
    host = destination.host if destination.port == 80 else f"{destination.host}:{destination.port}"
    lines = [f"{request.method.decode()} {path} HTTP/1.1".encode(), b"Host: " + host.encode()]
    for name, value in request.headers:
        if name not in _DROPPED and name not in listed:
            lines.append(name + b": " + value)
    lines.append(b"Connection: close")
    return b"\r\n".join(lines) + b"\r\n\r\n"
