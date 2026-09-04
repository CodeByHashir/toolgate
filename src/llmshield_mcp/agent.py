"""Minimal reference agent.

Not a product. Its only job is to drive real MCP servers with a real model so
that realistic tool-call chains can be recorded for evaluation
(PROPOSAL.md section 3.1: "a minimal reference agent used only to host
realistic tool-call chains ... not a shippable product").

Why a manual tool-use loop rather than the SDK's beta `tool_runner`: the loop
is the thing being instrumented. Every call and result has to be recorded with
timing and a correlation ID, and from M2 the transport underneath is replaced
by the gating decorator. Both seams stay visible in an explicit loop, and the
evaluation path avoids depending on a beta API.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import mcp_types
from anthropic import AsyncAnthropic
from anthropic.types import MessageParam, ToolParam, ToolResultBlockParam
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from llmshield_mcp.chain import ChainRecord, ToolCallRecord
from llmshield_mcp.config import DEFAULT_AGENT_MODEL
from llmshield_mcp.servers import ServerSpec

DEFAULT_MODEL = DEFAULT_AGENT_MODEL
DEFAULT_MAX_TOKENS = 16000

#: Guards against a model that keeps calling tools forever. PROPOSAL.md FR-14
#: requires chains of at least 20 calls, so the ceiling sits well above that.
DEFAULT_MAX_ITERATIONS = 40

#: Separator between server name and tool name in the flattened tool namespace.
#: Two servers may expose the same tool name, and the Anthropic tool name
#: pattern allows only [a-zA-Z0-9_-].
NAME_SEPARATOR = "__"

SYSTEM_PROMPT = (
    "You are a research assistant with access to a sandboxed filesystem and a web "
    "fetch tool. Use the tools to answer the user's request. Prefer several small, "
    "specific tool calls over one broad one. When you have enough information, give "
    "a short plain-text answer."
)

#: Factory that turns stdio parameters into an MCP transport. Swapped in M2 for
#: the gating decorator, which is why it is a parameter rather than a hard call.
TransportFactory = Callable[[StdioServerParameters], Any]


def qualified_tool_name(server: str, tool: str) -> str:
    return f"{server}{NAME_SEPARATOR}{tool}"


def split_tool_name(qualified: str) -> tuple[str, str]:
    server, separator, tool = qualified.partition(NAME_SEPARATOR)
    if not separator:
        raise ValueError(f"tool name {qualified!r} is not server-qualified")
    return server, tool


def to_anthropic_tool(server: str, tool: mcp_types.Tool) -> ToolParam:
    """Convert one MCP tool declaration into an Anthropic tool definition."""
    return ToolParam(
        name=qualified_tool_name(server, tool.name),
        description=tool.description or f"{tool.name} (from the {server} MCP server)",
        input_schema=tool.input_schema,
    )


def flatten_result(result: mcp_types.CallToolResult) -> tuple[str, tuple[str, ...]]:
    """Reduce a CallToolResult to scannable text plus the block types it held.

    Only text blocks contribute to the text. Images, audio and embedded binary
    resources are recorded by type but never concatenated -- they are not
    text-scanned, per the binary-content policy in PROPOSAL.md section 19.
    """
    parts: list[str] = []
    types: list[str] = []
    for block in result.content:
        types.append(getattr(block, "type", type(block).__name__))
        if isinstance(block, mcp_types.TextContent):
            parts.append(block.text)
        elif isinstance(block, mcp_types.EmbeddedResource):
            resource = block.resource
            if isinstance(resource, mcp_types.TextResourceContents):
                parts.append(resource.text)
    return "\n".join(parts), tuple(types)


@dataclass(frozen=True, slots=True)
class ConnectedServer:
    name: str
    session: ClientSession
    tools: tuple[mcp_types.Tool, ...]


@asynccontextmanager
async def open_servers(
    specs: Sequence[ServerSpec],
    transport_factory: TransportFactory = stdio_client,
) -> AsyncIterator[dict[str, ConnectedServer]]:
    """Launch each server over stdio and initialise an MCP session for it."""
    async with AsyncExitStack() as stack:
        connected: dict[str, ConnectedServer] = {}
        for spec in specs:
            params = StdioServerParameters(command=spec.command, args=list(spec.args))
            read, write = await stack.enter_async_context(transport_factory(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
            connected[spec.name] = ConnectedServer(
                name=spec.name, session=session, tools=tuple(listed.tools)
            )
        yield connected


class ReferenceAgent:
    """Drives a Claude tool-use loop over connected MCP servers."""

    def __init__(
        self,
        client: AsyncAnthropic,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        system: str = SYSTEM_PROMPT,
    ) -> None:
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._max_iterations = max_iterations
        self._system = system

    async def _call_tool(
        self,
        servers: dict[str, ConnectedServer],
        index: int,
        qualified: str,
        arguments: dict[str, Any],
    ) -> tuple[ToolCallRecord, bool]:
        server_name, tool_name = split_tool_name(qualified)
        started = time.perf_counter()
        try:
            result = await servers[server_name].session.call_tool(tool_name, arguments)
            text, block_types = flatten_result(result)
            is_error = bool(result.is_error)
        except Exception as exc:  # noqa: BLE001
            # A transport or protocol failure still belongs in the chain: the
            # agent has to be told something, and silently dropping the call
            # would leave a hole in the recorded sequence.
            text = f"{type(exc).__name__}: {exc}"
            block_types = ()
            is_error = True

        record = ToolCallRecord(
            index=index,
            correlation_id=uuid.uuid4().hex,
            server=server_name,
            tool=tool_name,
            arguments=arguments,
            result_text=text,
            result_block_types=block_types,
            is_error=is_error,
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )
        return record, is_error

    async def run(self, task: str, servers: dict[str, ConnectedServer]) -> ChainRecord:
        """Run the loop until the model stops calling tools."""
        tools: list[ToolParam] = [
            to_anthropic_tool(server.name, tool)
            for server in servers.values()
            for tool in server.tools
        ]
        messages: list[MessageParam] = [{"role": "user", "content": task}]
        calls: list[ToolCallRecord] = []

        for _ in range(self._max_iterations):
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=self._system,
                tools=tools,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "pause_turn":
                # Server-side pause; resume by sending the turn back unchanged.
                continue
            if response.stop_reason != "tool_use":
                break

            # Every tool_result for one assistant turn must go back in a SINGLE
            # user message. Splitting them across messages teaches the model to
            # stop issuing parallel calls.
            results: list[ToolResultBlockParam] = []
            for block in response.content:
                if block.type != "tool_use":
                    continue
                record, is_error = await self._call_tool(
                    servers, len(calls), block.name, dict(block.input)
                )
                calls.append(record)
                results.append(
                    ToolResultBlockParam(
                        type="tool_result",
                        tool_use_id=block.id,
                        content=record.result_text or "(empty result)",
                        is_error=is_error,
                    )
                )
            messages.append({"role": "user", "content": results})

        return ChainRecord(
            task=task,
            model=self._model,
            created_at=datetime.now(UTC).isoformat(),
            servers=tuple(servers),
            calls=tuple(calls),
        )
