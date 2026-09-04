"""Tests for the reference agent's tool-use loop.

No network and no MCP servers: the Anthropic client and the MCP sessions are
both faked, so the loop's own behaviour is what is under test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import mcp_types
import pytest

from llmshield_mcp.agent import (
    ConnectedServer,
    ReferenceAgent,
    flatten_result,
    qualified_tool_name,
    split_tool_name,
    to_anthropic_tool,
)

# --- fakes ---------------------------------------------------------------


@dataclass
class FakeToolUse:
    id: str
    name: str
    input: dict[str, Any]
    type: str = "tool_use"


@dataclass
class FakeText:
    text: str
    type: str = "text"


@dataclass
class FakeUsage:
    input_tokens: int = 10
    output_tokens: int = 5
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class FakeResponse:
    content: list[Any]
    stop_reason: str
    usage: FakeUsage = field(default_factory=FakeUsage)


class FakeMessages:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> FakeResponse:
        self.requests.append(kwargs)
        if not self._responses:
            return FakeResponse(content=[FakeText("done")], stop_reason="end_turn")
        return self._responses.pop(0)


class FakeAnthropic:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.messages = FakeMessages(responses)


class FakeSession:
    def __init__(self, results: dict[str, Any] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((name, arguments))
        outcome = self.results.get(name)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome or mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=f"result of {name}")]
        )


def _tool(name: str) -> mcp_types.Tool:
    return mcp_types.Tool(
        name=name,
        description=f"does {name}",
        inputSchema={"type": "object", "properties": {}},
    )


def _servers(session: FakeSession, *tool_names: str) -> dict[str, ConnectedServer]:
    return {
        "filesystem": ConnectedServer(
            name="filesystem",
            session=session,  # type: ignore[arg-type]
            tools=tuple(_tool(n) for n in tool_names),
        )
    }


# --- name handling -------------------------------------------------------


def test_tool_names_are_server_qualified() -> None:
    # Two servers may expose the same tool name; without qualification one
    # would shadow the other in the flattened Anthropic tool list.
    assert qualified_tool_name("fetch", "fetch") == "fetch__fetch"
    assert split_tool_name("filesystem__read_text_file") == ("filesystem", "read_text_file")


def test_unqualified_tool_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="server-qualified"):
        split_tool_name("read_text_file")


def test_mcp_tool_converts_to_anthropic_shape() -> None:
    converted = to_anthropic_tool("filesystem", _tool("read_text_file"))

    assert converted["name"] == "filesystem__read_text_file"
    assert converted["input_schema"] == {"type": "object", "properties": {}}


def test_tool_without_description_still_gets_one() -> None:
    bare = mcp_types.Tool(name="x", inputSchema={"type": "object"})

    assert "filesystem" in to_anthropic_tool("filesystem", bare)["description"]


# --- result flattening ---------------------------------------------------


def test_text_blocks_are_concatenated() -> None:
    result = mcp_types.CallToolResult(
        content=[
            mcp_types.TextContent(type="text", text="first"),
            mcp_types.TextContent(type="text", text="second"),
        ]
    )

    text, types = flatten_result(result)

    assert text == "first\nsecond"
    assert types == ("text", "text")


def test_binary_blocks_are_typed_but_not_concatenated() -> None:
    # PROPOSAL.md section 19: binary content is not text-scanned. It must still
    # be recorded, so the policy decision is visible rather than implicit.
    result = mcp_types.CallToolResult(
        content=[
            mcp_types.TextContent(type="text", text="caption"),
            mcp_types.ImageContent(type="image", data="AAAA", mimeType="image/png"),
        ]
    )

    text, types = flatten_result(result)

    assert text == "caption"
    assert types == ("text", "image")


def test_empty_result_flattens_to_empty_string() -> None:
    text, types = flatten_result(mcp_types.CallToolResult(content=[]))

    assert text == ""
    assert types == ()


# --- the loop ------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_without_tool_use_records_no_calls() -> None:
    client = FakeAnthropic([FakeResponse([FakeText("no tools needed")], "end_turn")])
    agent = ReferenceAgent(client)  # type: ignore[arg-type]

    chain = await agent.run("hello", _servers(FakeSession(), "read_text_file"))

    assert chain.calls == ()
    assert chain.task == "hello"


@pytest.mark.asyncio
async def test_tool_call_is_executed_and_recorded() -> None:
    client = FakeAnthropic(
        [
            FakeResponse(
                [FakeToolUse("t1", "filesystem__read_text_file", {"path": "a"})], "tool_use"
            ),
            FakeResponse([FakeText("summary")], "end_turn"),
        ]
    )
    session = FakeSession()
    agent = ReferenceAgent(client)  # type: ignore[arg-type]

    chain = await agent.run("read it", _servers(session, "read_text_file"))

    assert session.calls == [("read_text_file", {"path": "a"})]
    assert len(chain.calls) == 1
    assert chain.calls[0].tool == "read_text_file"
    assert chain.calls[0].result_text == "result of read_text_file"
    assert not chain.calls[0].is_error


@pytest.mark.asyncio
async def test_parallel_tool_calls_return_in_one_user_message() -> None:
    """Splitting tool_results across messages trains the model out of parallel calls."""
    client = FakeAnthropic(
        [
            FakeResponse(
                [
                    FakeToolUse("t1", "filesystem__read_text_file", {"path": "a"}),
                    FakeToolUse("t2", "filesystem__read_text_file", {"path": "b"}),
                ],
                "tool_use",
            ),
            FakeResponse([FakeText("done")], "end_turn"),
        ]
    )
    agent = ReferenceAgent(client)  # type: ignore[arg-type]

    chain = await agent.run("read both", _servers(FakeSession(), "read_text_file"))

    assert len(chain.calls) == 2
    second_request = client.messages.requests[1]
    tool_result_messages = [
        m
        for m in second_request["messages"]
        if m["role"] == "user" and isinstance(m["content"], list)
    ]
    assert len(tool_result_messages) == 1
    assert len(tool_result_messages[0]["content"]) == 2


@pytest.mark.asyncio
async def test_failing_tool_is_recorded_and_loop_continues() -> None:
    client = FakeAnthropic(
        [
            FakeResponse([FakeToolUse("t1", "filesystem__boom", {})], "tool_use"),
            FakeResponse([FakeText("recovered")], "end_turn"),
        ]
    )
    session = FakeSession({"boom": RuntimeError("server died")})
    agent = ReferenceAgent(client)  # type: ignore[arg-type]

    chain = await agent.run("try it", _servers(session, "boom"))

    assert len(chain.calls) == 1
    assert chain.calls[0].is_error
    assert "server died" in chain.calls[0].result_text


@pytest.mark.asyncio
async def test_indices_and_correlation_ids_are_unique() -> None:
    client = FakeAnthropic(
        [
            FakeResponse([FakeToolUse("t1", "filesystem__read_text_file", {})], "tool_use"),
            FakeResponse([FakeToolUse("t2", "filesystem__read_text_file", {})], "tool_use"),
            FakeResponse([FakeText("done")], "end_turn"),
        ]
    )
    agent = ReferenceAgent(client)  # type: ignore[arg-type]

    chain = await agent.run("twice", _servers(FakeSession(), "read_text_file"))

    assert [c.index for c in chain.calls] == [0, 1]
    assert len({c.correlation_id for c in chain.calls}) == 2


@pytest.mark.asyncio
async def test_max_iterations_bounds_the_loop() -> None:
    # A model that never stops calling tools must not spin forever.
    responses = [
        FakeResponse([FakeToolUse(f"t{i}", "filesystem__read_text_file", {})], "tool_use")
        for i in range(20)
    ]
    client = FakeAnthropic(responses)
    agent = ReferenceAgent(client, max_iterations=3)  # type: ignore[arg-type]

    chain = await agent.run("loop", _servers(FakeSession(), "read_text_file"))

    assert len(chain.calls) == 3
