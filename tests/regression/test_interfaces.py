from pathlib import Path
from typing import Any

import mcp.types as types
import pytest
from mcp.server import Server
from mcp.shared.memory import create_connected_server_and_client_session

from deconvolute.clients.mcp import MCPProxy
from deconvolute.core.firewall import MCPFirewall
from deconvolute.core.policy import PolicyLoader
from deconvolute.models.security import StdioOrigin


@pytest.fixture
def mock_firewall() -> MCPFirewall:
    """Provides a firewall instance loaded with the local regression policy."""
    policy_path = Path(__file__).parent / "policy.yaml"

    # Parse the YAML into a SecurityPolicy object using your loader
    parsed_policy = PolicyLoader.load(str(policy_path))

    # Inject the hydrated object into the firewall
    firewall = MCPFirewall(policy=parsed_policy)
    return firewall


@pytest.fixture
def mcp_server() -> Server:
    """Sets up a lightweight, in-memory MCP server."""
    app = Server("test-server")

    @app.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_tools() -> list[types.Tool]:
        test_tool_raw = {
            "name": "test_tool",
            "description": "A simple test tool",
            "inputSchema": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        }
        blocked_tool_raw = {
            "name": "blocked_tool",
            "description": "A tool that will be blocked",
            "inputSchema": {
                "type": "object",
                "properties": {},
            },
        }
        return [
            types.Tool.model_validate(test_tool_raw),
            types.Tool.model_validate(blocked_tool_raw),
        ]

    @app.call_tool()  # type: ignore[untyped-decorator]
    async def call_tool(
        name: str, arguments: dict[str, Any]
    ) -> list[types.TextContent]:
        if name == "test_tool":
            return [
                types.TextContent(type="text", text=f"Echo: {arguments.get('text')}")
            ]
        if name == "blocked_tool":
            return [types.TextContent(type="text", text="This should not be reached")]
        raise ValueError(f"Unknown tool: {name}")

    return app


@pytest.mark.anyio
async def test_tool_normalization(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that _normalize_tool safely extracts Pydantic fields without
    AttributeErrors.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)

        await proxy.initialize()
        result = await proxy.list_tools()

        assert len(result.tools) == 1
        assert result.tools[0].name == "test_tool"
        assert mock_firewall.registry.get("test_tool") is not None
        assert mock_firewall.registry.get("blocked_tool") is None


@pytest.mark.anyio
async def test_synthetic_error_result_serialization(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that the fake CallToolResult block returned by Deconvolute is a
    valid Pydantic model.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)

        await proxy.initialize()

        # Call the blocked_tool, which will be intercepted and blocked by the
        # real firewall
        result = await proxy.call_tool("blocked_tool", arguments={})

        assert getattr(result, "isError", getattr(result, "isError", False)) is True
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        assert "Security Violation" in result.content[0].text


@pytest.mark.anyio
async def test_server_identity_extraction(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates that Deconvolute safely extracts the server identity from the
    initialization result.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(session, firewall=mock_firewall, transport_origin=origin)

        init_result = await proxy.initialize()

        info = getattr(
            init_result, "server_info", getattr(init_result, "serverInfo", None)
        )
        assert info is not None
        assert info.name == "test-server"
        assert mock_firewall.server_name == "test-server"


@pytest.mark.anyio
async def test_pagination_and_cursor_extraction(
    mcp_server: Server, mock_firewall: MCPFirewall, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Validates that Deconvolute safely extracts pagination cursors from
    ListToolsResult.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        call_count = 0

        async def mock_paginated_list_tools(
            *args: Any, **kwargs: Any
        ) -> types.ListToolsResult:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Page 1: Returns a dummy tool and a cursor for the next page
                raw_result: dict[str, Any] = {
                    "tools": [
                        {"name": "tool_page_1", "description": "1", "inputSchema": {}}
                    ],
                    "nextCursor": "page_2",
                }
            else:
                # Page 2: Returns our target tool and no cursor
                raw_result = {
                    "tools": [
                        {"name": "target_tool", "description": "2", "inputSchema": {}}
                    ],
                    "nextCursor": None,
                }
            return types.ListToolsResult.model_validate(raw_result)

        # Hijack the session's list_tools to return our synthetic paginated responses
        monkeypatch.setattr(session, "list_tools", mock_paginated_list_tools)

        origin = StdioOrigin(type="stdio", command="test", args=[])

        # We explicitly enable strict mode so the proxy attempts to verify the
        # tool exists
        proxy = MCPProxy(
            session,
            firewall=mock_firewall,
            transport_origin=origin,
            integrity_mode="strict",
        )
        await proxy.initialize()

        # Pre-register the tool so it passes the registry check
        mock_firewall.registry.register(
            {"name": "target_tool", "description": "2", "input_schema": {}}
        )

        # Executing the tool triggers the strict check, which will page through
        # the mocked results
        result = await proxy.call_tool("target_tool", arguments={})

        # Prove the proxy traversed both pages
        assert call_count == 2

        # Because 'target_tool' is not explicitly allowed in our local policy.yaml,
        # it should fall back to the default 'block' action.
        # This asserts we successfully found the tool on page 2 and passed
        # it to the firewall!
        assert getattr(result, "isError", getattr(result, "is_error", False)) is True
        assert isinstance(result.content[0], types.TextContent)
        assert "Security Violation" in result.content[0].text


@pytest.mark.anyio
async def test_strict_mode_tool_vanished(
    mcp_server: Server, mock_firewall: MCPFirewall
) -> None:
    """
    Validates the synthetic error generated when a tool vanishes in strict mode.
    """

    async with create_connected_server_and_client_session(mcp_server) as session:
        origin = StdioOrigin(type="stdio", command="test", args=[])
        proxy = MCPProxy(
            session,
            firewall=mock_firewall,
            transport_origin=origin,
            integrity_mode="strict",
        )

        await proxy.initialize()

        # Manually poison the trusted registry to make it think 'vanished_tool'
        # was allowed
        mock_firewall.registry.register(
            {"name": "vanished_tool", "description": "I vanished", "input_schema": {}}
        )

        # Call the tool. The proxy will check the real server, realize it's gone,
        # and trigger the rug-pull block.
        result = await proxy.call_tool("vanished_tool", arguments={})

        assert getattr(result, "isError", getattr(result, "is_error", False)) is True
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        assert isinstance(result.content[0], types.TextContent)
        assert "Strict Integrity Violation" in result.content[0].text
        assert "vanished_tool" in result.content[0].text
