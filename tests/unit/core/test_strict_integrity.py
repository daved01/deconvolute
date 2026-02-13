import importlib
from unittest.mock import AsyncMock, MagicMock

import pytest

import deconvolute.clients.mcp
from deconvolute.clients.mcp import MCPProxy
from deconvolute.core.firewall import MCPFirewall
from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)


@pytest.fixture(autouse=True)
def clean_mcp_proxy():
    """Ensure MCPProxy is fresh and not using mocked mcp from other tests."""
    importlib.reload(deconvolute.clients.mcp)
    return deconvolute.clients.mcp.MCPProxy


@pytest.fixture
def mock_session():
    session = AsyncMock()
    # Mock list_tools response structure
    tool_a = MagicMock()
    tool_a.name = "tool_a"
    tool_a.model_dump.return_value = {
        "name": "tool_a",
        "description": "A test tool",
        "inputSchema": {"type": "object"},
    }

    session.list_tools.return_value.tools = [tool_a]
    return session


@pytest.fixture
def mock_firewall():
    firewall = MagicMock(spec=MCPFirewall)
    # Default behavior: Allow everything
    firewall.check_tool_list.side_effect = lambda tools: tools
    firewall.check_tool_call.return_value = SecurityResult(
        component=SecurityComponent.FIREWALL, status=SecurityStatus.SAFE, metadata={}
    )
    return firewall


@pytest.mark.asyncio
async def test_snapshot_mode_does_not_reverify(mock_session, mock_firewall):
    """Verify that default snapshot mode does NOT call list_tools during execution."""
    # Re-import to get the fresh class

    proxy = MCPProxy(mock_session, mock_firewall, integrity_mode="snapshot")

    # 1. Discovery
    await proxy.list_tools()
    assert mock_session.list_tools.call_count == 1

    # 2. Execution
    await proxy.call_tool("tool_a", {"args": "foo"})

    # Should STILL be 1 (no re-verification)
    assert mock_session.list_tools.call_count == 1
    # Check firewall call
    mock_firewall.check_tool_call.assert_called_with(
        "tool_a", {"args": "foo"}, current_tool_def=None
    )


@pytest.mark.asyncio
async def test_strict_mode_reverifies_success(mock_session, mock_firewall):
    """Verify that strict mode calls list_tools and passes definition to firewall."""
    proxy = MCPProxy(mock_session, mock_firewall, integrity_mode="strict")

    # 1. Discovery
    await proxy.list_tools()  # Count = 1

    # 2. Execution
    await proxy.call_tool("tool_a", {})

    # Should be 2 now
    assert mock_session.list_tools.call_count == 2

    # Check firewall received the tool definition
    call_args = mock_firewall.check_tool_call.call_args
    assert call_args is not None
    _, kwargs = call_args
    assert kwargs["current_tool_def"]["name"] == "tool_a"


@pytest.mark.asyncio
async def test_strict_mode_blocks_vanished_tool(mock_session, mock_firewall):
    """Verify strict mode blocks if tool disappears from server."""
    proxy = MCPProxy(mock_session, mock_firewall, integrity_mode="strict")

    # 1. Discovery (Tool exists)
    await proxy.list_tools()

    # 2. Tool vanishes!
    mock_session.list_tools.return_value.tools = []

    # 3. Execution
    result = await proxy.call_tool("tool_a", {})

    assert result.isError is True
    assert result.content[0].type == "text"
    assert "Strict Integrity Violation" in result.content[0].text
    # Firewall should NOT be called if tool is missing from server
    mock_firewall.check_tool_call.assert_not_called()


@pytest.mark.asyncio
async def test_strict_mode_handles_server_error(mock_session, mock_firewall):
    """Verify strict mode denies if server fails to list tools."""
    proxy = MCPProxy(mock_session, mock_firewall, integrity_mode="strict")

    mock_session.list_tools.side_effect = Exception("Server down")

    result = await proxy.call_tool("tool_a", {})

    assert result.isError is True
    assert "Strict Integrity Check Failed" in result.content[0].text  # type: ignore
