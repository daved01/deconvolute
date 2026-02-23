import importlib
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from deconvolute.models.security import (
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)


@pytest.fixture
def mock_mcp_modules():
    """
    Patches mcp modules in sys.modules and ensures deconvolute.clients.mcp uses them.
    """
    mcp_mock = MagicMock()
    mcp_types_mock = MagicMock()
    # Link them so import mcp; mcp.types is the same as import mcp.types
    mcp_mock.types = mcp_types_mock

    with patch.dict("sys.modules", {"mcp": mcp_mock, "mcp.types": mcp_types_mock}):
        # We must ensure deconvolute.clients.mcp is loaded with these mocks
        if "deconvolute.clients.mcp" in sys.modules:
            import deconvolute.clients.mcp

            importlib.reload(deconvolute.clients.mcp)
        else:
            import deconvolute.clients.mcp

        yield mcp_types_mock


@pytest.fixture
def proxy(mock_mcp_modules, mock_session, mock_firewall):
    # Import MCPProxy here, so we get the class defined during the patch validity
    from deconvolute.clients.mcp import MCPProxy

    return MCPProxy(mock_session, mock_firewall)


@pytest.fixture
def mock_session():
    session = MagicMock()
    session.list_tools = AsyncMock()
    session.call_tool = AsyncMock()
    return session


@pytest.fixture
def mock_firewall():
    firewall = MagicMock()
    return firewall


@pytest.mark.asyncio
async def test_list_tools_filtering_success(proxy, mock_session, mock_firewall):
    # Setup mock tools
    tool_a = MagicMock(name="Tool_a")
    tool_a.name = "allowed_tool"
    tool_a.description = "Allowed Tool Description"
    tool_a.input_schema = {"type": "object"}

    tool_b = MagicMock(name="Tool_b")
    tool_b.name = "blocked_tool"
    tool_b.description = "Blocked Tool Description"
    tool_b.input_schema = {"type": "object"}

    # Mock session response
    initial_result = MagicMock()
    initial_result.tools = [tool_a, tool_b]

    # Configure model_copy to return a new mock with the updated tools
    def side_effect_model_copy(update):
        new_result = MagicMock()
        new_result.tools = update["tools"]
        return new_result

    initial_result.model_copy.side_effect = side_effect_model_copy

    mock_session.list_tools.return_value = initial_result

    # Mock firewall response (only returns allowed tools)
    mock_firewall.check_tool_list.return_value = [{"name": "allowed_tool"}]

    # Execute
    result = await proxy.list_tools()

    # Verify
    mock_firewall.check_tool_list.assert_called_once()
    assert len(result.tools) == 1
    assert result.tools[0].name == "allowed_tool"


@pytest.mark.asyncio
async def test_call_tool_allowed(proxy, mock_session, mock_firewall):
    # Setup
    tool_name = "safe_tool"
    args: dict[str, str] = {"param": "value"}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.SAFE, component=SecurityComponent.FIREWALL
    )

    mock_session.call_tool.return_value = "success"

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_called_once_with(tool_name, args)
    assert result == "success"


@pytest.mark.asyncio
async def test_call_tool_blocked(proxy, mock_session, mock_firewall, mock_mcp_modules):
    # Setup
    tool_name = "unsafe_tool"
    args: dict[str, str] = {}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.UNSAFE,
        component=SecurityComponent.FIREWALL,
        metadata={"reason": "bad tool"},
    )

    # Configure CallToolResult mock directly on the global types mock
    types_mock = mock_mcp_modules

    mock_result_instance = MagicMock()
    mock_result_instance.is_error = True
    mock_result_instance.content = [MagicMock(text="🚫 Security Violation: bad tool")]

    # Configure the mock class constructor to return our instance
    types_mock.CallToolResult.return_value = mock_result_instance

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_not_called()
    assert result.is_error is True
    assert "Security Violation: bad tool" in result.content[0].text


@pytest.mark.asyncio
async def test_call_tool_warning(proxy, mock_session, mock_firewall):
    # Setup
    tool_name = "risky_tool"
    args: dict[str, str] = {}

    mock_firewall.check_tool_call.return_value = SecurityResult(
        status=SecurityStatus.WARNING,
        component=SecurityComponent.FIREWALL,
        metadata={"action": "warn"},
    )

    mock_session.call_tool.return_value = "success"

    # Execute
    result = await proxy.call_tool(tool_name, arguments=args)

    # Verify
    mock_firewall.check_tool_call.assert_called_once_with(
        tool_name, args, current_tool_def=None
    )
    mock_session.call_tool.assert_called_once_with(tool_name, args)
    assert result == "success"
