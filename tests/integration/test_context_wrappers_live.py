import os
import sys

import pytest
from mcp import StdioServerParameters

from deconvolute import secure_stdio_session


@pytest.mark.anyio
async def test_secure_stdio_session_lifecycle():
    """
    Verifies that the high-level secure_stdio_session context manager
    correctly spawns the server, wires the streams, and yields the
    Deconvolute proxy.
    """
    server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")
    policy_path = os.path.join(os.path.dirname(__file__), "policy_allow_echo.yaml")

    server_params = StdioServerParameters(
        command=sys.executable, args=[server_script], env=None
    )

    proxy_reference = None

    async with secure_stdio_session(server_params, policy_path=policy_path) as session:
        proxy_reference = session

        await session.initialize()
        params = await session.list_tools()

        assert "echo" in [t.name for t in params.tools]

        result = await session.call_tool("echo", arguments={"message": "Wrapper Test"})
        assert getattr(result, "isError", getattr(result, "is_error", False)) is False
        assert result.content[0].text == "Echo: Wrapper Test"

    # Ensure the underlying anyio task group / session was closed
    # by verifying we can no longer send requests through the proxy reference.
    with pytest.raises(Exception) as _:
        await proxy_reference.list_tools()
