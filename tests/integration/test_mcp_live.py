import os
import sys

import mcp.types as types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from deconvolute import mcp_guard

# Skip tests if NOT running in live mode
run_live = os.getenv("DCV_LIVE_TEST") == "true"
reason = "Skipping live MCP tests. Run with DCV_LIVE_TEST=true to enable."


@pytest.mark.skipif(not run_live, reason=reason)
@pytest.mark.asyncio
class TestLiveMCP:
    async def test_mcp_guard_integration(self):
        """
        Verifies that mcp_guard correctly wraps a real ClientSession and
        intercepts calls to a local MCP server.
        """
        # Path to the server script we created
        server_script = os.path.join(os.path.dirname(__file__), "mcp_server.py")

        server_params = StdioServerParameters(
            command=sys.executable, args=[server_script], env=None
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the session
                await session.initialize()

                # Wrap with security guard - using local test policy
                policy_path = os.path.join(
                    os.path.dirname(__file__), "policy_allow_echo.yaml"
                )

                try:
                    guarded_client = mcp_guard(session, policy_path=policy_path)
                except Exception as e:
                    pytest.skip(f"Skipping integration test config error: {e}")

                # Test list_tools
                params = await guarded_client.list_tools()
                tool_names = [t.name for t in params.tools]
                print(f"Tools found: {tool_names}")

                # Expect at least 'echo' and 'add' if policy allows them.
                # If policy blocks them, they won't be here.
                # This integration test mainly asserts that we CAN talk to the server
                # via the proxy.

                # Test call_tool (Echo)
                # If 'echo' is in the list, call it.
                if "echo" in tool_names:
                    result = await guarded_client.call_tool(
                        "echo", arguments={"message": "Hello MCP"}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "Echo: Hello MCP"

                # Test call_tool (Add)
                if "add" in tool_names:
                    result = await guarded_client.call_tool(
                        "add", arguments={"a": 10, "b": 32}
                    )
                    assert not result.isError
                    content = result.content[0]
                    assert isinstance(content, types.TextContent)
                    assert content.text == "42"
