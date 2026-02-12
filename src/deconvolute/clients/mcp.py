from typing import Any

# We perform top-level imports here because this file is only ever
# imported if the user explicitly calls 'mcp_guard()', which implies
# they have the 'mcp' library installed.
try:
    import mcp.types as types
    from mcp import ClientSession

    MCP_AVAILABLE = True
except ImportError:
    # Fallback types for static analysis if mcp is missing
    # We use a dummy class so that types.ListToolsResult works in signatures
    class DummyTypes:
        ListToolsResult = Any
        CallToolResult = Any
        Tool = Any
        TextContent = Any

    types = DummyTypes  # type: ignore
    ClientSession = Any  # type: ignore
    MCP_AVAILABLE = False

from deconvolute.core.firewall import MCPFirewall
from deconvolute.models.security import SecurityStatus
from deconvolute.utils.logger import get_logger

logger = get_logger()


class MCPProxy:
    """
    Transparent proxy for mcp.ClientSession that enforces security policies.

    This proxy sits between the Application and the MCP Client. It intercepts:
    1. list_tools(): To filter out tools that are blocked by policy.
    2. call_tool(): To block execution of unsafe tools or detect tampering.

    All other method calls (e.g. list_resources) are delegated directly to
    the underlying session.
    """

    def __init__(self, session: ClientSession, firewall: MCPFirewall) -> None:
        """
        Args:
            session: The original connected mcp.ClientSession.
            firewall: The configured enforcement engine.
        """
        self._session = session
        self._firewall = firewall

    def __getattr__(self, name: str) -> Any:
        """Delegate any unknown methods (like list_resources) to the real session."""
        return getattr(self._session, name)

    async def list_tools(self, *args: Any, **kwargs: Any) -> types.ListToolsResult:
        """
        Intercepts tool discovery to hide blocked tools.

        1. Fetches all tools from the server.
        2. Passes them through the Firewall filter.
        3. Registers allowed tools in the SessionRegistry (Snapshotting).
        4. Returns a ListToolsResult containing ONLY the allowed tools.
        """
        # Fetch real tools from the server
        result = await self._session.list_tools(*args, **kwargs)

        # Convert to dicts for firewall analysis
        # result.tools is a list[types.Tool] (Pydantic models)
        tools_data = [t.model_dump() for t in result.tools]

        # Filter & Register
        # The firewall returns only the allowed tool dicts
        allowed_data = self._firewall.check_tool_list(tools_data)
        allowed_names = {t["name"] for t in allowed_data}

        # Reconstruct the result
        # We filter the original Pydantic objects to preserve data fidelity
        filtered_tools = [t for t in result.tools if t.name in allowed_names]

        # Return a copy of the result with the tools list replaced
        # usage of model_copy with update is correct for Pydantic v2
        return result.model_copy(update={"tools": filtered_tools})

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> types.CallToolResult:
        """
        Intercepts tool execution to enforce policy.

        1. Checks Firewall for Policy (Is this allowed?) and Integrity (Is this known?).
        2. If UNSAFE, returns a fake Error Result (prevents network call).
        3. If SAFE/WARNING, proceeds with the real network call.
        """
        # Ensure arguments is a dict (mcp allows None, but firewall expects dict)
        safe_args = arguments or {}

        # Security Check
        sec_result = self._firewall.check_tool_call(name, safe_args)

        if sec_result.status == SecurityStatus.UNSAFE:
            reason = sec_result.metadata.get("reason", "Blocked by policy")
            logger.warning(f"MCPProxy: Blocked tool '{name}': {reason}")

            # Block: Return a valid MCP Error Result
            # This allows the app to handle the failure gracefully without crashing.
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"🚫 Security Violation: {reason}",
                    )
                ],
                isError=True,
            )

        # Log Warnings if present (Audit mode)
        if sec_result.status == SecurityStatus.WARNING:
            logger.warning(
                f"MCPProxy: Warning for tool '{name}': {sec_result.metadata}"
            )

        # Allow: Execute the real tool call
        return await self._session.call_tool(name, arguments, *args, **kwargs)
