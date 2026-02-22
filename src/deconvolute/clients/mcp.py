import uuid
from typing import Any

from deconvolute.models.observability import ToolData

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
from deconvolute.core.types import ToolInterface
from deconvolute.models.observability import AccessEvent, DiscoveryEvent
from deconvolute.models.security import (
    IntegrityLevel,
    SecurityComponent,
    SecurityResult,
    SecurityStatus,
)
from deconvolute.observability import get_backend
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

    def __init__(
        self,
        session: ClientSession,
        firewall: MCPFirewall,
        integrity_mode: IntegrityLevel = "snapshot",
    ) -> None:
        """
        Args:
            session: The original connected mcp.ClientSession.
            firewall: The configured enforcement engine.
            integrity_mode: 'snapshot' (default) or 'strict'.
        """
        self._session = session
        self._firewall = firewall
        self._integrity_mode = integrity_mode
        self._client_session_id = str(uuid.uuid4())

    async def initialize(self, *args: Any, **kwargs: Any) -> Any:
        """
        Intercepts session initialization to dynamically extract the server's identity.
        """
        result = await self._session.initialize(*args, **kwargs)
        if hasattr(result, "serverInfo") and hasattr(result.serverInfo, "name"):
            self._firewall.set_server(result.serverInfo.name)
        return result

    async def __aenter__(self) -> "MCPProxy":
        """
        Allow using the guarded session directly in 'async with'.
        We enter the underlying session, but return 'self' (the Proxy).
        """
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Pass context exit to the underlying session."""
        await self._session.__aexit__(exc_type, exc_value, traceback)

    def __getattr__(self, name: str) -> Any:
        """Delegate any unknown methods (like list_resources) to the real session."""
        return getattr(self._session, name)

    def _normalize_tool(self, tool: types.Tool | Any) -> ToolInterface:
        """
        Explicitly maps the MCP library type to our internal ToolInterface.
        This isolates us from Pydantic serialization changes (aliases, versions).
        """
        # We try to access attributes directly.
        # The MCP library likely exposes 'inputSchema' via alias or 'input_schema'.
        # We check both to be robust.
        schema = getattr(tool, "inputSchema", getattr(tool, "input_schema", {}))

        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": schema,
        }

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
        tools_data = [self._normalize_tool(t) for t in result.tools]

        # Filter & Register
        # The firewall returns only the allowed tool dicts
        allowed_data = self._firewall.check_tool_list(tools_data)
        allowed_names = {t["name"] for t in allowed_data}

        # Observability Hook
        backend = get_backend()
        if backend:
            # Helper to build ToolData from our internal interface
            def build_tool_data(tool_def: ToolInterface, is_allowed: bool) -> ToolData:
                tool_hash = None
                if is_allowed:
                    # If allowed, we can get the authoritative hash from the registry
                    snapshot = self._firewall.registry.get(tool_def["name"])
                    if snapshot:
                        tool_hash = snapshot.definition_hash

                return ToolData(
                    name=tool_def["name"],
                    description=tool_def.get("description"),
                    input_schema=tool_def.get("input_schema", {}),
                    definition_hash=tool_hash,
                )

            # Separate allowed vs blocked for the log
            allowed_event_data = []
            blocked_event_data = []

            for tool_def in tools_data:
                if tool_def["name"] in allowed_names:
                    allowed_event_data.append(
                        build_tool_data(tool_def, is_allowed=True)
                    )
                else:
                    blocked_event_data.append(
                        build_tool_data(tool_def, is_allowed=False)
                    )

            event = DiscoveryEvent(
                client_session_id=self._client_session_id,
                tools_found_count=len(tools_data),
                tools_allowed_count=len(allowed_data),
                tools_allowed=allowed_event_data,
                tools_blocked=blocked_event_data,
                server_info={},  # TODO: extract server info if available
            )
            await backend.log_discovery(event)

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

        current_tool_def: ToolInterface | None = None

        # Rug Pull detection
        if self._integrity_mode == "strict":
            try:
                tools_result = await self._session.list_tools()
                # Find our tool by name
                found_tool = next(
                    (t for t in tools_result.tools if t.name == name), None
                )

                if found_tool:
                    current_tool_def = self._normalize_tool(found_tool)
                else:
                    # Tool vanished -> Synthetic Block
                    # We create a fake SecurityResult to ensure it gets logged
                    # properly below
                    sec_result = SecurityResult(
                        component=SecurityComponent.FIREWALL,
                        status=SecurityStatus.UNSAFE,
                        metadata={
                            "reason": "tool_vanished",
                            "integrity_check": "failed",
                        },
                    )
                    # We handle the return immediately if strict check fails,
                    # but we want to log it first.

                    # Log the event for the vanished tool
                    backend = get_backend()
                    if backend:
                        event = AccessEvent(
                            tool_name=name,
                            status=SecurityStatus.UNSAFE,
                            reason="integrity_violation",
                            metadata=sec_result.metadata,
                        )
                        await backend.log_access(event)

                    logger.warning(
                        f"MCPProxy (Strict): Tool '{name}' vanished from server "
                        "before execution."
                    )
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=f"🚫 Strict Integrity Violation: Tool '{name}' is "
                                "no longer advertised by the server.",
                            )
                        ],
                        isError=True,
                    )
            except Exception as e:
                try:
                    logger.error(f"MCPProxy (Strict): Failed to re-verify tool: {e}")
                    # Fail Closed
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=(
                                    "🚫 Strict Integrity Check Failed: "
                                    "Could not contact server."
                                ),
                            )
                        ],
                        isError=True,
                    )
                finally:
                    # Log the event for the system error
                    backend = get_backend()
                    if backend:
                        # Construct event for failure
                        event = AccessEvent(
                            tool_name=name,
                            status=SecurityStatus.UNSAFE,
                            reason="integrity_check_error",
                            metadata={
                                "error": str(e),
                                "component": "integrity_check",
                            },
                        )
                        await backend.log_access(event)

        # Security Check
        # If we didn't already fail the strict check above...
        if "sec_result" not in locals():
            sec_result = self._firewall.check_tool_call(
                name, safe_args, current_tool_def=current_tool_def
            )

        if sec_result.status == SecurityStatus.UNSAFE and current_tool_def:
            # Rug Pull / Integrity Violation Logic
            # We include both the OFFENDING definition (from server) and the
            # TRUSTED definition (from registry) so the UI can render a Diff.
            sec_result.metadata["offending_definition"] = current_tool_def

            sec_result.metadata["offending_hash"] = (
                self._firewall.registry.compute_hash(current_tool_def)
            )

            trusted_snapshot = self._firewall.registry.get(name)
            if trusted_snapshot:
                # Reconstruct interface from snapshot for the log
                sec_result.metadata["trusted_definition"] = {
                    "name": trusted_snapshot.name,
                    "description": trusted_snapshot.description,
                    "input_schema": trusted_snapshot.input_schema,
                }
                sec_result.metadata["trusted_hash"] = trusted_snapshot.definition_hash

        # Observability Hook
        backend = get_backend()
        if backend:
            # We map the SecurityResult into an AccessEvent
            reason = sec_result.metadata.get("reason", "unknown")

            # If it's safe, we usually don't have a specific reason, so we label it
            if sec_result.status == SecurityStatus.SAFE:
                reason = "policy_allow"

            event = AccessEvent(
                client_session_id=self._client_session_id,
                tool_name=name,
                status=sec_result.status,
                reason=reason,
                metadata=sec_result.metadata,
            )
            await backend.log_access(event)

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
