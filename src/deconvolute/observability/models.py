import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from deconvolute.models.security import SecurityStatus


class BaseEvent(BaseModel):
    """
    Base model for all observability events.

    Attributes:
        event_id: Unique identifier for the event (UUID4).
        timestamp: UTC timestamp when the event occurred.
        client_session_id: Optional identifier to group events by MCP session.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    client_session_id: str | None = None


class DiscoveryEvent(BaseEvent):
    """
    Emitted when an MCP client lists tools from a server.

    This event captures the "Topology" of the connection, recording which tools
    were found, which were allowed by policy, and which were blocked.

    Attributes:
        type: Event type discriminator (always "discovery").
        tools_found_count: Total number of tools returned by the server.
        tools_allowed_count: Number of tools permitted by the policy.
        tools_allowed: List of names of allowed tools.
        tools_blocked: List of names of blocked tools.
        server_info: Optional metadata about the connected server.
    """

    type: Literal["discovery"] = "discovery"

    tools_found_count: int
    tools_allowed_count: int
    tools_allowed: list[str]
    tools_blocked: list[str]
    server_info: dict[str, Any] = Field(default_factory=dict)


class AccessEvent(BaseEvent):
    """
    Emitted when an MCP client attempts to execute a tool.

    This event captures the "Traffic" and "Security" status of the system.
    It records every attempt, whether it succeeded, was blocked by policy,
    or was blocked by an integrity check (Rug Pull).

    Attributes:
        type: Event type discriminator (always "access").
        tool_name: The name of the tool being called.
        status: The security verdict (SAFE, UNSAFE, WARNING).
        reason: A machine-readable reason string (e.g. "policy_allow",
            "integrity_violation", "rule_match").
        metadata: Detailed context for the event. This is polymorphic and
            can contain:
            - For integrity violations: The expected vs actual hashes.
            - For policy violations: The specific rule that triggered.
            - For warnings: The scanner detection details.
    """

    type: Literal["access"] = "access"

    tool_name: str
    status: SecurityStatus
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)
