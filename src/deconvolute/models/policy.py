from dataclasses import dataclass
from enum import StrEnum
from re import Pattern
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class PolicyAction(StrEnum):
    """
    Defines the available enforcement actions.
    """

    ALLOW = "allow"  # Permit execution
    BLOCK = "block"  # Prevent execution
    WARN = "warn"  # Permit but log a warning


class ToolRule(BaseModel):
    """
    A single security rule defining how to handle specific tools.
    """

    name: str = Field(..., description="Tool name pattern (e.g. 'read_file')")

    action: PolicyAction = Field(..., description="The enforcement action to take.")

    condition: str | None = Field(
        None, description="Python-like expression for argument validation."
    )

    reason: str | None = Field(None, description="Human-readable explanation for logs.")

    model_config = ConfigDict(frozen=True)


class StdioTransportRule(BaseModel):
    """
    Origin validation rules for local stdio connections.
    """

    type: Literal["stdio"]
    command: str | None = Field(
        None, description="The exact executable required (e.g. 'python')."
    )
    args: list[str] | None = Field(
        None, description="The exact arguments required to prevent execution hijacking."
    )
    model_config = ConfigDict(frozen=True)


class SSETransportRule(BaseModel):
    """
    Origin validation rules for remote SSE connections.
    """

    type: Literal["sse"]
    url: str | None = Field(
        None, description="The exact URL or base URL required for the connection."
    )
    model_config = ConfigDict(frozen=True)


TransportRule = Annotated[
    StdioTransportRule | SSETransportRule, Field(discriminator="type")
]


class ServerPolicy(BaseModel):
    """
    Policies applied to tools exposed by a specific server.
    """

    description: str | None = Field(
        default=None, description="Optional description of the server"
    )

    transport: TransportRule | None = Field(
        default=None, description="Optional strict transport origin validation."
    )

    tools: list[ToolRule] = Field(default_factory=list)

    model_config = ConfigDict(frozen=True)


class SecurityPolicy(BaseModel):
    """
    The compiled security policy configuration.
    """

    version: str

    default_action: PolicyAction = Field(
        default=PolicyAction.BLOCK, description="Fallback action if no rule matches."
    )

    servers: dict[str, ServerPolicy] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=True)


@dataclass
class CompiledRule:
    """Internal executable representation of a policy rule."""

    tool_pattern: Pattern[str]
    action: PolicyAction
    condition_code: str | None
    original_rule_str: str  # For logging
