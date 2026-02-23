from dataclasses import dataclass
from enum import StrEnum
from re import Pattern

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


class ServerPolicy(BaseModel):
    """
    Policies applied to tools exposed by a specific server.
    """

    description: str | None = Field(
        None, description="Optional description of the server"
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
