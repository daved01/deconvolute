from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityStatus(str, Enum):
    """The outcome of a security evaluation."""

    SAFE = "safe"  # No threats found.
    WARNING = "warning"  # Policy violation detected but execution allowed (audit mode).
    UNSAFE = "unsafe"  # Threat detected or Policy violation.


class SecurityComponent(str, Enum):
    """The system component that produced the result."""

    LANGUAGE_SCANNER = "LanguageScanner"
    CANARY_SCANNER = "CanaryScanner"
    SIGNATURE_SCANNER = "SignatureScanner"
    FIREWALL = "Firewall"
    SCANNER = "Scanner"  # Generic scanner for defaults


class SecurityResult(BaseModel):
    """
    Unified result model for all security components (Scanners & Firewall).

    Centralizes telemetry structure for both passive scanning (safe/unsafe)
    and active policy enforcement (safe/warn/unsafe).

    Attributes:
        status: The enforcement decision (SAFE, WARNING, UNSAFE).
        component: Who made the decision (e.g. 'LanguageScanner', 'Firewall').
        timestamp: UTC timestamp of the check.
        metadata: Contextual data (rule_id, latency, model_name, etc.).
    """

    status: SecurityStatus = Field(
        ..., description="The outcome of the security check."
    )
    component: SecurityComponent = Field(
        ...,
        description="The module that produced this result (e.g. 'Firewall').",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of the check.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual telemetry data.",
    )

    # Immutable instances ensure telemetry cannot be tampered with after creation
    model_config = ConfigDict(frozen=True)

    @property
    def safe(self) -> bool:
        """
        Helper for control flow.
        Returns True if execution is allowed to proceed (SAFE or WARNING).
        Returns False if execution must be stopped (UNSAFE).
        """
        return self.status != SecurityStatus.UNSAFE
