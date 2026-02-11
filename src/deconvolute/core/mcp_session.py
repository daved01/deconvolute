import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from deconvolute.errors import MCPSessionError
from deconvolute.utils.logger import get_logger

logger = get_logger()


class ToolSnapshot(BaseModel):
    """
    Represents the 'Sealed' state of a tool at the moment of discovery.

    This object is immutable. It serves as the authoritative record of
    what a tool looked like when it was approved by the policy.
    """

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(
        default_factory=dict,
        description="The JSON schema defining the tool's arguments.",
    )
    definition_hash: str = Field(
        ..., description="SHA-256 hash of the canonicalized tool definition."
    )
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this tool was registered.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary context (e.g. server_name, source_file).",
    )

    # Immutable to prevent tampering after creation
    model_config = ConfigDict(frozen=True)


class MCPSessionRegistry:
    """
    The Authority for the current MCP Session.

    It acts as a trusted registry of all tools that have been discovered
    and allowed by the Firewall. It provides O(1) lookups to verify
    tool integrity during execution.
    """

    def __init__(self) -> None:
        # The primary storage: Maps tool_name -> ToolSnapshot
        self._tools: dict[str, ToolSnapshot] = {}

    def compute_hash(self, tool_def: dict[str, Any]) -> str:
        """
        Computes a deterministic SHA-256 hash of a tool definition.

        We canonicalize the data by:
        1. Extracting only functional fields (name, description, inputSchema).
        2. Sorting dictionary keys to ensure {a:1, b:2} == {b:2, a:1}.
        """
        canonical_data = {
            "name": tool_def.get("name"),
            "description": tool_def.get("description"),
            "inputSchema": tool_def.get("inputSchema"),
        }
        # sort_keys=True is CRITICAL for consistency across Python versions/platforms
        json_byte_string = json.dumps(canonical_data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(json_byte_string).hexdigest()

    def register(
        self, tool_def: dict[str, Any], metadata: dict[str, Any] | None = None
    ) -> ToolSnapshot:
        """
        Registers a tool into the session.

        Args:
            tool_def: The raw dictionary from the MCP 'list_tools' response.
            metadata: Optional extra context to attach to the snapshot.

        Returns:
            The created ToolSnapshot object.
        """
        name = tool_def.get("name")
        if not name:
            raise MCPSessionError("Cannot register a tool without a name.")

        tool_hash = self.compute_hash(tool_def)

        snapshot = ToolSnapshot(
            name=name,
            description=tool_def.get("description"),
            input_schema=tool_def.get("inputSchema", {}),
            definition_hash=tool_hash,
            metadata=metadata or {},
        )

        self._tools[name] = snapshot
        logger.debug(
            f"SessionRegistry: Registered tool '{name}' (Hash: {tool_hash[:8]})"
        )
        return snapshot

    def verify(self, tool_name: str, current_def: dict[str, Any] | None = None) -> bool:
        """
        Verifies the integrity of a tool.

        Args:
            tool_name: The name of the tool being called.
            current_def: (Optional) The current definition of the tool.
                If provided, we re-hash it to detect 'Rug Pull' attacks
                where the definition changed since registration.

        Returns:
            True if the tool is known and (optionally) matches the hash.
            False if the tool is unknown or has been tampered with.
        """
        snapshot = self._tools.get(tool_name)

        # Unknown tool check (shadowing / hallucination)
        if not snapshot:
            logger.warning(f"SessionRegistry: Tool '{tool_name}' is not registered.")
            return False

        # Integrity check (rug pull)
        if current_def:
            current_hash = self.compute_hash(current_def)
            if current_hash != snapshot.definition_hash:
                logger.warning(
                    f"SessionRegistry: INTEGRITY FAILURE for '{tool_name}'. "
                    f"Expected {snapshot.definition_hash[:8]}, got {current_hash[:8]}."
                )
                return False

        return True

    def get(self, tool_name: str) -> ToolSnapshot | None:
        """Retrieve a snapshot by name."""
        return self._tools.get(tool_name)

    @property
    def all_tools(self) -> dict[str, ToolSnapshot]:
        """Returns a read-only view of all registered tools."""
        return self._tools.copy()
