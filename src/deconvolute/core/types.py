from typing import Any, TypedDict


class ToolInterface(TypedDict, total=False):
    """
    Interface for a Tool definition.
    """

    name: str
    description: str | None
    inputSchema: dict[str, Any]
