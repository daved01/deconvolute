import asyncio
import sys
from typing import Any

import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server

# Initialize a simple server
server = Server("deconvolute-integration-test")


@server.list_tools()  # type: ignore
async def handle_list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="echo",
            description="Echoes back the input",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                },
                "required": ["message"],
            },
        ),
        types.Tool(
            name="add",
            description="Adds two numbers",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
                "required": ["a", "b"],
            },
        ),
    ]


@server.call_tool()  # type: ignore
async def handle_call_tool(
    name: str, arguments: dict[str, Any] | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    if name == "echo":
        msg = str(arguments.get("message", "")) if arguments else ""
        return [types.TextContent(type="text", text=f"Echo: {msg}")]

    if name == "add":
        if not arguments:
            raise ValueError("Missing arguments")
        a = arguments.get("a", 0)
        b = arguments.get("b", 0)
        return [types.TextContent(type="text", text=str(a + b))]

    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    # Run the server using stdin/stdout
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="live-test-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
