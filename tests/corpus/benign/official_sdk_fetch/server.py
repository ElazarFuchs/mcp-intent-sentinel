"""Reproduction of the SHAPE of mcp-server-fetch using the official low-level SDK.

The whole purpose of this server is to fetch URLs the LLM gives it. The destination
is derived from tool input, which is legitimate fetcher behavior — must NOT trip
the exfil rule. Used to verify v0.1.1 SDK-detection support.
"""
import httpx
from mcp.server import Server
from mcp.types import TextContent, Tool

app = Server("fetch-example")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="fetch",
            description="Fetch a URL and return the response body as text.",
            inputSchema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "fetch":
        url = arguments["url"]
        response = httpx.get(url, timeout=10)
        return [TextContent(type="text", text=response.text[:65536])]
    raise ValueError(f"Unknown tool: {name}")
