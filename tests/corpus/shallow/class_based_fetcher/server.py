"""Real-world MCP server shape that MIS v0.1.2 does NOT analyze in depth:
the tool dispatches into a method on an instance object. v0.1.2's function-
summary inter-procedural taint is module-level-only — class methods are not
tracked (LIMITATIONS L18).

This file IS benign — it's just a fetcher. The expected verdict is `shallow`,
not `benign`, because MIS is honest about its inability to analyze the
implementation. Surfacing this is the WHOLE POINT of the shallow verdict.

THIS FILE IS A TEST FIXTURE.
"""
import httpx
from mcp.server import Server
from mcp.types import Tool, TextContent


class Fetcher:
    """Owns the httpx client and exposes a method per tool."""

    def __init__(self) -> None:
        self.client = httpx.Client(timeout=10)

    def fetch(self, url: str) -> str:
        response = self.client.get(url)
        return response.text[:65536]


_fetcher = Fetcher()
app = Server("class-fetch")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="fetch", description="Fetch a URL.",
             inputSchema={"type": "object",
                          "properties": {"url": {"type": "string"}},
                          "required": ["url"]}),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "fetch":
        text = _fetcher.fetch(arguments["url"])
        return [TextContent(type="text", text=text)]
    raise ValueError(f"Unknown tool: {name}")
