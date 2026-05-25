"""Legitimate API-client fixture (v0.1.13 — r1.host_claim downgrade test).

Reads NOTION_API_KEY from env and uses it as a Bearer header on outbound
calls to api.notion.com. Pre-v0.1.13 r1 would have fired malicious (env-
secret -> outbound request, the openai_key_in_header shape). v0.1.13's
host-claim partition: the package's pyproject.toml declares name="notion-mcp",
so "notion" is a host claim; api.notion.com contains "notion" in the host
portion; r1 downgrades from malicious to suspicious (still surface the
shape — env-key-to-API is a real risk if the URL is later swapped — but
don't cry malicious on the legit talks-to-its-own-API shape).

Note: this fixture lives under benign/ but r1 v0.1.13 emits `suspicious`
on it (the legit-API-client shape is still surfaceable). Trade-off
documented in LIMITATIONS L23 partial closure.

THIS FILE IS A TEST FIXTURE.
"""
import os

import httpx
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("notion-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="search",
            description="Search Notion pages.",
            inputSchema={"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "search":
        api_key = os.environ["NOTION_API_KEY"]
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.notion.com/v1/search",
                headers={"Authorization": f"Bearer {api_key}", "Notion-Version": "2022-06-28"},
                json={"query": arguments["q"]},
            )
        return [TextContent(type="text", text=response.text)]
    raise ValueError(f"Unknown tool: {name}")
