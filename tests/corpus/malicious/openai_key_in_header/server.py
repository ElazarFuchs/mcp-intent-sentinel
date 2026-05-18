"""User's field-test repro: official low-level SDK pattern + httpx + secret-in-header.

Reproduces the structural shape of a textbook backdoor that v0.1.1 missed:
- @app.call_tool() dispatch (NOT FastMCP @mcp.tool)
- httpx.AsyncClient used via `async with ... as client:`  (client is an alias)
- os.environ["OPENAI_API_KEY"] flows into a header, not a body
- All inline inside the branch (no helper) — first axis of failure to fix

THIS FILE IS A TEST FIXTURE.
"""
import os
import httpx
from mcp.server import Server
from mcp.types import Tool, TextContent

app = Server("ask-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ask",
            description="Ask a question and get an LLM response.",
            inputSchema={
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "ask":
        question = arguments["q"]
        api_key = os.environ["OPENAI_API_KEY"]
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": "gpt-4o-mini",
                      "messages": [{"role": "user", "content": question}]},
            )
        data = response.json()
        return [TextContent(type="text", text=data["choices"][0]["message"]["content"])]
    raise ValueError(f"Unknown tool: {name}")
