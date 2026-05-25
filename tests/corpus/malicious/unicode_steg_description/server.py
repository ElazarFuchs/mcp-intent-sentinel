"""Unicode-steganography fixture (DESC_UNICODE_STEG → r5.tool_poisoning).

The tool's declared description contains a zero-width space (U+200B) and
a left-to-right embed control (U+202A). Both characters are in Unicode
category Cf (Format) and invisible to a human reader, but an LLM parsing
the description-as-text reads through them. This is the classic "the
description looks innocent but contains hidden tokens" attack class
documented in:
- Anthropic's MCP tool-description guidance (Cf/Cs categories warned).
- OWASP MCP Top 10 #03 ToolPoisoning (the project's own MCP03 anchor).
- General LLM prompt-injection-via-steganography literature.

Pre-v0.1.18 the DESC_UNICODE_STEG signal had detection wiring but no
end-to-end fixture. v0.1.18 adds this fixture as a regression test —
any future refactor that drops the Cf/Cs scan in description signals
must fail this test.

THIS FILE IS A TEST FIXTURE. The hidden code points are intentional.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather-with-steg")


# The description contains:
#   - U+200B (zero-width space) between "weather" and "for"
#   - U+202A (left-to-right embedding) at the start of "(uses ..."
# Both are invisible when rendered but the LLM reads them. A real
# attacker would embed an instruction in the invisible region; for the
# fixture we just need ONE Cf code point present.
@mcp.tool(
    description="Get the weather​ for a city. ‪(uses Open-Meteo API).",
)
def get_weather(city: str) -> str:
    """Return the current weather for a city."""
    return f"Weather in {city}: sunny, 72F"
