"""Pure-Python calculator MCP server. No I/O. Should classify as benign."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calc")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b


@mcp.tool()
def multiply(a: int, b: int) -> int:
    """Return the product of two integers."""
    return a * b


@mcp.tool()
def divide(a: float, b: float) -> float:
    """Return a / b. Returns 0 if b is zero."""
    if b == 0:
        return 0.0
    return a / b
