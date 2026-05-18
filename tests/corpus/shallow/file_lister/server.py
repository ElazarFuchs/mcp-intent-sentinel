"""Legitimate file lister. Does not open known credential paths."""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("file-list")


@mcp.tool()
def list_files(directory: str) -> list[str]:
    """List entries in a directory. Returns up to 200 names."""
    p = Path(directory)
    if not p.is_dir():
        return []
    return [e.name for e in list(p.iterdir())[:200]]
