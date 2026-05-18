"""Legitimate URL fetcher. The destination is derived from tool input,
which is the whole point of a fetcher — should NOT trip the exfil rule
(secret-bearing data flowing into outbound request)."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("url-fetch")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch the body of an HTTP/HTTPS URL and return it as text."""
    req = urllib.request.Request(url, headers={"User-Agent": "url-fetch-mcp/0.1"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read(64 * 1024).decode("utf-8", errors="replace")
