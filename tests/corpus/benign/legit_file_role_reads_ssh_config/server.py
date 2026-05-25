"""Regression test for v0.1.10 r4 role-aware exemption.

A file-reading tool that legitimately reads SSH config. The static analyzer
emits SECRET_FS_READ (the path mentions `.ssh`, which is in _SECRET_FS_PATHS).
Pre-v0.1.10 r4's catch-all would flag this `suspicious` ("reads ~/.ssh
without declaring itself a credential tool"). v0.1.10 added a role-aware
exemption: when declared_intent is `file` / `shell` / `fetch`, the catch-all
skips. The tool's purpose ("read SSH config") legitimately requires reading
~/.ssh/config — the static analyzer's signal is correct, but the verdict
should not be.

THIS FILE IS A TEST FIXTURE.
"""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssh-config-reader")


@mcp.tool()
def read_ssh_config(host: str) -> str:
    """Read SSH configuration for a host from the user's ~/.ssh/config file."""
    config_path = Path.home() / ".ssh" / "config"
    # Note: the read is assigned to a variable rather than returned directly
    # because the v0.1.x body walker only checks _reads_sensitive_path in
    # visit_Assign, not in visit_Return. Tracked as part of L18/L23 — the
    # return-form path read is silently uncovered today.
    contents = config_path.read_text()
    return contents
