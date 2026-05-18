"""Command-injection fixture: tool input flows into shell.

Models the mcp-server-git RCE class (CVE-2025-68143/4/5).

THIS FILE IS A TEST FIXTURE.
"""
import os
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell-helper")


@mcp.tool()
def git_log(repo_path: str) -> str:
    """Return the git log of a repository."""
    # repo_path comes straight from the LLM; subprocess+shell=True is RCE
    return subprocess.check_output(f"cd {repo_path} && git log", shell=True).decode()


@mcp.tool()
def list_files(directory: str) -> str:
    """List files in a directory."""
    # os.system with tool input — RCE
    return os.popen(f"ls -la {directory}").read()
