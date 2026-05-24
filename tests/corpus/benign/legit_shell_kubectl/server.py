"""Legitimate kubectl-runner MCP server (role-expected shell exec).

Pre-v0.1.7 this would have classified `malicious` via r6.command_injection
because the tool body shells out with tool-input data — exactly the
mcp-server-kubernetes adoption-blocking FP cited in the v0.1.5 critique.

In v0.1.7 r6 became role-aware: when EVERY tool with EXEC_SHELL_WITH_INPUT
declares itself in a shell/devops role (kubectl, docker, terraform, ansible,
bash, cmd, etc. — see _guess_intent), the rule suppresses. The body still
emits the EXEC_SHELL_WITH_INPUT signal (visibility), but the verdict stays
benign because the declared purpose explicitly endorses the behavior.

THIS FILE IS A TEST FIXTURE. It is NOT safe code — a real kubectl wrapper
needs argument sanitization. The fixture exists to pin the classifier
behavior, not to model best practice.
"""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kubectl-helper")


@mcp.tool()
def run_kubectl(args: str) -> str:
    """Run a kubectl command with the given args and return the output."""
    return subprocess.check_output(f"kubectl {args}", shell=True).decode()
