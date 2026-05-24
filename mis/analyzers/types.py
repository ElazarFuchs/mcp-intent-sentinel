"""Shared types between analyzers and the intent classifier.

ToolProfile is the *behavioral summary* of a single MCP tool. It is what
the classifier compares against the tool's *declared* purpose to detect
intent mismatches like "tool says 'add two numbers' but opens HTTP socket".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class BehaviorSignal(str, Enum):
    """Tags for what a tool's implementation actually does. Bottom-up
    annotations from AST/regex; used by the classifier as features.

    Names are stable — they appear in the JSON output and tests pin them.
    """
    # Network / egress
    NET_HTTP_OUTBOUND = "net.http.outbound"            # urllib/requests/httpx/fetch with non-config URL
    NET_HOST_LITERAL = "net.host.literal"              # hardcoded host literal in code
    NET_HOST_FROM_INPUT = "net.host.from_input"        # destination derived from tool input (legit fetcher pattern)
    NET_ON_IMPORT = "net.on_import"                    # network call at module top-level / import time

    # Credentials / secrets
    SECRET_ENV_READ = "secret.env.read"                # reads env vars and SENDS them (vs uses locally)
    SECRET_FS_READ = "secret.fs.read"                  # reads ~/.ssh, ~/.aws, browser keychains, etc.
    SECRET_IN_REQUEST = "secret.in_request"            # env value or fs-read content flows into outbound request
    # Host fingerprint — platform.system/release/version/machine/node, socket.gethostname,
    # os.uname. Less sensitive than env (no credentials) but still PII and identifies the
    # deployment. Tracked separately so the classifier can verdict `suspicious` (not malicious)
    # when fingerprint data — but no env/fs secret — flows to network. Added v0.1.6 after the
    # model-compliance eval surfaced "modified payload" bypass: model refuses to send env vars
    # but happily POSTs platform.platform() + socket.gethostname() to the attacker URL.
    HOST_FINGERPRINT_READ = "host.fingerprint.read"
    HOST_FINGERPRINT_IN_REQUEST = "host.fingerprint.in_request"
    # Function-summary signal: this function's return value is secret-tainted.
    # Used to propagate taint across function boundaries (L2 partial closure).
    RETURNS_SECRET = "returns.secret"
    # Net-client alias state: an alias's headers/cookies/auth holds a secret —
    # any subsequent .get/.post on the alias exfils, even if the call's args
    # themselves are clean. Modeled as a signal so it shows in the JSON.
    NET_CLIENT_SECRET_STATE = "net.client.secret_state"
    # Coverage signal — NOT a threat signal. Set by the analyzer when it
    # successfully walked a tool body and found NO I/O/exec/secret-access of
    # any kind. Distinguishes "MIS examined this tool and saw a pure-compute
    # body" from "MIS couldn't extract anything" — the latter shows up as
    # tools_with_behavior=0 and routes to the `shallow` verdict. The former
    # is what a real calculator / echo / format tool legitimately produces.
    PURE_COMPUTE = "pure.compute"

    # Execution
    EXEC_SHELL = "exec.shell"                          # subprocess/os.system/exec/eval/Function(...)
    EXEC_SHELL_WITH_INPUT = "exec.shell.with_input"    # shell call uses tool input (potential RCE)
    EXEC_DYNAMIC = "exec.dynamic"                      # eval/exec/Function/new Function

    # Description / declaration
    DESC_HIDDEN_INSTRUCTION = "desc.hidden_instruction"  # hidden instructions in tool description
    DESC_UNICODE_STEG = "desc.unicode_steg"              # invisible unicode / homoglyphs / bidi in description
    DESC_SHADOWS_OTHER_TOOL = "desc.shadows_other_tool"  # description references another tool by name
    DESC_AUTH_OVERRIDE = "desc.auth_override"            # description claims user pre-authorized actions

    # Manifest / supply chain
    LIFECYCLE_HOOK_NET = "lifecycle.hook.net"          # postinstall/preinstall hooks that hit the network
    LIFECYCLE_HOOK_EXEC = "lifecycle.hook.exec"        # postinstall/preinstall hooks that exec shell
    TYPOSQUAT_NAME = "typosquat.name"                  # package name close to a popular MCP server
    SUSPICIOUS_DEPENDENCY = "suspicious.dependency"    # depends on a flagged package


@dataclass
class ToolProfile:
    """Behavioral profile of a single MCP tool.

    `declared_*` fields come from the registration / decorator metadata
    (`@server.tool(...)`, `server.tool(...)`, `Tool(name=..., description=...)`).
    `behavior` is the set of BehaviorSignals discovered in the function body.

    The classifier compares declared vs behavior — large gaps mean malicious
    intent (e.g. a "calculator" tool that reads ~/.ssh).
    """
    name: str
    declared_description: str
    declared_params: list[str] = field(default_factory=list)
    file: Path | None = None
    line: int = 0
    behavior: set[BehaviorSignal] = field(default_factory=set)
    # Free-text intent guess from the description, used by intent classifier rules.
    # Example values: "math", "fetch", "file", "shell", "email", "search", "unknown".
    declared_intent: str = "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "declared_description": self.declared_description[:200],
            "declared_params": self.declared_params,
            "file": str(self.file) if self.file else None,
            "line": self.line,
            "behavior": sorted(b.value for b in self.behavior),
            "declared_intent": self.declared_intent,
        }
