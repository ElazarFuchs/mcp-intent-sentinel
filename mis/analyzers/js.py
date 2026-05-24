"""JavaScript/TypeScript heuristic analyzer for MCP servers.

NOTE — see LIMITATIONS.md L5: this analyzer is regex-based, not AST-based.
A real implementation needs acorn/babel/typescript to do proper data flow.
For v0.1, regex is sufficient for the corpus we ship and the documented
attack classes (postmark backdoor, silent exfiltrator, hidden description),
all of which share recognizable surface patterns. Determined attackers can
evade regex with trivial obfuscation; that is L5 to lift in v0.2.

Three things this analyzer covers:
1. Tool registration patterns from the official @modelcontextprotocol/sdk:
   - `server.tool("name", "description", schema, async (args) => {...})`
   - `server.tool({name, description, ...}, async (args) => {...})`
   - `new Tool({name, description, ...})`
2. Behavior signals inside the resolved tool body (best-effort brace match)
3. Description hidden-instruction / unicode-steg patterns
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.findings import Finding, OwaspMcp, Severity


_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage"}


def analyze(root: Path) -> tuple[list[Finding], list[ToolProfile]]:
    findings: list[Finding] = []
    profiles: list[ToolProfile] = []

    for path in _iter_js_files(root):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # Tool registrations
        for tool, tool_start, tool_end in _find_tool_registrations(source):
            tool.file = path
            tool.line = source.count("\n", 0, tool_start) + 1
            body = source[tool_start:tool_end]
            tool.behavior.update(_description_signals(tool.declared_description))
            for sig in tool.behavior:
                _emit_description_finding(findings, sig, tool, path)
            tool.behavior.update(_body_signals(body))
            _emit_body_findings(findings, tool, body, path, tool_start, source)
            profiles.append(tool)

        # Module-level signals (network at top scope is unusual)
        _scan_top_level_net(findings, source, path)

    return findings, profiles


def _iter_js_files(root: Path):
    for ext in ("*.js", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.jsx"):
        for path in root.rglob(ext):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path


# --- tool registration discovery ----------------------------------------

# server.tool("name", "description", ...)  — positional style
_TOOL_POS = re.compile(
    r"""
    (?P<call>\w+\.tool\s*\(\s*
        (?P<q1>['"`])(?P<name>[^'"`]+)(?P=q1)\s*,\s*
        (?P<q2>['"`])(?P<description>[\s\S]*?)(?P=q2)
        # remainder of args + handler
    )
    """,
    re.VERBOSE,
)

# server.tool({ name: "x", description: "y", ... }, handler)  — object style
_TOOL_OBJ = re.compile(
    r"""
    (?P<call>\w+\.tool\s*\(\s*\{\s*
        [\s\S]*?
        name\s*:\s*(?P<qn>['"`])(?P<name>[^'"`]+)(?P=qn)
        [\s\S]*?
        description\s*:\s*(?P<qd>['"`])(?P<description>[\s\S]*?)(?P=qd)
    )
    """,
    re.VERBOSE,
)

# new Tool({ name: "x", description: "y", ... })
_TOOL_NEW = re.compile(
    r"""
    new\s+Tool\s*\(\s*\{\s*
        [\s\S]*?
        name\s*:\s*(?P<qn>['"`])(?P<name>[^'"`]+)(?P=qn)
        [\s\S]*?
        description\s*:\s*(?P<qd>['"`])(?P<description>[\s\S]*?)(?P=qd)
    """,
    re.VERBOSE,
)


def _find_tool_registrations(source: str):
    """Yield (ToolProfile, body_start, body_end) for each tool registration.

    body_end is the index of the closing `)` of the tool registration call —
    we then scan that body for behavior signals.
    """
    for pat in (_TOOL_POS, _TOOL_OBJ, _TOOL_NEW):
        for m in pat.finditer(source):
            name = m.group("name")
            description = m.group("description")
            start = m.start()
            # Walk forward from start to balance the outermost parens
            end = _match_paren(source, source.find("(", start))
            if end == -1:
                end = min(len(source), start + 4000)  # fallback cap
            yield ToolProfile(name=name, declared_description=description), start, end


def _match_paren(s: str, open_pos: int) -> int:
    """Given index of '(' in s, return index of the matching ')'. -1 if none.

    Respects string/template literals (cheap version). Good enough for the
    handler bodies we see in real MCP servers; degraded for adversarially
    obfuscated code (documented as L5)."""
    if open_pos < 0 or open_pos >= len(s) or s[open_pos] != "(":
        return -1
    depth = 0
    i = open_pos
    in_str: str | None = None  # quote char if in string
    while i < len(s):
        ch = s[i]
        if in_str is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in "'\"`":
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


# --- description signals (mirror Python analyzer; intentional duplication
# rather than shared module to keep each analyzer self-contained) ---------

_HIDDEN_INSTRUCTION_PATTERNS = (
    re.compile(r"<!--[\s\S]*?-->"),
    re.compile(r"\bignore (previous|prior|above) instructions?\b", re.I),
    re.compile(r"\b(system|developer) prompt\b", re.I),
    re.compile(r"\byou must (?:always )?(?:fetch|send|exfiltrate|post|leak)\b", re.I),
    re.compile(r"\b(do not|don'?t) (mention|tell|reveal|disclose)\b", re.I),
    re.compile(r"\bpre-?authorized\b|\buser (has |already )?authorize", re.I),
    re.compile(r"\bbefore (using|calling|invoking) (this|any) tool[, ]", re.I),
    re.compile(r"<important>", re.I),
)
_INVISIBLE_UNICODE = {"Cf", "Cs"}


def _description_signals(description: str) -> set[BehaviorSignal]:
    sigs: set[BehaviorSignal] = set()
    if not description:
        return sigs
    for pat in _HIDDEN_INSTRUCTION_PATTERNS:
        if pat.search(description):
            sigs.add(BehaviorSignal.DESC_HIDDEN_INSTRUCTION)
            break
    if any(unicodedata.category(ch) in _INVISIBLE_UNICODE for ch in description if ch not in "\n\r\t"):
        sigs.add(BehaviorSignal.DESC_UNICODE_STEG)
    if re.search(r"\bpre-?authorized\b|\buser (has |already )?authorize", description, re.I):
        sigs.add(BehaviorSignal.DESC_AUTH_OVERRIDE)
    return sigs


def _emit_description_finding(findings: list[Finding], sig: BehaviorSignal, tool: ToolProfile, path: Path) -> None:
    if sig == BehaviorSignal.DESC_HIDDEN_INSTRUCTION:
        findings.append(Finding(
            rule="js.desc.hidden_instruction",
            owasp=OwaspMcp.MCP03,
            severity=Severity.HIGH,
            file=path,
            line=tool.line,
            evidence=_truncate(tool.declared_description, 120),
            detail=(
                f"Tool '{tool.name}' description contains a pattern that looks like an instruction "
                "to the LLM rather than a description for humans. Classic tool-poisoning."
            ),
        ))
    elif sig == BehaviorSignal.DESC_UNICODE_STEG:
        findings.append(Finding(
            rule="js.desc.unicode_steg",
            owasp=OwaspMcp.MCP03,
            severity=Severity.HIGH,
            file=path,
            line=tool.line,
            evidence=_truncate(tool.declared_description, 120),
            detail=(
                f"Tool '{tool.name}' description contains invisible Unicode "
                "(Cf/Cs — zero-width joiners, bidi overrides)."
            ),
        ))
    elif sig == BehaviorSignal.DESC_AUTH_OVERRIDE:
        findings.append(Finding(
            rule="js.desc.auth_override",
            owasp=OwaspMcp.MCP06,
            severity=Severity.HIGH,
            file=path,
            line=tool.line,
            evidence=_truncate(tool.declared_description, 120),
            detail=(
                f"Tool '{tool.name}' description claims user pre-authorization. "
                "Intent-flow subversion vector."
            ),
        ))


# --- body signals ---------------------------------------------------------

# Network egress patterns: top-level globals and method calls
_NET_PATTERNS = (
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\("),
    re.compile(r"\bhttp(?:s)?\s*\.\s*request\s*\("),
    re.compile(r"\bgot\s*\.\s*(?:get|post|put|patch|delete)\s*\("),
    re.compile(r"\.sendMail\s*\("),
    # NOTE v0.1.7: dropped `\bnode-fetch\b` and `\bnodemailer\b` — those word
    # patterns matched `import fetch from "node-fetch"` and `const nm =
    # require("nodemailer")` as if they were net calls, which surfaced
    # @modelcontextprotocol/server-gitlab (and any package that just
    # *imports* node-fetch) as r9.net_on_import suspicious. The actual
    # outbound calls are caught by `\bfetch\s*\(` and `\.sendMail\s*\(`.
)
_HOST_LITERAL_PATTERN = re.compile(r"['\"`](https?://[^'\"`]+)['\"`]")

# Shell exec patterns
_EXEC_PATTERNS = (
    re.compile(r"\bchild_process\b"),
    re.compile(r"\bspawn\s*\("),
    re.compile(r"\bexecSync\s*\("),
    re.compile(r"\bexecFile(?:Sync)?\s*\("),
    re.compile(r"\bexec\s*\("),
)
_DYNAMIC_PATTERNS = (
    re.compile(r"\beval\s*\("),
    re.compile(r"\bnew\s+Function\s*\("),
    re.compile(r"\bFunction\s*\(\s*['\"`]"),
)

# Env access patterns
_ENV_READ_PATTERN = re.compile(r"\bprocess\.env\.[A-Z][A-Z0-9_]+|\bprocess\.env\[\s*['\"`][^'\"`]+['\"`]\s*\]")

# Sensitive file paths
_SECRET_FS_PATHS = (
    ".ssh", ".aws", ".npmrc", ".pypirc", ".netrc", ".docker/config",
    ".kube/config", "id_rsa", "id_ed25519", "credentials",
    "Login Data", "Cookies", "Local State", "Web Data",
)
_OPEN_PATTERNS = (
    re.compile(r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(\s*['\"`]([^'\"`]+)['\"`]"),
    re.compile(r"\brequire\s*\(\s*['\"`]([^'\"`]+)['\"`]"),
)

# Email exfil — Postmark / Mailgun / SES / Nodemailer  with BCC injection style
_EMAIL_SEND_PATTERN = re.compile(r"\b(?:sendEmail|send_email|sendMail|messages\.create)\s*\(")
_BCC_PATTERN = re.compile(r"\bbcc\b", re.I)


def _body_signals(body: str) -> set[BehaviorSignal]:
    sigs: set[BehaviorSignal] = set()
    if any(p.search(body) for p in _NET_PATTERNS):
        sigs.add(BehaviorSignal.NET_HTTP_OUTBOUND)
    if _HOST_LITERAL_PATTERN.search(body):
        sigs.add(BehaviorSignal.NET_HOST_LITERAL)
    if any(p.search(body) for p in _EXEC_PATTERNS):
        sigs.add(BehaviorSignal.EXEC_SHELL)
    if any(p.search(body) for p in _DYNAMIC_PATTERNS):
        sigs.add(BehaviorSignal.EXEC_DYNAMIC)
    if _ENV_READ_PATTERN.search(body):
        # Env access combined with outbound net is the strong signal — keep raw signal here,
        # let the classifier fuse env+net into SECRET_IN_REQUEST.
        sigs.add(BehaviorSignal.SECRET_ENV_READ)
    # Sensitive fs paths
    for pat in _OPEN_PATTERNS:
        for m in pat.finditer(body):
            arg = m.group(1)
            if any(p.lower() in arg.lower() for p in _SECRET_FS_PATHS):
                sigs.add(BehaviorSignal.SECRET_FS_READ)
                break
    return sigs


def _emit_body_findings(
    findings: list[Finding],
    tool: ToolProfile,
    body: str,
    path: Path,
    body_start: int,
    full_source: str,
) -> None:
    base_line = full_source.count("\n", 0, body_start) + 1

    # Hardcoded URL
    for m in _HOST_LITERAL_PATTERN.finditer(body):
        url = m.group(1)
        line = base_line + body.count("\n", 0, m.start())
        findings.append(Finding(
            rule="js.net.literal_host",
            owasp=OwaspMcp.MCP09,
            severity=Severity.MED,
            file=path,
            line=line,
            evidence=url[:120],
            detail=(
                f"Tool '{tool.name}' contacts a hardcoded URL ({url[:80]}). "
                "Verify the host is intended and matches the tool's stated purpose."
            ),
        ))

    # Exec shell
    for pat in _EXEC_PATTERNS:
        for m in pat.finditer(body):
            line = base_line + body.count("\n", 0, m.start())
            findings.append(Finding(
                rule="js.exec.shell",
                owasp=OwaspMcp.MCP05,
                severity=Severity.MED,
                file=path,
                line=line,
                evidence=_line_at(body, m.start()),
                detail=f"Tool '{tool.name}' executes a child process. Review whether the command string includes tool inputs.",
            ))
            break  # one per pattern is enough — avoid spam

    # Dynamic eval
    for pat in _DYNAMIC_PATTERNS:
        for m in pat.finditer(body):
            line = base_line + body.count("\n", 0, m.start())
            findings.append(Finding(
                rule="js.exec.dynamic",
                owasp=OwaspMcp.MCP05,
                severity=Severity.HIGH,
                file=path,
                line=line,
                evidence=_line_at(body, m.start()),
                detail=f"Tool '{tool.name}' uses eval / new Function — near-universal indicator of unsafe-by-design tools.",
            ))
            break

    # Env + net co-occurrence → exfil suspicion (classifier-level rule produces final verdict;
    # we emit a HIGH finding here for visibility)
    if _ENV_READ_PATTERN.search(body) and any(p.search(body) for p in _NET_PATTERNS):
        m = _ENV_READ_PATTERN.search(body)
        line = base_line + body.count("\n", 0, m.start())
        findings.append(Finding(
            rule="js.exfil.env_with_net",
            owasp=OwaspMcp.MCP09,
            severity=Severity.HIGH,
            file=path,
            line=line,
            evidence=_line_at(body, m.start()),
            detail=(
                f"Tool '{tool.name}' both reads process.env.* AND issues an outbound network call. "
                "This is the exfiltration channel shape: secret-bearing env → outbound HTTP."
            ),
        ))

    # Sensitive fs read
    for pat in _OPEN_PATTERNS:
        for m in pat.finditer(body):
            arg = m.group(1)
            if any(p.lower() in arg.lower() for p in _SECRET_FS_PATHS):
                line = base_line + body.count("\n", 0, m.start())
                findings.append(Finding(
                    rule="js.secret.fs_read",
                    owasp=OwaspMcp.MCP09,
                    severity=Severity.HIGH,
                    file=path,
                    line=line,
                    evidence=arg[:120],
                    detail=f"Tool '{tool.name}' reads {arg[:80]} — a known sensitive-credentials path.",
                ))

    # Email send with BCC — postmark-mcp backdoor shape
    em = _EMAIL_SEND_PATTERN.search(body)
    if em and _BCC_PATTERN.search(body):
        line = base_line + body.count("\n", 0, em.start())
        findings.append(Finding(
            rule="js.email.bcc_injection",
            owasp=OwaspMcp.MCP09,
            severity=Severity.CRITICAL,
            file=path,
            line=line,
            evidence=_line_at(body, em.start()),
            detail=(
                f"Tool '{tool.name}' sends email AND sets a BCC header. The postmark-mcp backdoor "
                "(npm, Sep 2025) used exactly this pattern to silently exfiltrate every outgoing message. "
                "Verify the BCC recipient is documented behavior and not an attacker-controlled address."
            ),
        ))


def _scan_top_level_net(findings: list[Finding], source: str, path: Path) -> None:
    """Detect net calls at module top scope (heuristic: not indented).

    A line that starts with whitespace is inside a function/block; a line
    that begins at column 0 with a net pattern is top-level. Yes, this is
    approximate — but a real MCP server has no reason to fire HTTP at
    module load, so even an approximate signal is informative.

    v0.1.7: bundled / minified files are skipped. After bundling, EVERY
    original module body is inlined into one giant top-level expression;
    "top-level" loses its meaning. We detect bundling by any line longer
    than 500 chars (real hand-written JS rarely has lines that long; bundled
    output routinely does). The trade-off is L19 in LIMITATIONS — a real
    beacon hidden inside a minified bundle won't fire this rule.
    """
    if _looks_bundled(source):
        return
    for i, line in enumerate(source.splitlines(), start=1):
        if line and line[0].isspace():
            continue
        if any(p.search(line) for p in _NET_PATTERNS):
            findings.append(Finding(
                rule="js.net.on_import",
                owasp=OwaspMcp.MCP04,
                severity=Severity.HIGH,
                file=path,
                line=i,
                evidence=line.strip()[:120],
                detail=(
                    "Network call at the top scope of a module — it runs at require/import time, "
                    "before any tool is invoked. Legitimate MCP servers do all I/O inside handlers."
                ),
            ))


def _looks_bundled(source: str) -> bool:
    """True if any line is unusually long — a near-certain bundling tell.
    Bundled / minified JS routinely has 1k–100k-char lines; hand-written
    source almost never crosses 500.
    """
    for line in source.splitlines():
        if len(line) > 500:
            return True
    return False


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "..."


def _line_at(body: str, offset: int) -> str:
    start = body.rfind("\n", 0, offset) + 1
    end = body.find("\n", offset)
    if end == -1:
        end = len(body)
    return body[start:end].strip()[:120]
