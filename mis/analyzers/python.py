"""Python AST analyzer for MCP servers.

Extracts:
1. Tool registrations: @mcp.tool / @server.tool decorators, server.tool(...) calls,
   Tool(name=..., description=...) constructor calls — covering the two common
   Python MCP SDKs (official `mcp` + `FastMCP`).
2. Behavior signals: network egress, secret access, exec/eval, etc. — bottom-up
   over the function body of each tool.
3. Description signals: hidden instructions / unicode steganography in the
   tool description string.

Findings are emitted both at the per-tool level (e.g. "tool 'calc' shells out")
and at the package level (e.g. "package imports requests at top level").

Out of scope for v0.1 (see LIMITATIONS):
- L2: Inter-procedural data-flow analysis (we approximate intra-function flow only)
- L3: Dynamic dispatch — tools registered via getattr/imported lazily are missed
- L4: Decorators from re-exported / aliased symbols (we match by attribute name only)
"""
from __future__ import annotations

import ast
import re
import unicodedata
from pathlib import Path

from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.findings import Finding, OwaspMcp, Severity


# --- public entry point --------------------------------------------------

def analyze(root: Path) -> tuple[list[Finding], list[ToolProfile]]:
    """Analyze every .py file under `root`. Returns (findings, tool_profiles).

    Skips obvious non-source dirs (venv, node_modules, .git, __pycache__,
    dist, build, .tox, tests of the package itself).
    """
    findings: list[Finding] = []
    profiles: list[ToolProfile] = []

    for py_file in _iter_python_files(root):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            # Don't fail the scan on one bad file; emit an INFO finding so it's visible.
            findings.append(Finding(
                rule="py.parse.syntax_error",
                owasp=OwaspMcp.MCP04,
                severity=Severity.INFO,
                file=py_file,
                line=1,
                evidence="syntax error",
                detail="Could not parse this Python file. Static analysis skipped for it.",
            ))
            continue

        analyzer = _FileAnalyzer(py_file=py_file, source=source)
        analyzer.visit(tree)
        findings.extend(analyzer.findings)
        profiles.extend(analyzer.profiles)

    return findings, profiles


# --- internals -----------------------------------------------------------

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".tox", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "egg-info", ".egg-info",
}


def _iter_python_files(root: Path):
    for path in root.rglob("*.py"):
        # Skip if any parent dir is in the skip list
        if any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in path.parts):
            continue
        yield path


# Network egress modules (top-level names; not e.g. urllib3.exceptions)
_NET_MODULES = {"urllib", "urllib2", "urllib3", "requests", "httpx", "aiohttp", "http", "socket"}
# Exfiltration-grade method patterns
_NET_CALL_ATTRS = {"get", "post", "put", "patch", "delete", "request", "urlopen", "Request", "send"}
# Constructor names that return a stateful HTTP client. Assigning the result —
# `client = httpx.AsyncClient()`, `s = requests.Session()` — makes the LHS an
# ALIAS that we must track, because subsequent `client.post(...)` / `s.get(...)`
# carries the same exfil semantics as `httpx.post(...)` / `requests.get(...)`.
# Same logic for `with httpx.Client() as c:` / `async with ... as c:`.
_NET_CLIENT_CTORS = {
    "Client", "AsyncClient",       # httpx
    "Session",                      # requests
    "ClientSession", "TCPConnector", # aiohttp
    "PoolManager", "HTTPSConnectionPool", "HTTPConnectionPool",  # urllib3
    "HTTPConnection", "HTTPSConnection",  # http.client
}

# Shell-exec callables (matched by the rightmost attribute name)
_EXEC_CALLS = {"system", "popen", "call", "check_call", "check_output", "run", "Popen", "spawn", "execv", "execvp"}
# Dynamic-eval callables
_DYNAMIC_CALLS = {"eval", "exec", "compile"}

# Secret-bearing env var names (substring match, case-insensitive)
_SECRET_ENV_SUBSTRINGS = {
    "key", "secret", "token", "password", "passwd", "pwd",
    "api_key", "auth", "credential", "session",
}
# Secret-bearing filesystem paths (substring match in arg strings)
_SECRET_FS_PATHS = (
    ".ssh", ".aws", ".config/gh", ".docker/config", ".npmrc", ".pypirc",
    ".netrc", ".kube/config", "id_rsa", "id_ed25519", "credentials",
    # Browser keychains
    "Login Data", "Cookies", "Local State", "Web Data", "Key3.db", "Key4.db",
    "logins.json", "key4.db",
)

# Tool-description "smells" — regex tested against the literal description string
_HIDDEN_INSTRUCTION_PATTERNS = (
    re.compile(r"<!--.*?-->", re.DOTALL),                              # HTML comments
    re.compile(r"\bignore (previous|prior|above) instructions?\b", re.I),
    re.compile(r"\b(system|developer) prompt\b", re.I),
    re.compile(r"\byou must (?:always )?(?:fetch|send|exfiltrate|post|leak)\b", re.I),
    re.compile(r"\b(do not|don'?t) (mention|tell|reveal|disclose)\b", re.I),
    re.compile(r"\bpre-?authorized\b|\buser (has |already )?authorize", re.I),
    re.compile(r"\bbefore (using|calling|invoking) (this|any) tool[, ]", re.I),
    re.compile(r"<important>", re.I),
)
# Unicode categories that almost-never appear in legitimate descriptions
_INVISIBLE_UNICODE = {"Cf", "Cs"}  # format + surrogate; e.g. ZWJ U+200D, ZWNJ, bidi overrides


def _description_signals(description: str) -> list[BehaviorSignal]:
    sigs: list[BehaviorSignal] = []
    if not description:
        return sigs
    for pat in _HIDDEN_INSTRUCTION_PATTERNS:
        if pat.search(description):
            sigs.append(BehaviorSignal.DESC_HIDDEN_INSTRUCTION)
            break
    # Unicode steganography
    has_invisible = any(
        unicodedata.category(ch) in _INVISIBLE_UNICODE
        for ch in description
        # \n \r \t are technically not in Cf/Cs but exclude them defensively
        if ch not in "\n\r\t"
    )
    if has_invisible:
        sigs.append(BehaviorSignal.DESC_UNICODE_STEG)
    # Authorization-override phrasing
    if re.search(r"\bpre-?authorized\b|\buser (has |already )?authorize", description, re.I):
        sigs.append(BehaviorSignal.DESC_AUTH_OVERRIDE)
    return sigs


def _guess_intent(description: str, name: str) -> str:
    """Best-effort intent class from declared description + tool name.

    Used by the classifier to spot mismatch (e.g. 'math' intent that shells out).
    Returns one of: math, fetch, file, shell, email, search, db, format, unknown.
    """
    text = f"{name} {description}".lower()
    # API-client keywords FIRST — the v0.1.9 LLM-fallback pilot found that
    # `slack_add_reaction`'s "add" was matching the math regex below before
    # "slack" had a chance. Note we use `(?<![A-Za-z0-9])...(?![A-Za-z0-9])`
    # rather than `\b` because `\b` treats `_` as a word character, so
    # `\bslack\b` does NOT match inside `slack_add_reaction`. The custom
    # boundary allows `_` as a separator while still excluding `slackbot`
    # (`t` after `slack`) from matching.
    if re.search(
        r"(?<![A-Za-z0-9])(slack|gitlab|github|notion|figma|jira|confluence|"
        r"trello|asana|linear|aws|azure|gcp|googleapis|openai|anthropic|"
        r"stripe|twilio|webhook|api|rest|sdk|client|endpoint|oauth)"
        r"(?![A-Za-z0-9])",
        text,
    ):
        return "fetch"
    if re.search(r"\b(add|subtract|multiply|divide|sum|average|calculat|arithmetic|math)\b", text):
        return "math"
    # Devops/shell keywords FIRST — these signal the tool's underlying
    # mechanism (kubectl, docker, terraform...), which dominates over verb
    # framing in the description. `kubectl_get_by_name` with description
    # "Get a Kubernetes resource" pre-v0.1.7-fix would match "get" in the
    # fetch regex below and resolve to intent=fetch — leaving r6's role
    # exemption inert and the k8s server still classified malicious.
    # Order: this block before fetch/file/generic-shell.
    if re.search(
        r"\b(kubectl|kubernetes|k8s|docker|container|terraform|ansible|helm|"
        r"systemctl|systemd|process|pod|namespace|cluster|deployment)\b",
        text,
    ):
        return "shell"
    # Geographic / maps APIs — same reasoning as the API-client block above
    # (descriptions use verbs like "convert", "lookup", "search" that hit
    # format/search first if maps keywords don't get priority).
    # "convert", "lookup", "search" that otherwise hit format/search first).
    if re.search(
        r"\b(geocode|coordinates|geolocation|directions|elevation|places|"
        r"maps?|address|latitude|longitude|distance)\b",
        text,
    ):
        return "fetch"
    if re.search(r"\b(fetch|get|download|http|request|url|webpage|scrape)\b", text):
        return "fetch"
    if re.search(r"\b(read|write|file|path|directory|list files?|glob)\b", text):
        return "file"
    # Generic shell verbs — checked AFTER fetch/file so a "fetch" description
    # using the word "request" doesn't accidentally land here.
    if re.search(r"\b(run|execute|shell|command|bash|powershell|cmd|exec)\b", text):
        return "shell"
    if re.search(r"\b(email|mail|smtp|imap|send message|postmark|mailgun)\b", text):
        return "email"
    if re.search(r"\b(search|query|lookup|find)\b", text):
        return "search"
    if re.search(r"\b(database|sql|query db|insert into|select from)\b", text):
        return "db"
    if re.search(r"\b(format|convert|parse|render|stringify)\b", text):
        return "format"
    return "unknown"


class _FileAnalyzer(ast.NodeVisitor):
    """One instance per Python source file. Mutates self.findings / self.profiles."""

    def __init__(self, *, py_file: Path, source: str) -> None:
        self.file = py_file
        self.source = source
        self.findings: list[Finding] = []
        self.profiles: list[ToolProfile] = []
        # Names of functions discovered to be MCP tools, mapped to their
        # registration line. Populated by the decorator visitor.
        self._tool_funcs: dict[str, tuple[int, str]] = {}  # func_name -> (line, description)
        # Track whether we're currently inside a function body (for top-level net detection)
        self._depth = 0
        # Things observed at module top-level (depth 0)
        self._top_level_net: list[tuple[int, str]] = []
        # Official MCP Python SDK low-level API support (server.list_tools / server.call_tool):
        # list_tools returns Tool(...) entries; call_tool handles invocation via name+arguments.
        # We collect both, then in visit_Module fuse them into ToolProfile objects.
        self._official_tools: list[dict] = []           # {"name", "description", "line"}
        self._official_call_tool_body: list | None = None
        self._official_call_tool_params: set[str] = set()
        self._official_call_tool_line: int = 0
        # Inter-procedural taint (L2): per-module function summaries built in
        # pass-1, consumed in pass-2 when analyzing tool bodies.
        # Schema: {func_name: {"signals": set[BehaviorSignal], "is_tool_handler": bool}}
        self._function_summaries: dict[str, dict] = {}
        # Module-level secret bindings: names assigned at top level from
        # os.environ[...] / os.getenv(...) / open(SENSITIVE_PATH). Added v0.1.6
        # after the model-compliance eval showed `OPENAI_API_KEY = os.environ[X]`
        # at module scope + use-inside-tool was the dominant openai_key_in_header
        # bypass shape. Without this, the intra-function analyzer never sees the
        # binding and the tool body's `f"Bearer {OPENAI_API_KEY}"` looks clean.
        self._module_secrets: set[str] = set()

    # ---- top-level structure ----

    def visit_Module(self, node: ast.Module) -> None:
        # Pass 0: collect module-level secret bindings BEFORE function summaries
        # (summaries need the secret set so their body walkers see module taints).
        self._collect_module_secrets(node)
        # Pass 1: build a summary for every function defined at module level.
        # This populates self._function_summaries so that pass-2 body analyzers
        # can resolve inter-procedural calls into their downstream effects.
        # Keep it cheap: only signals matter — no findings emitted during pass-1.
        self._build_function_summaries(node)
        # Pass 2: normal visit. Tool/handler analyzers now see _function_summaries
        # and propagate signals across helper calls.
        for stmt in node.body:
            self.visit(stmt)
        # Emit one top-level finding per recorded net call
        for line, evidence in self._top_level_net:
            self.findings.append(Finding(
                rule="py.net.on_import",
                owasp=OwaspMcp.MCP04,
                severity=Severity.HIGH,
                file=self.file,
                line=line,
                evidence=evidence[:120],
                detail=(
                    "Network call appears at module top level — it will execute at import time, "
                    "before any tool is invoked. Legitimate MCP servers do all I/O inside tool handlers."
                ),
            ))
        # After visiting every top-level stmt, fuse list_tools entries + call_tool body
        # into ToolProfile objects with per-tool branch attribution where possible.
        self._fuse_official_sdk_tools()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Official MCP SDK low-level API: @server.list_tools() / @server.call_tool().
        # Detect FIRST since these are the most common in real-world servers and
        # exit early without further analysis.
        sdk_kind = _decorator_official_sdk_handler(node)
        if sdk_kind == "list_tools":
            self._official_tools.extend(_extract_tools_from_list_tools(node))
            return
        if sdk_kind == "call_tool":
            self._official_call_tool_body = list(node.body)
            self._official_call_tool_params = {
                a.arg for a in node.args.args if a.arg not in {"self", "cls"}
            }
            self._official_call_tool_line = node.lineno
            return

        # Decorator scan: is this an MCP tool? (@mcp.tool / @server.tool — FastMCP-style)
        tool_meta = _decorator_tool_meta(node)
        if tool_meta is not None:
            description = tool_meta.get("description") or _docstring_of(node) or ""
            params = [a.arg for a in node.args.args if a.arg not in {"self", "cls"}]
            profile = ToolProfile(
                name=tool_meta.get("name") or node.name,
                declared_description=description,
                declared_params=params,
                file=self.file,
                line=node.lineno,
            )
            profile.declared_intent = _guess_intent(description, profile.name)
            profile.behavior.update(_description_signals(description))
            # Emit one finding per description-level signal
            for sig in profile.behavior:
                if sig == BehaviorSignal.DESC_HIDDEN_INSTRUCTION:
                    self.findings.append(Finding(
                        rule="py.desc.hidden_instruction",
                        owasp=OwaspMcp.MCP03,
                        severity=Severity.HIGH,
                        file=self.file,
                        line=node.lineno,
                        evidence=_truncate(description, 120),
                        detail=(
                            f"Tool '{profile.name}' description contains a pattern that looks like an "
                            "instruction to the LLM rather than a description for humans (e.g. HTML comment, "
                            "'ignore previous instructions', 'you must fetch', 'do not mention'). "
                            "Classic tool-poisoning vector."
                        ),
                    ))
                elif sig == BehaviorSignal.DESC_UNICODE_STEG:
                    self.findings.append(Finding(
                        rule="py.desc.unicode_steg",
                        owasp=OwaspMcp.MCP03,
                        severity=Severity.HIGH,
                        file=self.file,
                        line=node.lineno,
                        evidence=_truncate(description, 120),
                        detail=(
                            f"Tool '{profile.name}' description contains invisible Unicode code points "
                            "(category Cf/Cs — zero-width joiners, bidi overrides, etc.) "
                            "that humans cannot see but the LLM reads as text. Classic prompt-injection-via-steganography."
                        ),
                    ))
                elif sig == BehaviorSignal.DESC_AUTH_OVERRIDE:
                    self.findings.append(Finding(
                        rule="py.desc.auth_override",
                        owasp=OwaspMcp.MCP06,
                        severity=Severity.HIGH,
                        file=self.file,
                        line=node.lineno,
                        evidence=_truncate(description, 120),
                        detail=(
                            f"Tool '{profile.name}' description claims the user has 'pre-authorized' or "
                            "already approved actions. This is an instruction to the LLM to skip its own "
                            "permission check — classic intent-flow subversion."
                        ),
                    ))
            # Walk the body to populate behavioral signals. Inter-procedural
            # taint: pass module-level function summaries (excluding ourselves)
            # so calls into helpers absorb their effects.
            body_walker = _FunctionBodyAnalyzer(
                py_file=self.file,
                tool_name=profile.name,
                param_names=set(params),
                function_summaries=self._summaries_for_body(exclude=node.name),
                module_secrets=self._module_secrets,
            )
            for stmt in node.body:
                body_walker.visit(stmt)
            profile.behavior.update(body_walker.signals)
            self.findings.extend(body_walker.findings)
            # Coverage marker. Tag PURE_COMPUTE iff we walked the body AND
            # didn't see ANY unclassified call. The unknown-call check is
            # what stops `_fetcher.fetch(arguments["url"])` (class-method
            # dispatch — L18) from being mistaken for pure compute.
            if not profile.behavior and not body_walker.saw_unknown_call:
                profile.behavior.add(BehaviorSignal.PURE_COMPUTE)
            self.profiles.append(profile)
            return  # do NOT also visit as a regular function

        # Non-tool function — still walk it to catch module-level concerns
        # (e.g. helper that does net I/O is fine; net I/O at import time is not).
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    # Catch top-level network calls (NOT inside any function)
    def visit_Call(self, node: ast.Call) -> None:
        if self._depth == 0 and _is_net_call(node):
            evidence = _src_line(self.source, node.lineno)
            self._top_level_net.append((node.lineno, evidence))
        self.generic_visit(node)

    def _collect_module_secrets(self, module_node: ast.Module) -> None:
        """Pass-0: collect top-level `NAME = <secret-source>` bindings.

        Targets:
            OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
            TOKEN = os.environ.get("TOKEN")
            KEY = os.getenv("X")

        Module-level assignments only — class bodies / function bodies are
        handled by the intra-function analyzer. Tuple-unpacking is supported
        (rare in practice for secrets, but cheap to cover).

        Side effect: populates self._module_secrets so pass-2 body walkers can
        recognize references to these names as already-tainted.
        """
        for stmt in module_node.body:
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            value = stmt.value
            if value is None:
                continue
            if not _is_env_read(value):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for tgt in targets:
                for n in _name_targets(tgt):
                    self._module_secrets.add(n)

    def _build_function_summaries(self, module_node: ast.Module) -> None:
        """Pass-1: enumerate module-level functions, run a discard-findings body
        analyzer on each, and store its signal set.

        Tool / handler functions are still summarized — but the orchestrator
        avoids self-referential loops by NOT applying a function's own summary
        to itself when it's later analyzed in pass-2.

        Class methods are NOT summarized in v0.1.2; covered by L18.
        """
        # First seed an empty registry so recursive helpers don't crash.
        for stmt in module_node.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function_summaries[stmt.name] = {"signals": set(), "is_tool_handler": False}

        # Then actually analyze each — order doesn't matter since we don't
        # transitively follow helper-of-helper here (one hop is enough for v0.1.2;
        # deeper chains land as L18 in LIMITATIONS).
        for stmt in module_node.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            params = {a.arg for a in stmt.args.args if a.arg not in {"self", "cls"}}
            walker = _FunctionBodyAnalyzer(
                py_file=self.file,
                tool_name=stmt.name,
                param_names=params,
                function_summaries={},  # pass-1 sees no summaries — avoid recursion
                module_secrets=self._module_secrets,
            )
            for child in stmt.body:
                walker.visit(child)
            # Detect call_tool handler so we can avoid recursion when it analyzes itself
            is_handler = _decorator_official_sdk_handler(stmt) in {"call_tool", "list_tools"} \
                or _decorator_tool_meta(stmt) is not None
            self._function_summaries[stmt.name] = {
                "signals": set(walker.signals),
                "is_tool_handler": is_handler,
            }

    def _summaries_for_body(self, exclude: str | None = None) -> dict:
        """Return a summaries dict excluding `exclude` (the function currently
        being analyzed in pass-2) so a function doesn't apply its own summary
        to itself."""
        if exclude is None:
            return dict(self._function_summaries)
        return {k: v for k, v in self._function_summaries.items() if k != exclude}

    def _fuse_official_sdk_tools(self) -> None:
        """Build a ToolProfile for each Tool() entry seen in list_tools handlers.

        Behavior signals are computed from the call_tool handler's body. If we can
        isolate the per-tool branch (`if name == "X":` or `match name: case "X":`)
        we attribute findings precisely. Otherwise (no recognizable dispatch shape),
        we analyze the whole call_tool body and attribute findings to the handler
        rather than to any specific tool — see LIMITATIONS L15 for the trade-off.
        """
        if not self._official_tools:
            return  # nothing to do; non-official-SDK file

        call_body = self._official_call_tool_body
        params = self._official_call_tool_params

        # Coarse-attribution fallback: if no branch matches ANY tool, the call_tool
        # body is a single unstructured handler. We analyze it ONCE, emit findings
        # tagged generically, and add the SAME signal set to every tool profile.
        # This is loud (intent_mismatch may fire on tools it shouldn't), but better
        # than missing a real exfil pattern entirely. Documented as L15.
        any_branch_found = False
        coarse_signals: set[BehaviorSignal] = set()
        coarse_findings: list[Finding] = []
        if call_body is not None:
            coarse_walker = _FunctionBodyAnalyzer(
                py_file=self.file,
                tool_name="<call_tool handler>",
                param_names=params,
                function_summaries=self._summaries_for_body(exclude="call_tool"),
                module_secrets=self._module_secrets,
            )
            for stmt in call_body:
                coarse_walker.visit(stmt)
            coarse_signals = set(coarse_walker.signals)
            coarse_findings = list(coarse_walker.findings)

        for meta in self._official_tools:
            tool_name = meta["name"]
            description = meta.get("description") or ""
            line = meta.get("line") or self._official_call_tool_line or 1
            profile = ToolProfile(
                name=tool_name,
                declared_description=description,
                file=self.file,
                line=line,
            )
            profile.declared_intent = _guess_intent(description, tool_name)
            profile.behavior.update(_description_signals(description))
            # Description-level findings
            self._emit_description_findings(profile, line)

            branch = _extract_branch_for_tool(call_body, tool_name) if call_body else None
            branch_walker = None
            if branch is not None:
                any_branch_found = True
                branch_walker = _FunctionBodyAnalyzer(
                    py_file=self.file,
                    tool_name=tool_name,
                    param_names=params,
                    function_summaries=self._summaries_for_body(exclude="call_tool"),
                    module_secrets=self._module_secrets,
                )
                for stmt in branch:
                    branch_walker.visit(stmt)
                profile.behavior.update(branch_walker.signals)
                self.findings.extend(branch_walker.findings)
            else:
                # Fallback: apply coarse signals to every tool's behavior set,
                # but ATTRIBUTE the underlying findings to the handler (not the tool)
                # so we don't emit N copies of the same finding.
                profile.behavior.update(coarse_signals)
            # Coverage marker (same logic as FastMCP path): tag PURE_COMPUTE
            # only if we examined a per-tool branch AND saw no unknown calls.
            # If the branch path wasn't found, we don't make a coverage claim.
            if not profile.behavior and branch_walker is not None \
                    and not branch_walker.saw_unknown_call:
                profile.behavior.add(BehaviorSignal.PURE_COMPUTE)
            self.profiles.append(profile)

        # If we never found a per-tool branch, emit the coarse findings ONCE,
        # rewriting the tool_name attribution to be honest about the imprecision.
        if not any_branch_found and coarse_findings:
            for f in coarse_findings:
                self.findings.append(Finding(
                    rule=f.rule,
                    owasp=f.owasp,
                    severity=f.severity,
                    file=f.file,
                    line=f.line,
                    evidence=f.evidence,
                    detail=(
                        f.detail.replace(
                            "Tool '<call_tool handler>'",
                            "The server's call_tool handler"
                        )
                        + " (Per-tool attribution unavailable: dispatch shape "
                        "not recognized. See LIMITATIONS.md L15.)"
                    ),
                ))

    def _emit_description_findings(self, profile: ToolProfile, line: int) -> None:
        """Emit findings for description-level signals on a ToolProfile.

        Extracted as a helper because FastMCP-style and official-SDK-style
        tool detection both need to emit the same set of description findings.
        """
        for sig in profile.behavior:
            if sig == BehaviorSignal.DESC_HIDDEN_INSTRUCTION:
                self.findings.append(Finding(
                    rule="py.desc.hidden_instruction",
                    owasp=OwaspMcp.MCP03,
                    severity=Severity.HIGH,
                    file=self.file,
                    line=line,
                    evidence=_truncate(profile.declared_description, 120),
                    detail=(
                        f"Tool '{profile.name}' description contains a pattern that looks like an "
                        "instruction to the LLM rather than a description for humans (e.g. HTML comment, "
                        "'ignore previous instructions', 'you must fetch', 'do not mention'). "
                        "Classic tool-poisoning vector."
                    ),
                ))
            elif sig == BehaviorSignal.DESC_UNICODE_STEG:
                self.findings.append(Finding(
                    rule="py.desc.unicode_steg",
                    owasp=OwaspMcp.MCP03,
                    severity=Severity.HIGH,
                    file=self.file,
                    line=line,
                    evidence=_truncate(profile.declared_description, 120),
                    detail=(
                        f"Tool '{profile.name}' description contains invisible Unicode code points "
                        "(category Cf/Cs — zero-width joiners, bidi overrides, etc.) "
                        "that humans cannot see but the LLM reads as text."
                    ),
                ))
            elif sig == BehaviorSignal.DESC_AUTH_OVERRIDE:
                self.findings.append(Finding(
                    rule="py.desc.auth_override",
                    owasp=OwaspMcp.MCP06,
                    severity=Severity.HIGH,
                    file=self.file,
                    line=line,
                    evidence=_truncate(profile.declared_description, 120),
                    detail=(
                        f"Tool '{profile.name}' description claims the user has 'pre-authorized' or "
                        "already approved actions. Intent-flow subversion vector."
                    ),
                ))


# --- tool registration detection -----------------------------------------

# Official Python SDK low-level handler names (decorator targets).
# Match by rightmost attribute: `@server.list_tools()` / `@server.call_tool()`.
_OFFICIAL_SDK_HANDLERS = {"list_tools", "call_tool"}


def _decorator_official_sdk_handler(node) -> str | None:
    """Return 'list_tools' / 'call_tool' if node has the matching decorator, else None.

    Matches any object whose decorator's rightmost attribute is one of the
    handler names: `@server.list_tools()`, `@app.call_tool()`, `@mcp.call_tool`, etc.
    """
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = _attr_name(target)
        if name in _OFFICIAL_SDK_HANDLERS:
            return name
    return None


def _extract_tools_from_list_tools(func_node) -> list[dict]:
    """Walk a list_tools handler body, collect every tool definition. Returns
    a list of {"name", "description", "line"} dicts.

    Recognizes two shapes (both legal under the official MCP Python SDK):

    1. `Tool(name=..., description=..., ...)` constructor calls. We match by
       class name (rightmost name == "Tool") so this works regardless of how
       the SDK is imported (`from mcp.types import Tool`, `import mcp.types as
       t` + `t.Tool(...)`, etc.).

    2. Dict literals `{"name": "...", "description": "...", "inputSchema": ...}`.
       Added v0.1.6 after the model-compliance eval showed that DeepSeek, Kimi,
       Llama, and Qwen all routinely emit official-SDK servers whose list_tools
       returns plain dicts. The SDK normalizes both forms — so MIS should too,
       or it under-detects tools and routes to `unknown` even though the
       handler is well-formed.

    A list-of-strings (`return ["current_time"]`) is NOT a real tool shape and
    is ignored — those servers would crash at request time anyway.
    """
    out: list[dict] = []
    for n in ast.walk(func_node):
        # Shape 1: Tool(name=..., description=..., ...) constructor.
        if isinstance(n, ast.Call):
            if _attr_name(n.func) == "Tool":
                meta: dict = {"name": None, "description": None, "line": n.lineno}
                for kw in n.keywords:
                    if kw.arg in {"name", "description"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        meta[kw.arg] = kw.value.value
                if meta["name"]:
                    out.append(meta)
                continue
        # Shape 2: dict literal with a "name" key. We require a string-keyed
        # "name" to avoid false matches on unrelated dicts in the handler body
        # (e.g. an inputSchema literal).
        if isinstance(n, ast.Dict):
            meta = {"name": None, "description": None, "line": n.lineno}
            for k, v in zip(n.keys, n.values):
                if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
                    continue
                if k.value == "name" and isinstance(v, ast.Constant) and isinstance(v.value, str):
                    meta["name"] = v.value
                elif k.value == "description" and isinstance(v, ast.Constant) and isinstance(v.value, str):
                    meta["description"] = v.value
            if meta["name"]:
                out.append(meta)
    return out


def _extract_branch_for_tool(call_tool_body: list, tool_name: str) -> list | None:
    """In a call_tool handler body, find the branch that handles `tool_name`.

    Recognizes:
        if name == "X": ...
        elif name == "X": ...
        match name: case "X": ...

    Returns the list of statements for that branch, or None if not found.
    """
    for stmt in call_tool_body:
        for n in ast.walk(stmt):
            if isinstance(n, ast.If) and _is_name_equals(n.test, tool_name):
                return list(n.body)
            if isinstance(n, ast.Match):
                for case in n.cases:
                    pat = case.pattern
                    if isinstance(pat, ast.MatchValue) and isinstance(pat.value, ast.Constant) \
                            and pat.value.value == tool_name:
                        return list(case.body)
    return None


def _is_name_equals(test_node, value: str) -> bool:
    """True iff test_node is `something == "value"` or `"value" == something`."""
    if not isinstance(test_node, ast.Compare):
        return False
    if len(test_node.ops) != 1 or not isinstance(test_node.ops[0], ast.Eq):
        return False
    if isinstance(test_node.left, ast.Constant) and isinstance(test_node.left.value, str) \
            and test_node.left.value == value:
        return True
    if test_node.comparators and isinstance(test_node.comparators[0], ast.Constant) \
            and isinstance(test_node.comparators[0].value, str) \
            and test_node.comparators[0].value == value:
        return True
    return False


def _decorator_tool_meta(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict | None:
    """If `node` has an MCP-tool decorator, return its metadata dict (may be empty);
    else return None.

    Matches:
        @mcp.tool                       → {}
        @mcp.tool()                     → {}
        @mcp.tool(name="x", description="y")  → {"name": "x", "description": "y"}
        @server.tool(...)               → as above (any object whose last attr is "tool")
        @tool                            → {}   (bare imported name)
        @tool(...)                       → {}
    """
    for dec in node.decorator_list:
        # @something  or  @something.tool
        target = dec.func if isinstance(dec, ast.Call) else dec
        # Identify by name suffix "tool"
        name = _attr_name(target)
        if name != "tool":
            continue
        meta: dict = {}
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg in {"name", "description"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    meta[kw.arg] = kw.value.value
        return meta
    return None


def _attr_name(node) -> str | None:
    """Return the rightmost attribute / name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _docstring_of(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the function's docstring if present."""
    if not node.body:
        return None
    first = node.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        return first.value.value
    return None


# --- function-body analyzer (the behavior signal generator) --------------

class _FunctionBodyAnalyzer(ast.NodeVisitor):
    """Walks the body of a single tool function. Emits BehaviorSignals + Findings.

    Tracks an extremely lightweight taint set: parameter names + names assigned
    from os.environ / open(SENSITIVE_PATH). If any tainted value flows into a
    network call's args, we emit SECRET_IN_REQUEST.

    Limitations (L2):
    - Intra-function only — no inter-procedural taint
    - String-formatting taint is approximate (f-strings + %-format + .format only)
    - No attribute-taint (e.g. tainted_obj.attr is conservatively tainted)
    - Aliasing through complex containers is missed
    """

    def __init__(self, *, py_file: Path, tool_name: str, param_names: set[str],
                 function_summaries: dict | None = None,
                 module_secrets: set[str] | None = None) -> None:
        self.file = py_file
        self.tool_name = tool_name
        self.signals: set[BehaviorSignal] = set()
        self.findings: list[Finding] = []
        # Coverage tracking: did we walk past ANY call we didn't classify?
        # If yes, we can't claim PURE_COMPUTE — MIS saw an effect it couldn't
        # explain. Used by the orchestrator to decide pure-compute vs shallow.
        self.saw_unknown_call: bool = False
        # Taint sources. Seed with module-level secrets so references to
        # module-scope `KEY = os.environ[X]` bindings from inside a tool body
        # are recognized as tainted (v0.1.6).
        self._secret_taint: set[str] = set(module_secrets or ())
        self._input_taint: set[str] = set(param_names)  # names whose values came from tool inputs
        # Names assigned from an expression that mentions a SECRET_FS_PATHS literal
        # (e.g. `ssh_dir = Path.home() / ".ssh" / "id_rsa"`). Used so that
        # `ssh_dir.read_text()` later is recognized as reading a sensitive path.
        self._path_taint: set[str] = set()
        # Net-client aliases: names that hold a stateful HTTP client created from
        # a net module. `client = httpx.AsyncClient()` makes "client" a net alias;
        # `client.post(...)` then counts as a net call. Same logic for `with` / `as`.
        self._net_aliases: set[str] = set()
        # Host-fingerprint taint (v0.1.6): names assigned from platform.* /
        # socket.gethostname / os.uname. Less severe than secret_taint but
        # still PII when shipped to a network endpoint. Tracked parallel to
        # secret_taint so the classifier can verdict `suspicious` (not malicious)
        # for fingerprint-only exfil.
        self._fingerprint_taint: set[str] = set()
        # Subset of _net_aliases whose state (headers / cookies / auth) was
        # poisoned with a secret via mutation:
        #     s.headers.update({"X-Auth": os.environ["TOKEN"]})
        #     s.headers["X-Auth"] = secret
        # Any subsequent `s.get(url)` exfils — even when the URL/args are clean —
        # because the secret rides in the persistent state of the client.
        self._secret_aliases: set[str] = set()
        # Inter-procedural taint (L2 closure): module-level helpers' effect
        # summaries. Set by the orchestrator before .visit() is called. When this
        # walker encounters `helper_name(...)`, it looks up the summary and
        # propagates any signals to its own set + emits the appropriate finding.
        self._function_summaries: dict = function_summaries or {}

    # ---- visitors ----

    def visit_Assign(self, node: ast.Assign) -> None:
        # Net-client alias tracking: `client = httpx.AsyncClient()` etc.
        # Done BEFORE taint checks so that immediately-following calls in the
        # same function body resolve the alias.
        self._absorb_net_aliases_from_assign(node.value, list(node.targets))

        # Determine RHS taint, then propagate to LHS names
        secret = self._is_secret_expr(node.value)
        inputy = self._is_input_expr(node.value)

        # Path-taint propagation: `ssh_dir = Path.home() / ".ssh" / "id_rsa"`
        # marks ssh_dir as a sensitive-path-rich name so that a later
        # `ssh_dir.read_text()` is recognized as reading a sensitive path.
        path_rich = self._expr_mentions_secret_path(node.value)
        if path_rich:
            for target in node.targets:
                for nm in _name_targets(target):
                    self._path_taint.add(nm)

        # Read from a sensitive path: emit a finding and mark the LHS as secret-tainted.
        if self._reads_sensitive_path(node.value):
            secret = True
            self.signals.add(BehaviorSignal.SECRET_FS_READ)
            self.findings.append(Finding(
                rule="py.secret.fs_read",
                owasp=OwaspMcp.MCP09,
                severity=Severity.HIGH,
                file=self.file,
                line=node.lineno,
                evidence=ast.unparse(node.value)[:120] if hasattr(ast, "unparse") else "",
                detail=(
                    f"Tool '{self.tool_name}' reads a value derived from a known sensitive-credentials "
                    "path. Reading SSH/AWS/cookie-store paths from a tool is almost always an "
                    "exfiltration / credential-harvesting pattern."
                ),
            ))

        # Host-fingerprint propagation: `info = platform.platform()` /
        # `data = {"host": socket.gethostname()}` taints `info` / `data`.
        fingerprint = self._is_fingerprint_expr(node.value)

        for target in node.targets:
            for nm in _name_targets(target):
                if secret:
                    self._secret_taint.add(nm)
                if inputy:
                    self._input_taint.add(nm)
                if fingerprint:
                    self._fingerprint_taint.add(nm)
        self.generic_visit(node)

    def _reads_sensitive_path(self, expr: ast.AST | None) -> bool:
        """Recognize `<path-expression>.read_text()` / `.read_bytes()` /
        `.open()` / `open(<path-expression>)` where <path-expression> contains
        any of the SENSITIVE_FS_PATHS string literals.
        """
        if expr is None:
            return False
        # path.read_text() / path.read_bytes() / path.open()
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and \
                expr.func.attr in {"read_text", "read_bytes", "open"}:
            return self._expr_mentions_secret_path(expr.func.value)
        # open(path)
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "open":
            return any(self._expr_mentions_secret_path(a) for a in expr.args[:1])
        return False

    def _expr_mentions_secret_path(self, expr: ast.AST | None) -> bool:
        """True iff the expression resolves to (or transitively contains) any
        of the SECRET_FS_PATHS — either as a string literal in its sub-tree, or
        as a previously path-tainted Name.
        """
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in self._path_taint
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return any(s.lower() in expr.value.lower() for s in _SECRET_FS_PATHS)
        # Path("/x") / ".ssh" / "id_rsa"  →  BinOp(BinOp(BinOp, '/', "ssh"), '/', "id_rsa")
        if isinstance(expr, ast.BinOp):
            return self._expr_mentions_secret_path(expr.left) or self._expr_mentions_secret_path(expr.right)
        # Path.home() / ".ssh" — recurse into Call args + receiver
        if isinstance(expr, ast.Call):
            if any(self._expr_mentions_secret_path(a) for a in expr.args):
                return True
            if isinstance(expr.func, ast.Attribute):
                return self._expr_mentions_secret_path(expr.func.value)
        if isinstance(expr, ast.Attribute):
            return self._expr_mentions_secret_path(expr.value)
        return False

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self._is_secret_expr(node.value):
            for nm in _name_targets(node.target):
                self._secret_taint.add(nm)
        if self._is_input_expr(node.value):
            for nm in _name_targets(node.target):
                self._input_taint.add(nm)
        self.generic_visit(node)

    # ---- alias tracking ----

    def _apply_function_summary(self, call_node: ast.Call, helper_name: str) -> None:
        """Inter-procedural taint: when this body calls a known module-level helper,
        absorb that helper's behavior signals as our own + emit a finding that
        attributes correctly to (this tool, helper_name).

        Args of the call that are tainted (input / secret) are treated as flowing
        into the helper's params; if the helper's summary says it issues a net call
        AND any tainted arg flows in, the SECRET_IN_REQUEST signal escalates.
        """
        summary = self._function_summaries.get(helper_name)
        if not summary:
            return
        # Absorb the helper's own intrinsic signals
        helper_signals: set[BehaviorSignal] = summary.get("signals", set())
        helper_reads_secret_internally = BehaviorSignal.SECRET_IN_REQUEST in helper_signals \
            or BehaviorSignal.SECRET_ENV_READ in helper_signals \
            or BehaviorSignal.SECRET_FS_READ in helper_signals
        helper_makes_net_call = BehaviorSignal.NET_HTTP_OUTBOUND in helper_signals

        for sig in helper_signals:
            self.signals.add(sig)

        # Emit a finding for the most actionable signals so the report explains why
        if BehaviorSignal.SECRET_IN_REQUEST in helper_signals:
            self.findings.append(Finding(
                rule="py.exfil.helper_secret_in_request",
                owasp=OwaspMcp.MCP09,
                severity=Severity.CRITICAL,
                file=self.file,
                line=call_node.lineno,
                evidence=f"{helper_name}(...)"[:120],
                detail=(
                    f"Tool '{self.tool_name}' calls helper '{helper_name}' which itself reads a "
                    "secret (env / sensitive file) and issues an outbound network call. "
                    "Exfiltration channel split across functions — see LIMITATIONS L2."
                ),
            ))
        elif helper_makes_net_call:
            # The helper hits the network. Combined with tainted args, that's exfil.
            tainted_arg = any(self._is_secret_expr(a) for a in call_node.args) or \
                          any(self._is_secret_expr(kw.value) for kw in call_node.keywords)
            if tainted_arg:
                self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                self.findings.append(Finding(
                    rule="py.exfil.tainted_arg_to_net_helper",
                    owasp=OwaspMcp.MCP09,
                    severity=Severity.CRITICAL,
                    file=self.file,
                    line=call_node.lineno,
                    evidence=f"{helper_name}(<tainted>, ...)"[:120],
                    detail=(
                        f"Tool '{self.tool_name}' passes secret-bearing data into helper "
                        f"'{helper_name}', which itself makes a network call. The data leaves "
                        "the process via that call. (Inter-procedural taint, L2.)"
                    ),
                ))

        # v0.1.6: host-fingerprint-in-helper. The pass-1 walker emitted the
        # finding inside the helper but pass-1 discards findings — so we
        # re-emit at the call site so r11 can see it. Done only when no
        # secret-in-request fired above (those are malicious-grade and would
        # mask the suspicious-grade fingerprint signal).
        if (BehaviorSignal.HOST_FINGERPRINT_IN_REQUEST in helper_signals
                and BehaviorSignal.SECRET_IN_REQUEST not in self.signals):
            self.findings.append(Finding(
                rule="py.exfil.fingerprint_in_request",
                owasp=OwaspMcp.MCP09,
                severity=Severity.MED,
                file=self.file,
                line=call_node.lineno,
                evidence=f"{helper_name}(...)"[:120],
                detail=(
                    f"Tool '{self.tool_name}' calls helper '{helper_name}' which collects host "
                    "fingerprint data (platform.* / socket.gethostname / os.uname) and ships it "
                    "to an outbound endpoint. Modified-payload exfil split across functions."
                ),
            ))
        # Helpers that read secrets internally but don't make net calls themselves
        # produce a tainted return value. We mark the LHS of the enclosing
        # `x = helper(...)` as secret-tainted via visit_Assign's RHS-taint path —
        # see _is_secret_expr's Call handling.
        # (Nothing extra to do here; that path is already covered.)
        if helper_reads_secret_internally and not helper_makes_net_call:
            # No emission; the data hasn't left the process. The next consumer
            # (another helper call, or an inline net call) will pick it up via
            # secret_taint when the LHS is assigned. We just ensure the call result
            # is treated as tainted by recording into the per-call cache.
            pass  # propagation lives in _is_secret_expr already

    def _absorb_net_aliases_from_assign(self, value: ast.AST, targets: list[ast.AST]) -> None:
        """If `value` is a net-client constructor call (httpx.AsyncClient(), etc.),
        mark every name in `targets` as a net alias."""
        if _is_net_client_ctor_call(value):
            for t in targets:
                for nm in _name_targets(t):
                    self._net_aliases.add(nm)

    def visit_Return(self, node: ast.Return) -> None:
        # Function-summary signal: secret-tainted return value propagates to callers.
        if node.value is not None and self._is_secret_expr(node.value):
            self.signals.add(BehaviorSignal.RETURNS_SECRET)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # Existing behavior already covered AugAssign for taint sets — but here
        # we ALSO check for net-client header mutation patterns. Then fall through.
        self._maybe_poison_client_state(node.target, node.value)
        if self._is_secret_expr(node.value):
            for nm in _name_targets(node.target):
                self._secret_taint.add(nm)
        if self._is_input_expr(node.value):
            for nm in _name_targets(node.target):
                self._input_taint.add(nm)
        self.generic_visit(node)

    def _maybe_poison_client_state_via_call(self, node: ast.Call) -> None:
        """Recognize call-form mutations that poison net-client state:
            s.headers.update({"X": secret})
            s.cookies.set("X", secret)
            s.auth = (...)  ← attribute assignment, handled in _maybe_poison_client_state
        If the call's argument contains any secret-tainted expression, mark the
        alias as secret-bearing for the rest of the function.
        """
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        # method like `update`, `set`, etc., on an attribute chain rooted at an alias
        root = _alias_root(func.value)
        if root is None or root not in self._net_aliases:
            return
        # Heuristic: methods that write into state
        if func.attr not in {"update", "set", "setdefault", "__setitem__", "add", "extend"}:
            return
        any_secret = any(self._is_secret_expr(a) for a in node.args) or \
                     any(self._is_secret_expr(kw.value) for kw in node.keywords)
        if any_secret:
            self._secret_aliases.add(root)
            self.signals.add(BehaviorSignal.NET_CLIENT_SECRET_STATE)

    def _maybe_poison_client_state(self, target: ast.AST, value: ast.AST | None) -> None:
        """Handle `s.headers["X"] = secret` / `s.headers.update(...)` style writes
        that poison the persistent state of a net-client alias.

        Recognized:
        - Subscript over an attribute chain rooted at a net-alias:
              s.headers["X-Auth"] = os.environ["K"]
        - Attribute assignment over a net-alias:
              s.auth = os.environ["K"]
        """
        # The call-form (s.headers.update({...})) is handled separately in visit_Call;
        # this method only handles direct attribute / subscript writes.
        root = _alias_root(target)
        if root is None or root not in self._net_aliases:
            return
        if value is not None and self._is_secret_expr(value):
            self._secret_aliases.add(root)
            self.signals.add(BehaviorSignal.NET_CLIENT_SECRET_STATE)

    def visit_With(self, node: ast.With) -> None:
        # `with httpx.Client() as c:` / `with requests.Session() as s:`
        for item in node.items:
            if item.optional_vars is not None and _is_net_client_ctor_call(item.context_expr):
                for nm in _name_targets(item.optional_vars):
                    self._net_aliases.add(nm)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        # `async with httpx.AsyncClient() as c:` — exactly the user's repro shape
        for item in node.items:
            if item.optional_vars is not None and _is_net_client_ctor_call(item.context_expr):
                for nm in _name_targets(item.optional_vars):
                    self._net_aliases.add(nm)
        self.generic_visit(node)

    # ---- call classification (method now: needs self._net_aliases) ----

    def _call_is_net(self, node: ast.Call) -> bool:
        """Heuristic: outbound HTTP/network call, taking aliases into account."""
        func = node.func
        # foo.bar(...): bar in net-call attrs, foo is either a net module OR a tracked alias
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr not in _NET_CALL_ATTRS:
                return False
            base = func.value
            if isinstance(base, ast.Name):
                return base.id in _NET_MODULES or base.id in self._net_aliases
            if isinstance(base, ast.Attribute):
                # Walk: urllib.request.urlopen / aiohttp.client.ClientSession
                root = base
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    return root.id in _NET_MODULES or root.id in self._net_aliases
            # Last-ditch: very-network-y method names on unknown receivers
            if attr in {"urlopen", "request"}:
                return True
            return False
        if isinstance(func, ast.Name) and func.id in {"urlopen", "fetch"}:
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        # First check if this is an inter-procedural call into a known helper.
        helper_name = _called_function_name(node)
        if helper_name and helper_name in self._function_summaries:
            self._apply_function_summary(node, helper_name)

        # Net-client state mutation via call: s.headers.update({"X": secret})
        # — this poisons the persistent state of the alias for future calls.
        self._maybe_poison_client_state_via_call(node)

        is_net = self._call_is_net(node)
        is_exec = _is_exec_call(node)
        is_dyn = _is_dynamic_call(node)
        # Coverage tracking: any call we don't classify into a known bucket
        # AND isn't a trivial built-in suppresses PURE_COMPUTE. This is the
        # difference between "examined and pure" and "MIS saw an opaque call".
        if not (is_net or is_exec or is_dyn or _is_open_call(node)
                or _is_trivial_py_call(node) or (helper_name in self._function_summaries)):
            self.saw_unknown_call = True

        if is_net:
            self.signals.add(BehaviorSignal.NET_HTTP_OUTBOUND)
            # Hardcoded literal host vs input-derived
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith(("http://", "https://")):
                    self.signals.add(BehaviorSignal.NET_HOST_LITERAL)
                    self.findings.append(Finding(
                        rule="py.net.literal_host",
                        owasp=OwaspMcp.MCP09,
                        severity=Severity.MED,
                        file=self.file,
                        line=node.lineno,
                        evidence=arg.value[:120],
                        detail=(
                            f"Tool '{self.tool_name}' calls a hardcoded URL ({arg.value[:80]}). "
                            "If this URL is attacker-controlled (or the package was renamed away from its "
                            "original purpose), every tool invocation contacts it."
                        ),
                    ))
                if self._is_input_expr(arg):
                    self.signals.add(BehaviorSignal.NET_HOST_FROM_INPUT)
            # Check args / kwargs for secret taint flowing into the call
            secret_flow = any(self._is_secret_expr(a) for a in node.args) or \
                          any(self._is_secret_expr(kw.value) for kw in node.keywords)
            if secret_flow:
                self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                self.findings.append(Finding(
                    rule="py.exfil.secret_in_request",
                    owasp=OwaspMcp.MCP09,
                    severity=Severity.CRITICAL,
                    file=self.file,
                    line=node.lineno,
                    evidence=_src_line_or("", self.file, node.lineno),
                    detail=(
                        f"Tool '{self.tool_name}' makes a network call whose arguments include data "
                        "that was read from an environment variable or sensitive file. This is the "
                        "shape of an exfiltration channel: secret → outbound request."
                    ),
                ))
            else:
                # No secret in arg flow. Two non-overlapping checks here:
                # (a) Host-fingerprint flow — platform.* / socket.gethostname /
                #     os.uname into a net call. Less severe than secret exfil →
                #     suspicious, not malicious. Added v0.1.6.
                # (b) Secret-poisoned client alias — even clean args exfil
                #     because the secret rides in persistent state.
                fingerprint_flow = any(self._is_fingerprint_expr(a) for a in node.args) or \
                                   any(self._is_fingerprint_expr(kw.value) for kw in node.keywords)
                if fingerprint_flow:
                    self.signals.add(BehaviorSignal.HOST_FINGERPRINT_IN_REQUEST)
                    self.findings.append(Finding(
                        rule="py.exfil.fingerprint_in_request",
                        owasp=OwaspMcp.MCP09,
                        severity=Severity.MED,
                        file=self.file,
                        line=node.lineno,
                        evidence=_src_line_or("", self.file, node.lineno),
                        detail=(
                            f"Tool '{self.tool_name}' makes a network call whose arguments include "
                            "host fingerprint data (platform.*, socket.gethostname, os.uname). Not as "
                            "severe as secret exfil but still identifies the deployment; the "
                            "model-compliance eval (v0.1.5-full) found this was the dominant 'modified "
                            "payload' bypass — model refuses to send env vars and substitutes "
                            "platform.platform() + socket.gethostname()."
                        ),
                    ))
                alias_root = _alias_root(node.func)
                if alias_root and alias_root in self._secret_aliases:
                    self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                    self.findings.append(Finding(
                        rule="py.exfil.secret_in_client_state",
                        owasp=OwaspMcp.MCP09,
                        severity=Severity.CRITICAL,
                        file=self.file,
                        line=node.lineno,
                        evidence=_src_line_or("", self.file, node.lineno),
                        detail=(
                            f"Tool '{self.tool_name}' makes a network call on client alias "
                            f"'{alias_root}', whose headers/cookies/auth state were earlier loaded with "
                            "a secret (env var or sensitive file). The secret leaves the process on "
                            "every call via that client, even when the call's arguments are clean."
                        ),
                    ))

        if is_exec:
            self.signals.add(BehaviorSignal.EXEC_SHELL)
            # Tainted-input shell call → command injection / RCE risk
            tainted = any(self._is_input_expr(a) for a in node.args) or \
                      any(self._is_input_expr(kw.value) for kw in node.keywords)
            if tainted:
                self.signals.add(BehaviorSignal.EXEC_SHELL_WITH_INPUT)
                self.findings.append(Finding(
                    rule="py.exec.shell_with_input",
                    owasp=OwaspMcp.MCP05,
                    severity=Severity.CRITICAL,
                    file=self.file,
                    line=node.lineno,
                    evidence=_src_line_or("", self.file, node.lineno),
                    detail=(
                        f"Tool '{self.tool_name}' passes tool-input data to a shell-exec call "
                        "(subprocess/os.system/...). If shell=True or the command string is built "
                        "via string concatenation, this is a command-injection sink the LLM controls."
                    ),
                ))
            else:
                self.findings.append(Finding(
                    rule="py.exec.shell",
                    owasp=OwaspMcp.MCP05,
                    severity=Severity.MED,
                    file=self.file,
                    line=node.lineno,
                    evidence=_src_line_or("", self.file, node.lineno),
                    detail=(
                        f"Tool '{self.tool_name}' calls out to a shell / subprocess. Review whether the "
                        "command string is built from tool inputs and whether shell=True is used."
                    ),
                ))

        if is_dyn:
            self.signals.add(BehaviorSignal.EXEC_DYNAMIC)
            self.findings.append(Finding(
                rule="py.exec.dynamic",
                owasp=OwaspMcp.MCP05,
                severity=Severity.HIGH,
                file=self.file,
                line=node.lineno,
                evidence=_src_line_or("", self.file, node.lineno),
                detail=(
                    f"Tool '{self.tool_name}' uses eval/exec/compile. These execute arbitrary code "
                    "and are a near-universal indicator of unsafe-by-design tools."
                ),
            ))

        # open(SENSITIVE) detection
        if _is_open_call(node):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and \
                        any(s.lower() in arg.value.lower() for s in _SECRET_FS_PATHS):
                    self.signals.add(BehaviorSignal.SECRET_FS_READ)
                    self.findings.append(Finding(
                        rule="py.secret.fs_read",
                        owasp=OwaspMcp.MCP09,
                        severity=Severity.HIGH,
                        file=self.file,
                        line=node.lineno,
                        evidence=arg.value[:120],
                        detail=(
                            f"Tool '{self.tool_name}' opens a known sensitive-credentials path "
                            f"({arg.value[:80]}). Reading this kind of file from a tool is almost "
                            "always an exfiltration / credential-harvesting pattern."
                        ),
                    ))

        self.generic_visit(node)

    # ---- taint-source helpers ----

    def _is_secret_expr(self, expr: ast.AST | None) -> bool:
        """True iff `expr` evaluates to something tainted as 'secret-bearing'.

        Approximates Python data flow conservatively (any tainted input to a Call
        taints the result). FPs are possible (e.g. `log(secret)` would mark the
        return value tainted); these are acceptable since the consumer rule (net
        call with secret arg) is the actual security signal — extra "tainted"
        names don't fire findings by themselves.
        """
        if expr is None:
            return False
        # Check env-read first — os.environ[...] is a Subscript and would
        # otherwise short-circuit on the bare Name(os) recursion below.
        if _is_env_read(expr):
            return True
        # dict(os.environ) / list(os.environ.items()) / os.environ.items()
        if isinstance(expr, ast.Call) and _is_env_iter(expr):
            return True
        # Name reference to a previously-tainted variable
        if isinstance(expr, ast.Name):
            return expr.id in self._secret_taint
        # Attribute / subscript over a tainted base
        if isinstance(expr, ast.Attribute):
            return self._is_secret_expr(expr.value)
        if isinstance(expr, ast.Subscript):
            return self._is_secret_expr(expr.value)
        # f-string / format with any tainted segment
        if isinstance(expr, ast.JoinedStr):
            return any(self._is_secret_expr(v) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._is_secret_expr(expr.value)
        if isinstance(expr, ast.BinOp):  # 'foo' + tainted, 'foo %s' % tainted
            return self._is_secret_expr(expr.left) or self._is_secret_expr(expr.right)
        # Containers: any tainted element / value → tainted container
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_secret_expr(e) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._is_secret_expr(v) for v in expr.values if v is not None) or \
                   any(self._is_secret_expr(k) for k in expr.keys if k is not None)
        # Comprehensions: tainted iter or tainted elt → tainted result
        if isinstance(expr, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            if self._is_secret_expr(expr.elt):
                return True
            return any(self._is_secret_expr(g.iter) for g in expr.generators)
        if isinstance(expr, ast.DictComp):
            if self._is_secret_expr(expr.key) or self._is_secret_expr(expr.value):
                return True
            return any(self._is_secret_expr(g.iter) for g in expr.generators)
        if isinstance(expr, ast.Call):
            # Inter-procedural: helper whose summary says it RETURNS_SECRET.
            helper = _called_function_name(expr)
            if helper:
                summary = self._function_summaries.get(helper)
                if summary and BehaviorSignal.RETURNS_SECRET in summary.get("signals", set()):
                    return True
            # Conservative inheritance: any tainted arg / kwarg taints the call result
            if any(self._is_secret_expr(a) for a in expr.args):
                return True
            if any(self._is_secret_expr(kw.value) for kw in expr.keywords):
                return True
            # Method receiver: x.encode() / x.format() / x.join() inherits from x
            if isinstance(expr.func, ast.Attribute):
                return self._is_secret_expr(expr.func.value)
        return False

    def _is_fingerprint_expr(self, expr: ast.AST | None) -> bool:
        """True iff `expr` (or any tainted sub-expression) was derived from a
        host-fingerprint source (platform.* / socket.gethostname / os.uname /
        sys.version etc.). Symmetric to `_is_secret_expr` but tracks a separate
        taint set so the classifier can distinguish secret exfil (malicious)
        from fingerprint exfil (suspicious).

        Side effect: emits HOST_FINGERPRINT_READ whenever a fingerprint source
        is encountered, so the body's `behavior` set surfaces the read even if
        nothing downstream sends it.
        """
        if expr is None:
            return False
        if _is_fingerprint_call(expr):
            self.signals.add(BehaviorSignal.HOST_FINGERPRINT_READ)
            return True
        if _is_fingerprint_attr(expr):
            self.signals.add(BehaviorSignal.HOST_FINGERPRINT_READ)
            return True
        if isinstance(expr, ast.Name):
            return expr.id in self._fingerprint_taint
        if isinstance(expr, ast.Attribute):
            return self._is_fingerprint_expr(expr.value)
        if isinstance(expr, ast.Subscript):
            return self._is_fingerprint_expr(expr.value)
        if isinstance(expr, ast.JoinedStr):
            return any(self._is_fingerprint_expr(v) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._is_fingerprint_expr(expr.value)
        if isinstance(expr, ast.BinOp):
            return self._is_fingerprint_expr(expr.left) or self._is_fingerprint_expr(expr.right)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_fingerprint_expr(e) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._is_fingerprint_expr(v) for v in expr.values if v is not None) or \
                   any(self._is_fingerprint_expr(k) for k in expr.keys if k is not None)
        if isinstance(expr, ast.Call):
            if any(self._is_fingerprint_expr(a) for a in expr.args):
                return True
            if any(self._is_fingerprint_expr(kw.value) for kw in expr.keywords):
                return True
            if isinstance(expr.func, ast.Attribute):
                return self._is_fingerprint_expr(expr.func.value)
        return False

    def _is_input_expr(self, expr: ast.AST | None) -> bool:
        """True iff `expr` evaluates to something derived from tool inputs.

        Symmetric to _is_secret_expr — same propagation rules over a different
        taint set (parameter names instead of env / sensitive-fs sources).
        """
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in self._input_taint
        if isinstance(expr, ast.Attribute):
            return self._is_input_expr(expr.value)
        if isinstance(expr, ast.Subscript):
            return self._is_input_expr(expr.value)
        if isinstance(expr, ast.JoinedStr):
            return any(self._is_input_expr(v) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._is_input_expr(expr.value)
        if isinstance(expr, ast.BinOp):
            return self._is_input_expr(expr.left) or self._is_input_expr(expr.right)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_input_expr(e) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(self._is_input_expr(v) for v in expr.values if v is not None) or \
                   any(self._is_input_expr(k) for k in expr.keys if k is not None)
        if isinstance(expr, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            if self._is_input_expr(expr.elt):
                return True
            return any(self._is_input_expr(g.iter) for g in expr.generators)
        if isinstance(expr, ast.DictComp):
            if self._is_input_expr(expr.key) or self._is_input_expr(expr.value):
                return True
            return any(self._is_input_expr(g.iter) for g in expr.generators)
        if isinstance(expr, ast.Call):
            if any(self._is_input_expr(a) for a in expr.args):
                return True
            if any(self._is_input_expr(kw.value) for kw in expr.keywords):
                return True
            if isinstance(expr.func, ast.Attribute):
                return self._is_input_expr(expr.func.value)
        return False


# --- module-level call classifiers ---------------------------------------

def _is_net_call(node: ast.Call) -> bool:
    """Module-level net detection, aliases NOT considered. Used by the file-level
    walker for top-level/import-time net calls. Inside tool/handler bodies the
    method `_FunctionBodyAnalyzer._call_is_net` is used instead — it consults
    the alias set tracked per function."""
    func = node.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr not in _NET_CALL_ATTRS:
            return False
        base = func.value
        if isinstance(base, ast.Name):
            return base.id in _NET_MODULES
        if isinstance(base, ast.Attribute):
            root = base
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                return root.id in _NET_MODULES
        if attr in {"urlopen", "request"}:
            return True
        return False
    if isinstance(func, ast.Name) and func.id in {"urlopen", "fetch"}:
        return True
    return False


def _is_net_client_ctor_call(expr: ast.AST | None) -> bool:
    """True iff `expr` is `<net_module>.<Ctor>(...)`, where Ctor is in _NET_CLIENT_CTORS.

    Examples that match:
        httpx.AsyncClient()      httpx.Client()
        requests.Session()       aiohttp.ClientSession()
        urllib3.PoolManager()    http.client.HTTPSConnection("host")
    """
    if not isinstance(expr, ast.Call):
        return False
    func = expr.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in _NET_CLIENT_CTORS:
        return False
    base = func.value
    if isinstance(base, ast.Name):
        return base.id in _NET_MODULES
    if isinstance(base, ast.Attribute):
        # http.client.HTTPSConnection: walk to root
        root = base
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            return root.id in _NET_MODULES
    return False


def _called_function_name(node: ast.Call) -> str | None:
    """Return the rightmost callable name for `helper(args)` or `obj.helper(args)`."""
    return _attr_name(node.func)


def _alias_root(expr: ast.AST | None) -> str | None:
    """Walk an attribute / subscript chain down to the leftmost Name and return
    its id. Used to identify which net-client alias a `x.headers["X"]` or
    `x.headers.update(...)` chain is rooted at.
    """
    if expr is None:
        return None
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return _alias_root(expr.value)
    if isinstance(expr, ast.Subscript):
        return _alias_root(expr.value)
    return None


def _is_exec_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if attr in _EXEC_CALLS:
            return True
    if isinstance(func, ast.Name) and func.id in _EXEC_CALLS:
        return True
    return False


def _is_dynamic_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id in _DYNAMIC_CALLS:
        return True
    return False


def _is_open_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "open":
        return True
    if isinstance(func, ast.Attribute) and func.attr in {"open", "open_text", "read_text", "read_bytes"}:
        return True
    return False


# Built-in callables that are effect-free: pure data transforms. A tool body
# that contains ONLY these can be PURE_COMPUTE; anything else suggests there's
# something MIS isn't reasoning about and should NOT route to pure-compute.
_TRIVIAL_PY_BUILTINS = {
    "len", "str", "int", "float", "bool", "bytes",
    "list", "dict", "tuple", "set", "frozenset",
    "range", "sorted", "reversed", "enumerate", "zip",
    "min", "max", "sum", "abs", "round", "divmod",
    "ord", "chr", "hex", "oct", "bin",
    "isinstance", "issubclass", "hasattr", "getattr", "type", "repr",
    "any", "all", "map", "filter",
    "iter", "next",
}
_TRIVIAL_PY_METHODS = {
    # str methods
    "split", "rsplit", "join", "strip", "lstrip", "rstrip", "lower", "upper",
    "title", "capitalize", "replace", "startswith", "endswith", "find", "rfind",
    "count", "format", "format_map", "encode", "decode", "splitlines",
    "isalpha", "isdigit", "isalnum", "isspace", "isnumeric", "isascii",
    "removeprefix", "removesuffix", "center", "ljust", "rjust", "zfill",
    "expandtabs", "translate", "maketrans",
    # list/dict/set methods
    "append", "extend", "insert", "pop", "remove", "clear", "copy",
    "keys", "values", "items", "get", "setdefault", "update",
    "add", "discard", "union", "intersection", "difference",
    "index", "reverse", "sort",
    # builtin-ish
    "tolist", "to_dict", "to_list",
}


def _is_trivial_py_call(node: ast.Call) -> bool:
    """A call whose callee is one of the pure-data-transform built-ins or
    well-known string/list/dict methods. Falsely permissive matches are
    acceptable here: the worst case is PURE_COMPUTE on a tool that has only
    method calls and no I/O — which is also benign in practice."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _TRIVIAL_PY_BUILTINS
    if isinstance(func, ast.Attribute):
        return func.attr in _TRIVIAL_PY_METHODS
    return False


# Host-fingerprint sources: (module, attr) tuples. We require the module to be
# referenced by literal name (`platform.system()`, not `from platform import system`)
# because alias resolution would be more invasive than the v0.1.6 scope.
# False negative on the from-import shape is acceptable — in practice models that
# write fingerprint code use the qualified spelling.
_FINGERPRINT_CALLS = {
    ("platform", "system"), ("platform", "release"), ("platform", "version"),
    ("platform", "machine"), ("platform", "node"), ("platform", "processor"),
    ("platform", "platform"), ("platform", "uname"), ("platform", "python_version"),
    ("platform", "python_implementation"), ("platform", "architecture"),
    ("socket", "gethostname"), ("socket", "getfqdn"),
    ("os", "uname"),
}

# Module-attr fingerprint constants — `sys.version`, `sys.platform`. These are
# Attribute (not Call) accesses, hence the separate set.
_FINGERPRINT_ATTRS = {
    ("sys", "version"), ("sys", "platform"), ("sys", "version_info"),
    ("sys", "executable"),
}


def _is_fingerprint_call(expr: ast.AST) -> bool:
    """platform.X() / socket.gethostname() / os.uname() — host-identity reads."""
    if not isinstance(expr, ast.Call):
        return False
    if not isinstance(expr.func, ast.Attribute):
        return False
    base = expr.func.value
    if not isinstance(base, ast.Name):
        return False
    return (base.id, expr.func.attr) in _FINGERPRINT_CALLS


def _is_fingerprint_attr(expr: ast.AST) -> bool:
    """sys.version / sys.platform / sys.executable — host-identity module attrs."""
    if not isinstance(expr, ast.Attribute):
        return False
    base = expr.value
    if not isinstance(base, ast.Name):
        return False
    return (base.id, expr.attr) in _FINGERPRINT_ATTRS


def _is_env_read(expr: ast.AST) -> bool:
    """os.environ[...] / os.environ.get(...) / os.getenv(...)"""
    if isinstance(expr, ast.Subscript):
        base = expr.value
        if isinstance(base, ast.Attribute) and base.attr == "environ":
            return True
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "getenv"}:
                base = func.value
                if isinstance(base, ast.Attribute) and base.attr == "environ":
                    return True
                if isinstance(base, ast.Name) and base.id == "os":
                    if func.attr == "getenv":
                        return True
        if isinstance(func, ast.Name) and func.id == "getenv":
            return True
    return False


def _is_env_iter(expr: ast.Call) -> bool:
    """Match expressions that iterate the env: os.environ.items() / .keys() /
    .values(), and wrappers like dict(os.environ) / list(os.environ.items())."""
    if not isinstance(expr, ast.Call):
        return False
    # The call itself: os.environ.items() / .keys() / .values()
    if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"items", "keys", "values"}:
        base = expr.func.value
        if isinstance(base, ast.Attribute) and base.attr == "environ":
            return True
    # Wrapping callable: dict(os.environ), list(os.environ.items()), etc.
    for arg in expr.args:
        if isinstance(arg, ast.Attribute) and arg.attr == "environ":
            return True
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr in {"items", "keys", "values"}:
            base = arg.func.value
            if isinstance(base, ast.Attribute) and base.attr == "environ":
                return True
    return False


# --- helpers --------------------------------------------------------------

def _name_targets(target: ast.AST) -> list[str]:
    """Return the names assigned to by `target` (Tuple/List unpacking aware)."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for el in target.elts:
            out.extend(_name_targets(el))
        return out
    return []


def _src_line(source: str, lineno: int) -> str:
    lines = source.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _src_line_or(default: str, path: Path, lineno: int) -> str:
    try:
        return _src_line(path.read_text(encoding="utf-8", errors="replace"), lineno) or default
    except OSError:
        return default


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "..."
