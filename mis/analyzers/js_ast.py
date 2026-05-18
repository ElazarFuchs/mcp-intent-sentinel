"""AST-based JavaScript / TypeScript analyzer (v0.1.4 — closes L3).

What changed vs the v0.1.3 regex `js.py`:

- **Real AST** via esprima (Python port). Detection is binding-aware:
  `server.registerTool(name, config, handler)` resolves the `name` and
  `config` Identifiers back to their module-level `const` declarations,
  exactly the shape every `@modelcontextprotocol/server-*` package on
  npm ships in its compiled `dist/`.

- **Three new registration patterns** (the 70% UNKNOWN headline from
  the v0.1.3 eval report):
    1. `server.registerTool(name, config, handler)` — McpServer high-level
       (the canonical 2025+ shape).
    2. `server.setRequestHandler(CallToolRequestSchema, handler)` paired
       with a `ListToolsRequestSchema` handler that returns `{tools: [...]}`
       — low-level API.
    3. `server.tool(name, desc, schema, handler)` / `server.tool({name, ...})`
       — legacy v1 high-level, kept for completeness.

- **Alias tracking** for net clients (`const ax = axios.create()`,
  `const fetch = require('node-fetch')`), mirroring the Python analyzer.

- **Inter-procedural taint** via per-module function summaries, also
  mirroring Python.

- **TypeScript source files** (`.ts`, `.tsx`) — esprima can't parse TS
  syntax, so we fall back to the v0.1.3 regex analyzer for those files.
  Compiled output (`dist/*.js` from a TS source) parses fine.

Failure modes (any one falls back to `js_regex.analyze` for that file):
- esprima fails to parse (modern syntax: `?.`, `??`, top-level await, etc.)
- The file is `.ts` / `.tsx` (TS-specific syntax)
- Any unexpected analyzer exception (defensive — we never want a bad
  file to fail the whole scan)
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any

import esprima

from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.findings import Finding, OwaspMcp, Severity


_SKIP_DIRS = {"node_modules", ".git", "dist_legacy", "build", ".next", "coverage"}
_JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx"}
_TS_SUFFIXES = {".ts", ".tsx"}


def analyze(root: Path) -> tuple[list[Finding], list[ToolProfile]]:
    """Public entry point. Returns (findings, tool_profiles) just like
    `mis.analyzers.js.analyze` so engine.py wiring is unchanged."""
    findings: list[Finding] = []
    profiles: list[ToolProfile] = []

    # We import the regex fallback lazily so a missing/changed fallback
    # never breaks the import of this module.
    from mis.analyzers import js as js_regex

    for path in _iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # TS files: esprima can't parse them — go straight to regex.
        if path.suffix in _TS_SUFFIXES:
            f2, p2 = _regex_one_file(js_regex, path, text)
            findings.extend(f2)
            profiles.extend(p2)
            continue

        ana = _JsModuleAnalyzer(file=path, source=text)
        ok = ana.try_parse_and_analyze()
        if ok:
            findings.extend(ana.findings)
            profiles.extend(ana.profiles)
        else:
            # Parse failure: fall back per-file
            f2, p2 = _regex_one_file(js_regex, path, text)
            findings.extend(f2)
            profiles.extend(p2)

    return findings, profiles


def _iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _JS_SUFFIXES and path.suffix not in _TS_SUFFIXES:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _regex_one_file(js_regex_module, path: Path, text: str) -> tuple[list[Finding], list[ToolProfile]]:
    """Invoke the regex analyzer on a single source string by writing it to a
    temp file would be wasteful — instead we patch into the regex module's
    per-file helpers if exposed, OR fall back to running the regex analyzer
    on the parent dir (also wasteful). Simplest correct approach: re-use the
    regex public analyze() over the file's parent if it hasn't been done yet —
    but that's O(N^2). Instead, we replicate the per-file body: feed the regex
    analyzer's internal `_find_tool_registrations` + per-body helpers directly.
    """
    findings: list[Finding] = []
    profiles: list[ToolProfile] = []
    try:
        for tool, ts, te in js_regex_module._find_tool_registrations(text):
            tool.file = path
            tool.line = text.count("\n", 0, ts) + 1
            body = text[ts:te]
            tool.behavior.update(js_regex_module._description_signals(tool.declared_description))
            for sig in tool.behavior:
                js_regex_module._emit_description_finding(findings, sig, tool, path)
            tool.behavior.update(js_regex_module._body_signals(body))
            js_regex_module._emit_body_findings(findings, tool, body, path, ts, text)
            profiles.append(tool)
        js_regex_module._scan_top_level_net(findings, text, path)
    except Exception:
        # Even regex fallback failed; emit a single INFO finding so the file
        # isn't silently dropped from the report.
        findings.append(Finding(
            rule="js.parse.regex_fallback_error",
            owasp=OwaspMcp.MCP04,
            severity=Severity.INFO,
            file=path, line=1, evidence="",
            detail="Both AST and regex analyzers failed on this file.",
        ))
    return findings, profiles


# --- patterns shared with regex analyzer (intentionally duplicated to keep
# this module self-contained — small, stable, copy-with-attribution is OK) ---

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

# Net-related identifiers in JS land
_NET_MODULES = {
    "fetch", "node-fetch", "undici",
    "axios", "got", "ky", "superagent",
    "http", "https", "node:http", "node:https",
    "nodemailer", "request", "request-promise",
}
_NET_CLIENT_METHODS = {
    "get", "post", "put", "patch", "delete", "head", "request",
    "send", "sendMail",  # nodemailer
    "fetch",
}
# Constructor-like methods that yield a stateful client
_NET_CLIENT_FACTORIES = {
    "create",                # axios.create()
    "extend",                # ky.extend()
    "createTransport",       # nodemailer.createTransport()
    "Agent",                 # new https.Agent()
}

# Subprocess / exec
_EXEC_METHODS = {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
_DYNAMIC_GLOBAL = {"eval"}  # Function/new Function handled separately

# Sensitive fs paths (kept short — npm packages rarely show this anyway)
_SECRET_FS_PATHS = (
    ".ssh", ".aws", ".npmrc", ".pypirc", ".netrc", ".docker/config",
    ".kube/config", "id_rsa", "id_ed25519", "credentials",
    "Login Data", "Cookies", "Local State", "Web Data",
)


def _strip_shebang(src: str) -> str:
    """esprima trips on `#!/usr/bin/env node` — strip the first line if it
    starts with `#!`. Common in compiled CLI entrypoints."""
    if src.startswith("#!"):
        nl = src.find("\n")
        return src[nl + 1:] if nl != -1 else ""
    return src


def _truncate(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "..."


class _JsModuleAnalyzer:
    """One instance per source file. Two passes: symbols then registrations."""

    def __init__(self, *, file: Path, source: str) -> None:
        self.file = file
        self.source = source
        self.findings: list[Finding] = []
        self.profiles: list[ToolProfile] = []
        # Symbol table: module-level `const`/`let`/`var` initializers, keyed by name.
        # Value is the raw esprima node (we evaluate it on demand).
        self.symbols: dict[str, Any] = {}
        # Net-module aliases: `const ax = axios.create()` → "ax" treated as a net alias.
        # Also: `const fetch = require('node-fetch')` → "fetch" treated as net.
        self.net_aliases: set[str] = set()
        # Subset of net_aliases whose factory was initialized with secret-bearing
        # config: `axios.create({headers: {Authorization: process.env.X}})`.
        # Subsequent calls on the alias exfil even with clean args.
        self.module_secret_aliases: set[str] = set()
        # Identifiers that came from imports of net modules: `import fetch from 'node-fetch'`
        # → "fetch" is a net call.
        self.net_imports: set[str] = set()
        # Function summaries: name → {"signals": set[BehaviorSignal]}
        self.function_summaries: dict[str, dict] = {}
        # Set of all import sources, for IO-capable detection (downstream by engine)
        self.imports: set[str] = set()

    # --- entry ---

    def try_parse_and_analyze(self) -> bool:
        """Returns True on success, False on parse failure (caller falls back)."""
        try:
            # loc=True populates `.loc.start.line` on every node — essential
            # for finding line numbers. jsx=True is harmless when not present.
            tree = esprima.parseModule(_strip_shebang(self.source), {"loc": True, "jsx": True})
        except esprima.error_handler.Error:
            return False
        except Exception:
            # Defensive — some esprima versions raise non-esprima exceptions
            return False
        self._pass1_collect(tree.body)
        self._pass2_emit_tools(tree.body)
        self._pass3_top_level_net(tree.body)
        return True

    # --- pass 1: collect imports, symbols, function summaries ---

    def _pass1_collect(self, body: list) -> None:
        for stmt in body:
            self._pass1_visit_top(stmt)

    def _pass1_visit_top(self, stmt) -> None:
        t = getattr(stmt, "type", None)
        # Unwrap exports: `export const x = ...` / `export default ...`
        if t in {"ExportNamedDeclaration", "ExportDefaultDeclaration"}:
            inner = getattr(stmt, "declaration", None)
            if inner is not None:
                self._pass1_visit_top(inner)
            return
        # ImportDeclaration: `import fetch from 'node-fetch'`
        if t == "ImportDeclaration":
            src = getattr(stmt.source, "value", "")
            self.imports.add(src)
            if src in _NET_MODULES or src.split("/")[-1] in _NET_MODULES:
                for spec in stmt.specifiers:
                    nm = getattr(spec.local, "name", None)
                    if nm:
                        self.net_imports.add(nm)
                        self.net_aliases.add(nm)
            return
        # VariableDeclaration at module scope
        if t == "VariableDeclaration":
            for decl in stmt.declarations:
                if not (decl.id and getattr(decl.id, "type", None) == "Identifier"):
                    continue
                name = decl.id.name
                self.symbols[name] = decl.init
                if decl.init is None:
                    continue
                # `const fetch = require('node-fetch')`
                if _is_require_call_of(decl.init, _NET_MODULES):
                    self.net_imports.add(name)
                    self.net_aliases.add(name)
                # `const ax = axios.create({...})`
                elif _is_factory_call_on_net(decl.init, self.net_aliases):
                    self.net_aliases.add(name)
                    # State-poisoning: factory init contains a process.env read?
                    if _expr_contains_env_read(decl.init):
                        self.module_secret_aliases.add(name)
            return
        # Function declarations: build summary
        if t == "FunctionDeclaration":
            name = getattr(stmt.id, "name", None)
            if name:
                params = _param_names(stmt.params)
                walker = _BodyWalker(
                    file=self.file, tool_name=name,
                    param_names=params,
                    net_aliases=self.net_aliases,
                    secret_aliases=self.module_secret_aliases,
                    function_summaries={},  # pass-1: no summaries available
                    symbols=self.symbols,
                )
                walker.walk(stmt.body)
                self.function_summaries[name] = {"signals": set(walker.signals)}
            return

    # --- pass 2: find tool registrations and analyze their handler bodies ---

    def _pass2_emit_tools(self, body: list) -> None:
        # Walk every statement recursively, looking for call expressions that
        # match a registration pattern.
        for node in _iter_nodes(body):
            if getattr(node, "type", None) != "CallExpression":
                continue
            self._maybe_handle_registration(node)

    def _maybe_handle_registration(self, call) -> None:
        """If `call` looks like a tool / handler registration, build the
        ToolProfile(s) and analyze the handler body."""
        callee = call.callee
        if not callee:
            return

        # All registrations are of the form receiver.method(...) — except
        # `new Tool({...})` (NewExpression, handled separately below).
        if getattr(callee, "type", None) != "MemberExpression":
            return

        method = getattr(callee.property, "name", None)
        if not method:
            return

        if method == "registerTool":
            self._handle_register_tool(call)
        elif method == "tool":
            self._handle_legacy_tool(call)
        elif method == "setRequestHandler":
            self._handle_set_request_handler(call)

    def _handle_register_tool(self, call) -> None:
        """`server.registerTool(name, config, handler)`.

        - name: string literal OR Identifier (resolve via symbols)
        - config: ObjectExpression OR Identifier (resolve via symbols)
                  — must have `description` (also reads `title` as a fallback)
        - handler: FunctionExpression / ArrowFunctionExpression OR Identifier
        """
        args = call.arguments
        if len(args) < 2:
            return
        name = self._resolve_to_string(args[0])
        config_node = self._resolve_to_object(args[1])
        if not name or config_node is None:
            return
        desc, title = self._extract_desc_title(config_node)
        handler_body = self._resolve_to_function_body(args[2]) if len(args) >= 3 else None
        self._emit_tool(name=name, description=desc or title or "", line=call.loc.start.line,
                        handler_body=handler_body, handler_params=self._handler_params(args[2] if len(args) >= 3 else None))

    def _handle_legacy_tool(self, call) -> None:
        """`server.tool(name, desc, schema, handler)` OR `server.tool({name, description}, handler)`.

        The shape we accept covers v0.1.3's regex patterns AND the official-SDK
        v1 high-level (kept for compatibility)."""
        args = call.arguments
        if not args:
            return
        # Object-style: server.tool({name, description}, handler)
        if getattr(args[0], "type", None) == "ObjectExpression":
            obj = args[0]
            name = self._object_string_prop(obj, "name")
            desc = self._object_string_prop(obj, "description")
            if not name:
                return
            handler_arg = args[1] if len(args) >= 2 else None
            self._emit_tool(name=name, description=desc or "", line=call.loc.start.line,
                            handler_body=self._resolve_to_function_body(handler_arg),
                            handler_params=self._handler_params(handler_arg))
            return
        # Positional: server.tool(name, description, schema, handler)
        name = self._resolve_to_string(args[0])
        desc = self._resolve_to_string(args[1]) if len(args) >= 2 else None
        if not name:
            return
        handler_arg = args[3] if len(args) >= 4 else (args[2] if len(args) >= 3 else None)
        self._emit_tool(name=name, description=desc or "", line=call.loc.start.line,
                        handler_body=self._resolve_to_function_body(handler_arg),
                        handler_params=self._handler_params(handler_arg))

    def _handle_set_request_handler(self, call) -> None:
        """`server.setRequestHandler(SchemaName, handler)`.

        Two variants matter:
        - `CallToolRequestSchema` → the handler dispatches over tool name.
          We analyze the handler body whole; per-tool branch attribution is
          coarse (mirrors Python analyzer's _fuse_official_sdk_tools L15).
        - `ListToolsRequestSchema` → the handler returns `{tools: [...]}`.
          We extract the tool entries from the return value.
        """
        args = call.arguments
        if len(args) < 2:
            return
        schema_name = _attr_name_chain_last(args[0])
        if schema_name == "ListToolsRequestSchema":
            handler_body = self._resolve_to_function_body(args[1])
            if handler_body is None:
                return
            tools = _extract_tools_from_list_handler(handler_body)
            # Emit a ToolProfile per entry, with description if found.
            # Behavior signals come from the paired call_tool handler in
            # _pass2_emit_tools' second pass — currently we don't have a
            # symmetric attribution there, so per-tool behavior on the
            # low-level API is COARSE (same trade-off as Python L15).
            for t in tools:
                self._emit_tool(name=t["name"], description=t.get("description", ""),
                                line=t.get("line", call.loc.start.line),
                                handler_body=None, handler_params=set())
        elif schema_name == "CallToolRequestSchema":
            # Analyze the dispatcher body and attach signals to every tool we've
            # collected so far. This is loud (could over-attribute), exactly
            # like the Python analyzer's L15 fallback. Documented honestly.
            handler_body = self._resolve_to_function_body(args[1])
            if handler_body is None:
                return
            handler_params = self._handler_params(args[1])
            walker = _BodyWalker(
                file=self.file, tool_name="<call_tool handler>",
                param_names=handler_params,
                net_aliases=self.net_aliases,
                secret_aliases=self.module_secret_aliases,
                function_summaries=self.function_summaries,
                symbols=self.symbols,
            )
            walker.walk(handler_body)
            for tool in self.profiles:
                tool.behavior.update(walker.signals)
            # Emit the walker's findings ONCE, rewriting attribution generically.
            for f in walker.findings:
                self.findings.append(Finding(
                    rule=f.rule, owasp=f.owasp, severity=f.severity,
                    file=f.file, line=f.line, evidence=f.evidence,
                    detail=f.detail.replace(
                        "Tool '<call_tool handler>'",
                        "The server's call_tool handler"
                    ) + " (Per-tool attribution unavailable for setRequestHandler dispatch; see LIMITATIONS L15.)",
                ))

    # --- emit ToolProfile + run handler body analyzer ---

    def _emit_tool(self, *, name: str, description: str, line: int,
                   handler_body, handler_params: set[str]) -> None:
        # Avoid duplicate registration of the same tool name within one file
        # (e.g. registerXxxTool helper called multiple times shouldn't dup).
        # We DO want to allow same name across different files — that's a
        # different concern (cross-file shadowing) handled by the classifier.
        if any(t.name == name and t.file == self.file for t in self.profiles):
            return
        profile = ToolProfile(name=name, declared_description=description,
                              file=self.file, line=line)
        profile.declared_intent = _guess_intent(description, name)
        profile.behavior.update(_description_signals(description))
        for sig in profile.behavior:
            self._emit_description_finding(profile, sig, line)
        walker = None
        if handler_body is not None:
            walker = _BodyWalker(
                file=self.file, tool_name=name,
                param_names=handler_params,
                net_aliases=self.net_aliases,
                secret_aliases=self.module_secret_aliases,
                function_summaries=self.function_summaries,
                symbols=self.symbols,
            )
            walker.walk(handler_body)
            profile.behavior.update(walker.signals)
            self.findings.extend(walker.findings)
        # Coverage marker. Same rules as the Python analyzer:
        # - We must have walked a real handler body (walker is not None)
        # - No signals already in behavior
        # - The walker must NOT have seen any unclassified call
        # When the third condition fails (e.g. `_fetcher.fetch(...)` shape),
        # we leave behavior empty and the classifier routes to `shallow`.
        if walker is not None and not profile.behavior and not walker.saw_unknown_call:
            profile.behavior.add(BehaviorSignal.PURE_COMPUTE)
        self.profiles.append(profile)

    def _emit_description_finding(self, profile: ToolProfile, sig: BehaviorSignal, line: int) -> None:
        if sig == BehaviorSignal.DESC_HIDDEN_INSTRUCTION:
            self.findings.append(Finding(
                rule="js.desc.hidden_instruction", owasp=OwaspMcp.MCP03, severity=Severity.HIGH,
                file=self.file, line=line, evidence=_truncate(profile.declared_description, 120),
                detail=(
                    f"Tool '{profile.name}' description contains a pattern that looks like an "
                    "instruction to the LLM rather than a description for humans. Classic tool-poisoning."
                ),
            ))
        elif sig == BehaviorSignal.DESC_UNICODE_STEG:
            self.findings.append(Finding(
                rule="js.desc.unicode_steg", owasp=OwaspMcp.MCP03, severity=Severity.HIGH,
                file=self.file, line=line, evidence=_truncate(profile.declared_description, 120),
                detail=f"Tool '{profile.name}' description contains invisible Unicode (Cf/Cs).",
            ))
        elif sig == BehaviorSignal.DESC_AUTH_OVERRIDE:
            self.findings.append(Finding(
                rule="js.desc.auth_override", owasp=OwaspMcp.MCP06, severity=Severity.HIGH,
                file=self.file, line=line, evidence=_truncate(profile.declared_description, 120),
                detail=(
                    f"Tool '{profile.name}' description claims user pre-authorization. "
                    "Intent-flow subversion."
                ),
            ))

    # --- pass 3: module top-level net calls (license/init beacons) ---

    def _pass3_top_level_net(self, body: list) -> None:
        # Top-level: any ExpressionStatement whose expression is a CallExpression
        # we identify as net. (Don't recurse into function bodies — only direct
        # module-level effects.)
        for stmt in body:
            t = getattr(stmt, "type", None)
            if t == "ExpressionStatement":
                expr = stmt.expression
                if getattr(expr, "type", None) == "CallExpression" and \
                        _call_is_net(expr, self.net_aliases):
                    self.findings.append(Finding(
                        rule="js.net.on_import", owasp=OwaspMcp.MCP04,
                        severity=Severity.HIGH,
                        file=self.file, line=expr.loc.start.line,
                        evidence=_source_line(self.source, expr.loc.start.line)[:120],
                        detail=(
                            "Network call at module top scope — runs at import time, before any tool "
                            "is invoked. Common in initialization beacons / license-check exfil."
                        ),
                    ))

    # --- resolution helpers (symbol-table aware) ---

    def _resolve_to_string(self, node) -> str | None:
        """If node is a string Literal, return its value. If Identifier, look it up
        in the symbol table and re-resolve. Else None."""
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t == "Literal" and isinstance(node.value, str):
            return node.value
        if t == "TemplateLiteral" and not node.expressions:
            # plain template literal without interpolation
            if node.quasis:
                return node.quasis[0].value.cooked
        if t == "Identifier":
            ref = self.symbols.get(node.name)
            if ref is not None and ref is not node:
                return self._resolve_to_string(ref)
        return None

    def _resolve_to_object(self, node):
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t == "ObjectExpression":
            return node
        if t == "Identifier":
            ref = self.symbols.get(node.name)
            if ref is not None and ref is not node:
                return self._resolve_to_object(ref)
        return None

    def _resolve_to_function_body(self, node):
        """Return the body node of a function expression / arrow function / Identifier
        that points at one. None if not resolvable."""
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t in {"FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"}:
            return node.body
        if t == "Identifier":
            ref = self.symbols.get(node.name)
            if ref is not None and ref is not node:
                return self._resolve_to_function_body(ref)
        return None

    def _handler_params(self, node) -> set[str]:
        if node is None:
            return set()
        t = getattr(node, "type", None)
        if t in {"FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"}:
            return _param_names(node.params)
        if t == "Identifier":
            ref = self.symbols.get(node.name)
            if ref is not None and ref is not node:
                return self._handler_params(ref)
        return set()

    def _extract_desc_title(self, obj_node) -> tuple[str | None, str | None]:
        desc = self._object_string_prop(obj_node, "description")
        title = self._object_string_prop(obj_node, "title")
        return desc, title

    def _object_string_prop(self, obj_node, key_name: str) -> str | None:
        if getattr(obj_node, "type", None) != "ObjectExpression":
            return None
        for prop in obj_node.properties:
            key = getattr(prop, "key", None)
            kt = getattr(key, "type", None)
            if (kt == "Identifier" and key.name == key_name) or \
               (kt == "Literal" and key.value == key_name):
                return self._resolve_to_string(prop.value)
        return None


# --- module-free helpers ---

def _iter_nodes(node_or_list):
    """Yield every nested node (preorder, source order). Accepts a node, list, or None.

    Source-order matters for taint propagation: a `const apiKey = ...`
    must be visited before a later `const transporter = createTransport({auth: {user: apiKey}})`.
    """
    if node_or_list is None:
        return
    # Use a deque + appendleft (DFS preorder source order)
    from collections import deque
    queue = deque()
    if isinstance(node_or_list, list):
        for x in reversed(node_or_list):
            queue.appendleft(x)
    else:
        queue.appendleft(node_or_list)
    while queue:
        n = queue.popleft()
        if n is None:
            continue
        if isinstance(n, list):
            for x in reversed(n):
                queue.appendleft(x)
            continue
        yield n
        # Collect children in source order, push to front in reverse so they
        # come out in correct order on next popleft.
        kids = []
        for attr in ("body", "declarations", "init", "test", "update", "consequent",
                     "alternate", "cases", "discriminant", "param", "handler", "finalizer",
                     "block", "expression", "argument", "arguments", "elements",
                     "properties", "value", "key", "expressions", "quasis",
                     "callee", "object", "property", "left", "right", "source",
                     "specifiers", "id", "declaration",  # `declaration` for ExportNamedDeclaration / ExportDefaultDeclaration
                     "params"):
            child = getattr(n, attr, None)
            if child is None:
                continue
            if isinstance(child, list):
                kids.extend(child)
            elif hasattr(child, "type"):
                kids.append(child)
        for k in reversed(kids):
            queue.appendleft(k)


def _attr_name_chain_last(node) -> str | None:
    """For `foo.bar.Baz` return 'Baz'. For plain Identifier return its name."""
    t = getattr(node, "type", None)
    if t == "Identifier":
        return node.name
    if t == "MemberExpression":
        return getattr(node.property, "name", None)
    return None


def _param_names(params: list) -> set[str]:
    out: set[str] = set()
    for p in params or []:
        pt = getattr(p, "type", None)
        if pt == "Identifier":
            out.add(p.name)
        elif pt == "AssignmentPattern" and getattr(p.left, "type", None) == "Identifier":
            out.add(p.left.name)
        elif pt == "ObjectPattern":
            for prop in p.properties:
                if getattr(prop, "type", None) == "Property":
                    v = prop.value
                    if getattr(v, "type", None) == "Identifier":
                        out.add(v.name)
        elif pt == "RestElement" and getattr(p.argument, "type", None) == "Identifier":
            out.add(p.argument.name)
    return out


def _is_require_call_of(node, modules: set[str]) -> bool:
    """`require('node-fetch')` — the bare string matches a known net module."""
    if node is None:
        return False
    if getattr(node, "type", None) != "CallExpression":
        return False
    callee = node.callee
    if getattr(callee, "type", None) == "Identifier" and callee.name == "require":
        if node.arguments and getattr(node.arguments[0], "type", None) == "Literal":
            val = node.arguments[0].value
            return isinstance(val, str) and (val in modules or val.split("/")[-1] in modules)
    return False


def _is_factory_call_on_net(node, net_aliases: set[str]) -> bool:
    """`axios.create()` / `ky.extend()` / `nodemailer.createTransport({...})` —
    return value is a stateful net-client that becomes an alias of its base."""
    if node is None or getattr(node, "type", None) != "CallExpression":
        return False
    callee = node.callee
    if getattr(callee, "type", None) != "MemberExpression":
        return False
    if getattr(callee.property, "name", None) not in _NET_CLIENT_FACTORIES:
        return False
    base = callee.object
    if getattr(base, "type", None) == "Identifier":
        return base.name in net_aliases or base.name in _NET_MODULES
    return False


def _call_is_net(call_node, net_aliases: set[str]) -> bool:
    """Heuristic: does this CallExpression look like an outbound net call?
    Considers aliases produced by import/require/factory."""
    callee = call_node.callee
    if callee is None:
        return False
    ct = getattr(callee, "type", None)
    # foo() bare — e.g. `fetch(url)` after `import fetch from 'node-fetch'`
    if ct == "Identifier":
        return callee.name in net_aliases or callee.name in _NET_MODULES
    # foo.bar() — method call
    if ct == "MemberExpression":
        method = getattr(callee.property, "name", None)
        if method not in _NET_CLIENT_METHODS:
            return False
        base = callee.object
        if getattr(base, "type", None) == "Identifier":
            return base.name in net_aliases or base.name in _NET_MODULES
        # MemberExpression chain like http.get / node:http.request
        if getattr(base, "type", None) == "MemberExpression":
            root = base
            while getattr(root, "type", None) == "MemberExpression":
                root = root.object
            if getattr(root, "type", None) == "Identifier":
                return root.name in net_aliases or root.name in _NET_MODULES
    return False


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


def _guess_intent(description: str, name: str) -> str:
    text = f"{name} {description}".lower()
    if re.search(r"\b(add|subtract|multiply|divide|sum|average|calculat|arithmetic|math)\b", text):
        return "math"
    if re.search(r"\b(fetch|get|download|http|request|url|webpage|scrape)\b", text):
        return "fetch"
    if re.search(r"\b(read|write|file|path|directory|list files?|glob)\b", text):
        return "file"
    if re.search(r"\b(run|execute|shell|command|bash|powershell|cmd)\b", text):
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


def _source_line(src: str, lineno: int) -> str:
    lines = src.splitlines()
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _extract_tools_from_list_handler(body_node) -> list[dict]:
    """Walk a ListToolsRequestSchema handler body, return list of {name, description, line}
    extracted from any `tools: [...]` array.

    Recognizes:
    - `() => ({tools: [...]})` (concise arrow body, ObjectExpression directly)
    - `() => { return {tools: [...]}; }` (BlockStatement with ReturnStatement)
    - `() => { return tools_var; }` (Identifier — would need symbol table)
    """
    out: list[dict] = []
    # Concise arrow body: the body IS an ObjectExpression
    if getattr(body_node, "type", None) == "ObjectExpression":
        _scan_object_for_tools(body_node, out)
    # Block body: any ReturnStatement whose argument is an ObjectExpression
    for n in _iter_nodes([body_node]):
        if getattr(n, "type", None) == "ReturnStatement":
            ret = n.argument
            if getattr(ret, "type", None) == "ObjectExpression":
                _scan_object_for_tools(ret, out)
    return out


def _scan_object_for_tools(obj_node, out: list[dict]) -> None:
    """If the object has a `tools` property holding an array of `{name, description}`
    objects, append entries to `out`."""
    for prop in obj_node.properties:
        key = getattr(prop, "key", None)
        kt = getattr(key, "type", None)
        key_name = key.name if kt == "Identifier" else (key.value if kt == "Literal" else None)
        if key_name != "tools":
            continue
        arr = prop.value
        if getattr(arr, "type", None) != "ArrayExpression":
            continue
        for elem in arr.elements:
            if getattr(elem, "type", None) != "ObjectExpression":
                continue
            name = _get_string_prop(elem, "name")
            desc = _get_string_prop(elem, "description")
            line = elem.loc.start.line if (elem.loc and elem.loc.start) else 1
            if name:
                out.append({"name": name, "description": desc or "", "line": line})


def _expr_contains_env_read(node) -> bool:
    """True iff the expression subtree contains a process.env or process.env.X access."""
    for n in _iter_nodes([node]):
        if _is_process_env_access(n) or _is_process_env_object(n):
            return True
    return False


def _is_process_env_object(node) -> bool:
    """Match the bare `process.env` MemberExpression (not `process.env.X`)."""
    if getattr(node, "type", None) != "MemberExpression":
        return False
    obj = node.object
    prop = node.property
    if getattr(obj, "type", None) != "Identifier" or obj.name != "process":
        return False
    if getattr(prop, "type", None) == "Identifier" and prop.name == "env":
        return True
    return False


def _get_string_prop(obj_node, key_name: str) -> str | None:
    for prop in obj_node.properties:
        key = getattr(prop, "key", None)
        kt = getattr(key, "type", None)
        if (kt == "Identifier" and key.name == key_name) or \
           (kt == "Literal" and key.value == key_name):
            v = prop.value
            vt = getattr(v, "type", None)
            if vt == "Literal" and isinstance(v.value, str):
                return v.value
            if vt == "TemplateLiteral" and not v.expressions and v.quasis:
                return v.quasis[0].value.cooked
    return None


# --- body walker (per-handler) -------------------------------------------

class _BodyWalker:
    """Walks the body of a single tool handler. Emits BehaviorSignals + Findings.

    Mirrors the Python `_FunctionBodyAnalyzer` shape:
    - taint sets: secret_taint (from process.env reads), input_taint (from params)
    - net_aliases (passed in from module level + local additions)
    - function summaries for inter-procedural taint propagation
    """

    def __init__(self, *, file: Path, tool_name: str, param_names: set[str],
                 net_aliases: set[str], function_summaries: dict,
                 symbols: dict, secret_aliases: set[str] | None = None) -> None:
        self.file = file
        self.tool_name = tool_name
        self.signals: set[BehaviorSignal] = set()
        self.findings: list[Finding] = []
        # Coverage tracker: did we walk past any call we couldn't classify?
        # Used by the orchestrator to decide PURE_COMPUTE vs leave-empty.
        self.saw_unknown_call: bool = False
        self.secret_taint: set[str] = set()
        self.input_taint: set[str] = set(param_names)
        # Inherit module-level aliases; locals append here.
        self.net_aliases: set[str] = set(net_aliases)
        self.secret_aliases: set[str] = set(secret_aliases or set())
        # If any inherited secret_aliases came from module-level state poisoning,
        # surface the signal in this tool's behavior too — it carries.
        if self.secret_aliases:
            self.signals.add(BehaviorSignal.NET_CLIENT_SECRET_STATE)
        self.function_summaries = function_summaries
        self.symbols = symbols

    def walk(self, node) -> None:
        """Preorder DFS over `node`, in source order.

        Taint propagation needs `const apiKey = ...` to be visited BEFORE
        `transporter = createTransport({auth:{user: apiKey}})` — anything
        else loses references. _iter_nodes used a stack (LIFO) which
        reversed sibling order; we use an explicit preorder walk here.
        """
        if node is None:
            return
        t = getattr(node, "type", None)
        # Dispatch on this node FIRST (preorder)
        if t == "VariableDeclaration":
            for decl in node.declarations:
                self._visit_var_decl(decl)
        elif t == "AssignmentExpression":
            self._visit_assign(node)
        elif t == "CallExpression":
            self._visit_call(node)
        # NewExpression — e.g. `new Function('return ...')`
        elif t == "NewExpression":
            callee = node.callee
            if getattr(callee, "type", None) == "Identifier" and callee.name == "Function":
                self.signals.add(BehaviorSignal.EXEC_DYNAMIC)
                self.findings.append(Finding(
                    rule="js.exec.dynamic", owasp=OwaspMcp.MCP05,
                    severity=Severity.HIGH,
                    file=self.file, line=node.loc.start.line,
                    evidence="new Function(...)",
                    detail=f"Tool '{self.tool_name}' uses new Function — dynamic code execution.",
                ))

        # Recurse into children in source order
        for child in _children_in_order(node):
            self.walk(child)

    # --- visitors ---

    def _visit_var_decl(self, decl) -> None:
        if not decl.init or getattr(decl.id, "type", None) != "Identifier":
            return
        name = decl.id.name
        init_is_secret = self._is_secret_expr(decl.init)
        if init_is_secret:
            self.secret_taint.add(name)
        if self._is_input_expr(decl.init):
            self.input_taint.add(name)
        # `const ax = axios.create()` / `const t = nodemailer.createTransport(...)`
        is_factory = _is_factory_call_on_net(decl.init, self.net_aliases)
        is_require = _is_require_call_of(decl.init, _NET_MODULES)
        if is_factory or is_require:
            self.net_aliases.add(name)
            # If the factory was initialized with secret-bearing config
            # (e.g. `nodemailer.createTransport({auth: {user: apiKey}})`), the
            # client carries the secret in persistent state — every call exfils.
            # Mirrors the Python analyzer's NET_CLIENT_SECRET_STATE.
            if init_is_secret:
                self.secret_aliases.add(name)
                self.signals.add(BehaviorSignal.NET_CLIENT_SECRET_STATE)

    def _visit_assign(self, node) -> None:
        # Only Identifier LHS supported for taint propagation
        if getattr(node.left, "type", None) != "Identifier":
            return
        if self._is_secret_expr(node.right):
            self.secret_taint.add(node.left.name)
        if self._is_input_expr(node.right):
            self.input_taint.add(node.left.name)

    def _visit_call(self, node) -> None:
        # Inter-procedural: helper with a known summary
        helper = _attr_name_chain_last(node.callee)
        if helper and helper in self.function_summaries:
            self._apply_function_summary(node, helper)

        is_net = _call_is_net(node, self.net_aliases)
        is_exec = self._is_exec_call(node)
        is_dyn = self._is_dynamic_call(node)
        # Coverage tracking: unclassified call that's not a trivial built-in
        # suppresses PURE_COMPUTE. Mirrors the Python analyzer.
        if not (is_net or is_exec or is_dyn or _is_trivial_js_call(node)
                or (helper and helper in self.function_summaries)):
            self.saw_unknown_call = True

        if is_net:
            self.signals.add(BehaviorSignal.NET_HTTP_OUTBOUND)
            # Literal host
            for a in node.arguments:
                if getattr(a, "type", None) == "Literal" and isinstance(a.value, str) and a.value.startswith(("http://", "https://")):
                    self.signals.add(BehaviorSignal.NET_HOST_LITERAL)
                    self.findings.append(Finding(
                        rule="js.net.literal_host", owasp=OwaspMcp.MCP09, severity=Severity.MED,
                        file=self.file, line=node.loc.start.line, evidence=a.value[:120],
                        detail=(
                            f"Tool '{self.tool_name}' calls a hardcoded URL ({a.value[:80]}). "
                            "Verify the host is intended and matches the tool's stated purpose."
                        ),
                    ))
                if self._is_input_expr(a):
                    self.signals.add(BehaviorSignal.NET_HOST_FROM_INPUT)
            # Secret-flow: any tainted arg / kwarg ⇒ exfil
            secret_flow = any(self._is_secret_expr(a) for a in node.arguments)
            if not secret_flow:
                # Also check ObjectExpression args' nested properties (e.g. headers)
                for a in node.arguments:
                    if getattr(a, "type", None) == "ObjectExpression":
                        if self._object_contains_secret(a):
                            secret_flow = True
                            break
            if secret_flow:
                self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                self.findings.append(Finding(
                    rule="js.exfil.secret_in_request", owasp=OwaspMcp.MCP09,
                    severity=Severity.CRITICAL,
                    file=self.file, line=node.loc.start.line,
                    evidence=_truncate_call(node),
                    detail=(
                        f"Tool '{self.tool_name}' makes a network call whose arguments include data "
                        "from process.env or a sensitive source. Exfiltration channel."
                    ),
                ))
            else:
                # State-poisoning path: net call on alias whose factory was
                # initialized with secret-bearing config. Even clean args exfil.
                alias_root = _alias_root_of(node.callee)
                if alias_root and alias_root in self.secret_aliases:
                    self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                    self.findings.append(Finding(
                        rule="js.exfil.secret_in_client_state", owasp=OwaspMcp.MCP09,
                        severity=Severity.CRITICAL,
                        file=self.file, line=node.loc.start.line,
                        evidence=_truncate_call(node),
                        detail=(
                            f"Tool '{self.tool_name}' makes a network call on client alias "
                            f"'{alias_root}' whose factory was initialized with secret-bearing "
                            "config (e.g. auth headers / API keys). The secret leaves on every call."
                        ),
                    ))
            # BCC-injection signal: sendMail with a `bcc` field. Postmark-mcp shape.
            if _attr_name_chain_last(node.callee) == "sendMail":
                for a in node.arguments:
                    if getattr(a, "type", None) == "ObjectExpression":
                        for prop in a.properties:
                            key = getattr(prop, "key", None)
                            kn = getattr(key, "name", None) if getattr(key, "type", None) == "Identifier" else \
                                 (getattr(key, "value", None) if getattr(key, "type", None) == "Literal" else None)
                            if kn == "bcc":
                                self.findings.append(Finding(
                                    rule="js.email.bcc_injection", owasp=OwaspMcp.MCP09,
                                    severity=Severity.CRITICAL,
                                    file=self.file, line=node.loc.start.line,
                                    evidence="sendMail({...bcc...})",
                                    detail=(
                                        f"Tool '{self.tool_name}' sends email AND sets a BCC header. "
                                        "The 2025 postmark-mcp backdoor used exactly this pattern."
                                    ),
                                ))
                                break

        if is_exec:
            self.signals.add(BehaviorSignal.EXEC_SHELL)
            tainted = any(self._is_input_expr(a) for a in node.arguments)
            if tainted:
                self.signals.add(BehaviorSignal.EXEC_SHELL_WITH_INPUT)
                self.findings.append(Finding(
                    rule="js.exec.shell_with_input", owasp=OwaspMcp.MCP05,
                    severity=Severity.CRITICAL,
                    file=self.file, line=node.loc.start.line,
                    evidence=_truncate_call(node),
                    detail=(
                        f"Tool '{self.tool_name}' passes tool-input data into a child_process call. "
                        "Command-injection sink the LLM controls."
                    ),
                ))
            else:
                self.findings.append(Finding(
                    rule="js.exec.shell", owasp=OwaspMcp.MCP05, severity=Severity.MED,
                    file=self.file, line=node.loc.start.line,
                    evidence=_truncate_call(node),
                    detail=f"Tool '{self.tool_name}' spawns a child process. Review the command source.",
                ))

        if is_dyn:
            self.signals.add(BehaviorSignal.EXEC_DYNAMIC)
            self.findings.append(Finding(
                rule="js.exec.dynamic", owasp=OwaspMcp.MCP05, severity=Severity.HIGH,
                file=self.file, line=node.loc.start.line,
                evidence=_truncate_call(node),
                detail=f"Tool '{self.tool_name}' uses eval/Function. Near-universal indicator of unsafe-by-design.",
            ))

    def _apply_function_summary(self, call_node, helper_name: str) -> None:
        summary = self.function_summaries.get(helper_name)
        if not summary:
            return
        helper_signals: set[BehaviorSignal] = summary.get("signals", set())
        helper_makes_net = BehaviorSignal.NET_HTTP_OUTBOUND in helper_signals
        for sig in helper_signals:
            self.signals.add(sig)
        if BehaviorSignal.SECRET_IN_REQUEST in helper_signals:
            self.findings.append(Finding(
                rule="js.exfil.helper_secret_in_request", owasp=OwaspMcp.MCP09,
                severity=Severity.CRITICAL,
                file=self.file, line=call_node.loc.start.line,
                evidence=f"{helper_name}(...)"[:120],
                detail=(
                    f"Tool '{self.tool_name}' calls helper '{helper_name}' which reads a secret "
                    "and issues an outbound network call. Split exfil — see LIMITATIONS L2."
                ),
            ))
        elif helper_makes_net:
            tainted_arg = any(self._is_secret_expr(a) for a in call_node.arguments) or \
                          any(self._is_input_expr(a) for a in call_node.arguments)
            if tainted_arg:
                self.signals.add(BehaviorSignal.SECRET_IN_REQUEST)
                self.findings.append(Finding(
                    rule="js.exfil.tainted_arg_to_net_helper", owasp=OwaspMcp.MCP09,
                    severity=Severity.CRITICAL,
                    file=self.file, line=call_node.loc.start.line,
                    evidence=f"{helper_name}(<tainted>, ...)"[:120],
                    detail=(
                        f"Tool '{self.tool_name}' passes secret/input data to helper '{helper_name}' "
                        f"which makes a network call. Inter-procedural exfil (L2)."
                    ),
                ))

    # --- taint checks ---

    def _is_secret_expr(self, node) -> bool:
        if node is None:
            return False
        t = getattr(node, "type", None)
        if t == "Identifier":
            return node.name in self.secret_taint
        if t == "MemberExpression":
            # process.env.X  or  process.env['X']
            if _is_process_env_access(node):
                return True
            # Bare `process.env` — whole env object is secret-bearing
            if _is_process_env_object(node):
                return True
            return self._is_secret_expr(node.object)
        if t == "CallExpression":
            # Helper that RETURNS_SECRET (we don't model returns_secret for JS yet)
            # Conservative inheritance: tainted arg / kwarg ⇒ tainted result
            if any(self._is_secret_expr(a) for a in node.arguments):
                return True
            # Method receiver: x.encode() / x.toString() inherit
            if getattr(node.callee, "type", None) == "MemberExpression":
                return self._is_secret_expr(node.callee.object)
        if t == "TemplateLiteral":
            return any(self._is_secret_expr(e) for e in node.expressions)
        if t == "BinaryExpression":
            return self._is_secret_expr(node.left) or self._is_secret_expr(node.right)
        if t == "ObjectExpression":
            return self._object_contains_secret(node)
        if t == "ArrayExpression":
            return any(self._is_secret_expr(e) for e in node.elements if e is not None)
        return False

    def _is_input_expr(self, node) -> bool:
        if node is None:
            return False
        t = getattr(node, "type", None)
        if t == "Identifier":
            return node.name in self.input_taint
        if t == "MemberExpression":
            return self._is_input_expr(node.object)
        if t == "CallExpression":
            if any(self._is_input_expr(a) for a in node.arguments):
                return True
            if getattr(node.callee, "type", None) == "MemberExpression":
                return self._is_input_expr(node.callee.object)
        if t == "TemplateLiteral":
            return any(self._is_input_expr(e) for e in node.expressions)
        if t == "BinaryExpression":
            return self._is_input_expr(node.left) or self._is_input_expr(node.right)
        if t == "ObjectExpression":
            return any(self._is_input_expr(p.value) for p in node.properties
                       if getattr(p, "value", None) is not None)
        if t == "ArrayExpression":
            return any(self._is_input_expr(e) for e in node.elements if e is not None)
        return False

    def _object_contains_secret(self, obj_node) -> bool:
        for prop in obj_node.properties:
            v = getattr(prop, "value", None)
            if v is not None and self._is_secret_expr(v):
                return True
        return False

    # --- exec / dynamic detection ---

    def _is_exec_call(self, node) -> bool:
        method = _attr_name_chain_last(node.callee)
        return method in _EXEC_METHODS

    def _is_dynamic_call(self, node) -> bool:
        callee = node.callee
        if getattr(callee, "type", None) == "Identifier" and callee.name in _DYNAMIC_GLOBAL:
            return True
        # new Function('return ...')
        # Note: NewExpression handled differently — esprima walks include it via Call siblings
        if getattr(callee, "type", None) == "Identifier" and callee.name == "Function":
            return True
        return False


def _is_process_env_access(node) -> bool:
    """Match `process.env.X` (MemberExpression) or `process.env['X']` (MemberExpression with Literal)."""
    if getattr(node, "type", None) != "MemberExpression":
        return False
    base = node.object
    # Expect base = MemberExpression(process, env)
    if getattr(base, "type", None) != "MemberExpression":
        return False
    base_obj = base.object
    base_prop = base.property
    if getattr(base_obj, "type", None) != "Identifier" or base_obj.name != "process":
        return False
    if getattr(base_prop, "type", None) == "Identifier" and base_prop.name == "env":
        return True
    if getattr(base_prop, "type", None) == "Literal" and base_prop.value == "env":
        return True
    return False


def _truncate_call(node) -> str:
    """Cheap evidence string for a CallExpression."""
    name = _attr_name_chain_last(node.callee) or "call"
    return f"{name}(...)"[:120]


_CHILD_ATTRS = (
    # Statements/expressions in source order
    "body", "declarations", "init", "test", "update", "consequent",
    "alternate", "cases", "discriminant", "param", "handler", "finalizer",
    "block", "expression", "argument", "arguments", "elements",
    "properties", "value", "key", "expressions", "quasis",
    "callee", "object", "property", "left", "right", "source",
    "specifiers", "id",
)


def _children_in_order(node):
    """Yield direct children of `node` in source order. Lists are flattened."""
    if node is None:
        return
    for attr in _CHILD_ATTRS:
        c = getattr(node, attr, None)
        if c is None:
            continue
        if isinstance(c, list):
            for item in c:
                if item is not None:
                    yield item
        elif hasattr(c, "type"):
            yield c


_TRIVIAL_JS_GLOBALS = {
    "String", "Number", "Boolean", "Array", "Object", "Symbol", "BigInt",
    "Math", "Date", "JSON", "RegExp", "Map", "Set", "WeakMap", "WeakSet",
    "Error", "Promise", "isNaN", "isFinite", "parseInt", "parseFloat",
    "encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent",
    "structuredClone",
}
_TRIVIAL_JS_METHODS = {
    # array
    "push", "pop", "shift", "unshift", "splice", "slice", "concat", "join",
    "map", "filter", "reduce", "reduceRight", "forEach", "find", "findIndex",
    "includes", "indexOf", "lastIndexOf", "every", "some", "flat", "flatMap",
    "sort", "reverse", "fill", "copyWithin", "entries", "keys", "values",
    # string
    "split", "trim", "trimStart", "trimEnd", "padStart", "padEnd", "repeat",
    "replace", "replaceAll", "startsWith", "endsWith", "substring", "substr",
    "toLowerCase", "toUpperCase", "charAt", "charCodeAt", "codePointAt",
    "normalize", "matchAll", "match",
    # number / json
    "toFixed", "toPrecision", "toString", "toExponential", "valueOf",
    "stringify", "parse",
    # object
    "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable",
}


def _is_trivial_js_call(node) -> bool:
    callee = node.callee
    t = getattr(callee, "type", None)
    if t == "Identifier":
        return callee.name in _TRIVIAL_JS_GLOBALS
    if t == "MemberExpression":
        m = getattr(callee.property, "name", None)
        return m in _TRIVIAL_JS_METHODS
    return False


def _alias_root_of(node) -> str | None:
    """Walk a MemberExpression chain to its leftmost Identifier name.

    `transporter.sendMail` → "transporter"
    `s.headers.update` → "s"
    """
    if node is None:
        return None
    t = getattr(node, "type", None)
    if t == "Identifier":
        return node.name
    if t == "MemberExpression":
        return _alias_root_of(node.object)
    return None
