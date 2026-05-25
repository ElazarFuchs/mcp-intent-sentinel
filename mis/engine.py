"""Top-level orchestrator.

`scan(source)` is the single entry point:
    1. extract(source) → ExtractedSource
    2. run Python + JS + manifest analyzers
    3. detect I/O-capable imports (input to shallow-verdict classifier rule)
    4. classify intent
    5. return ScanResult (verdict, triage, findings, rule hits, detected tools)
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from mis.analyzers import js_ast as js_analyzer       # v0.1.4: real AST analyzer
from mis.analyzers import manifest as manifest_analyzer
from mis.analyzers import python as python_analyzer
from mis.analyzers.types import ToolProfile
from mis.classifier.intent import RuleHit, classify
from mis.extractors import extract
from mis.findings import ScanResult


# v0.1.5: I/O-capable detection moved from a narrow substring list to AST-based
# import scanning. The v0.1.4 list missed Octokit, googleapis, kubernetes-client,
# prisma, and the whole long-tail of npm packages — which caused server-github
# (26 tools, 0 behavior) to verdict BENIGN instead of SHALLOW. The leak was
# documented by the user: "the +12pp benign jump is partially fake."
#
# New definition: a source has I/O capability if ANY import in any source file
# refers to a non-built-in package. Conservative on purpose — if a real server
# imports anything beyond stdlib (Python) / Node-builtin (JS), MIS should not
# claim "benign" on the basis of zero behavior extracted from its tools.
#
# Pure-calculator servers (calc_python: only `from mcp.server.fastmcp import FastMCP`)
# WILL still verdict benign — `mcp` package is in their imports, but combined
# with extracted-behavior=0 the classifier path matters too: tools_with_behavior
# is the better discriminator. v0.1.5 leans on BOTH signals (see classifier
# rule update for the new logic).


# Python stdlib module names (top-level packages). Python 3.10+ exposes this directly.
_PY_STDLIB = set(getattr(sys, "stdlib_module_names", set())) | {
    # belt-and-suspenders for portability across Python versions
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii", "bisect",
    "calendar", "collections", "concurrent", "contextlib", "copy", "csv", "ctypes",
    "dataclasses", "datetime", "decimal", "enum", "errno", "fnmatch", "functools",
    "gc", "getopt", "getpass", "glob", "gzip", "hashlib", "heapq", "html", "http",
    "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword",
    "logging", "math", "multiprocessing", "operator", "os", "pathlib", "pickle",
    "platform", "posixpath", "queue", "random", "re", "secrets", "select",
    "shutil", "signal", "site", "socket", "sqlite3", "ssl", "stat", "string",
    "struct", "subprocess", "sys", "sysconfig", "tempfile", "textwrap", "threading",
    "time", "timeit", "tokenize", "traceback", "types", "typing", "unicodedata",
    "unittest", "urllib", "uuid", "warnings", "weakref", "xml", "zipfile", "zlib",
    "tomllib",
}
# Stdlib modules that ARE I/O-capable. We still flag these as I/O even though they're stdlib.
_PY_STDLIB_IO = {
    "urllib", "http", "socket", "ssl", "smtplib", "ftplib", "telnetlib", "imaplib",
    "subprocess", "os", "shutil", "asyncio", "selectors", "select", "io", "tempfile",
}

# Node.js built-in modules (the user-perceived "stdlib" of JS). These are
# considered safe to NOT count as external — but several of them are still I/O.
_JS_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "perf_hooks", "process", "punycode",
    "querystring", "readline", "repl", "stream", "string_decoder",
    "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm",
    "wasi", "worker_threads", "zlib",
}
# Built-ins that ARE I/O-capable. Importing them means the server CAN do I/O.
_JS_BUILTIN_IO = {
    "child_process", "cluster", "dgram", "dns", "fs", "fs/promises", "http",
    "http2", "https", "net", "os", "stream", "tls", "url", "worker_threads",
}


def _has_io_capable_imports(root: Path) -> bool:
    """True iff any source file under root imports an I/O-capable module.

    v0.1.5 definition: AST-based scan. A source is I/O-capable if it imports
    either (a) a non-stdlib / non-Node-builtin module — ANY external package
    means there's something MIS doesn't understand statically — or (b) a
    stdlib / builtin module that's itself I/O-capable (http, fs, subprocess, etc.).

    Falls back to a narrow substring scan for files that fail to parse — we
    never want a bad file to silently flip the verdict.
    """
    for path in _iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if path.suffix == ".py":
            try:
                tree = ast.parse(text, filename=str(path))
            except SyntaxError:
                if _io_capable_substring_fallback(text):
                    return True
                continue
            if _py_imports_anything_external_or_io(tree):
                return True
        else:  # .js / .mjs / .cjs / .jsx / .ts / .tsx
            if _js_imports_anything_external_or_io(text):
                return True
    return False


def _iter_source_files(root: Path):
    suffixes = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
    skip = {"node_modules", ".git", "__pycache__", "dist_legacy", "build",
            ".venv", "venv", ".tox", ".pytest_cache"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if any(part in skip for part in path.parts):
            continue
        yield path


def _py_imports_anything_external_or_io(tree: ast.Module) -> bool:
    """True iff the Python module imports any non-stdlib package, OR a stdlib
    package that's itself I/O-capable (http, socket, subprocess, etc.)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in _PY_STDLIB:
                    return True  # external package
                if top in _PY_STDLIB_IO:
                    return True  # stdlib I/O
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import — same package, treat as benign here
                continue
            top = (node.module or "").split(".")[0]
            if not top:
                continue
            if top not in _PY_STDLIB:
                return True
            if top in _PY_STDLIB_IO:
                return True
    return False


# Regexes for JS import / require detection. AST would be cleaner but we'd
# need to parse every JS file (cost) and handle parse failures gracefully —
# at this level we only care about the import source string, which is
# pleasingly amenable to a regex. The regex is conservative: we only match
# the source string and only check string literals.
_JS_IMPORT_RE = re.compile(
    r"""(?:
        import\s+ (?:[^'"]*?\s+from\s+)? ['"]([^'"]+)['"]   # import ... from 'X'  /  import 'X'
        |
        require\s*\(\s*['"]([^'"]+)['"]\s*\)               # require('X')
    )""",
    re.VERBOSE,
)


def _js_imports_anything_external_or_io(source: str) -> bool:
    """True iff the JS/TS file imports an external package, or a Node-builtin
    that's itself I/O-capable."""
    for m in _JS_IMPORT_RE.finditer(source):
        spec = (m.group(1) or m.group(2) or "").strip()
        if not spec:
            continue
        # Strip `node:` prefix and trailing path segments
        if spec.startswith("node:"):
            spec = spec[len("node:"):]
        # Relative imports — same package
        if spec.startswith("."):
            continue
        # For namespaced packages (@scope/name), take the first segment as identity
        if spec.startswith("@"):
            return True  # any @scope package is external
        head = spec.split("/")[0]
        if head not in _JS_BUILTINS:
            return True  # external npm package
        if head in _JS_BUILTIN_IO or spec in _JS_BUILTIN_IO:
            return True
    return False


def _io_capable_substring_fallback(text: str) -> bool:
    """Tiny safety net for files that failed to AST-parse. Conservative — only
    fires on the most universal IO indicators so we don't accidentally taint
    a benign comment."""
    return any(tok in text for tok in (
        "import requests", "import httpx", "import aiohttp", "import urllib",
        "import socket", "import subprocess", "import http", "import smtplib",
        "from requests", "from httpx", "from aiohttp", "from urllib",
    ))


def scan(source: str) -> tuple[ScanResult, list[RuleHit]]:
    """Scan an MCP server package by source spec.

    Returns (result, rule_hits). Rule hits are returned alongside the result
    so the report can render them in priority order — they are NOT stored on
    ScanResult itself to keep the JSON shape stable for CI consumers.
    """
    with extract(source) as src:
        result, hits = scan_directory(src.root, source=source)
    return result, hits


def scan_directory(root: Path, *, source: str | None = None) -> tuple[ScanResult, list[RuleHit]]:
    """Scan an already-extracted directory. Used by tests and by `extract+scan`."""
    if source is None:
        source = f"file://{root.resolve()}"
    result = ScanResult(root=root.resolve(), source=source)

    py_findings, py_tools = python_analyzer.analyze(root)
    js_findings, js_tools = js_analyzer.analyze(root)
    mf_findings = manifest_analyzer.analyze(root)

    result.findings.extend(py_findings)
    result.findings.extend(js_findings)
    result.findings.extend(mf_findings)

    tools: list[ToolProfile] = py_tools + js_tools
    # Surface what we identified in the result so JSON consumers (and the user
    # reading the table) can tell the difference between "we saw 0 tools" and
    # "we saw 4 tools and none looked malicious". This was the field-test
    # signal that a 'benign' verdict could be hiding a coverage gap.
    result.tools = tools
    # Capability hint for the shallow-verdict rule: do any of the source files
    # import an I/O-capable module? If yes and we still extracted zero behavior
    # from any tool, the analyzer is shallow on this server, not the server idle.
    result.io_capable_imports_present = _has_io_capable_imports(root)
    # v0.1.13 — extract host claims from package.json / pyproject.toml so
    # r1.secret_to_request can downgrade when a secret-bearing net call
    # goes to a host the package self-declares.
    result.host_claims = manifest_analyzer.extract_host_claims(root)
    hits = classify(result, tools)
    return result, hits
