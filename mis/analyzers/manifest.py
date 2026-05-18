"""Manifest analyzer — covers MCP04 (Supply Chain) signals at package level.

What this catches:
1. npm `package.json` lifecycle scripts (preinstall/postinstall/prepublish)
   that fetch+exec from the network — classic supply-chain dropper pattern.
2. Python `pyproject.toml` / `setup.py` postinstall via setuptools cmdclass
   (deferred to LIMITATIONS L7 — covers obvious patterns only).
3. Typosquat heuristic against a small list of well-known MCP server names.

OUT OF SCOPE for v0.1 (LIMITATIONS L6, L7):
- Dependency-tree analysis: we look at direct deps only, not transitive.
- Lockfile inspection / dependency pinning gaps.
- Recursive scan of vendored packages.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from mis.findings import Finding, OwaspMcp, Severity


# Small set of well-known MCP server / org names. v0.1 list — to be expanded
# from the MCP registry index in v0.2. Sourced from anthropic.com / modelcontextprotocol.io.
_KNOWN_MCP_NAMES = {
    # Anthropic-published
    "mcp-server-git", "mcp-server-filesystem", "mcp-server-github",
    "mcp-server-postgres", "mcp-server-puppeteer", "mcp-server-slack",
    "mcp-server-time", "mcp-server-memory", "mcp-server-fetch",
    "mcp-server-sqlite", "mcp-server-everything", "mcp-server-brave-search",
    # Common community / commercial
    "postmark-mcp", "stripe-mcp", "linear-mcp", "notion-mcp", "atlassian-mcp",
    "modelcontextprotocol", "fastmcp",
}

# Lifecycle scripts that npm runs as part of `npm install` (no flags needed)
_AUTO_RUN_NPM_SCRIPTS = {
    "preinstall", "install", "postinstall",
    "preprepare", "prepare", "postprepare",
    "prepublish", "prepublishOnly",
}

# Patterns inside a script that mean "fetch and exec"
_FETCH_EXEC_PATTERNS = (
    re.compile(r"(?:curl|wget)\s+.*?\|\s*(?:sh|bash|zsh|python|node)\b"),
    re.compile(r"(?:curl|wget)\s+[^;]*;\s*(?:sh|bash|zsh|python|node)\b"),
    re.compile(r"(?:curl|wget)\s+.*\s+-o\s+\S+.*;\s*(?:bash|sh)\s+\S+"),
)
# Patterns that mean "send something to a remote URL"
_BEACON_PATTERNS = (
    re.compile(r"(?:curl|wget)\s+.*--data\b"),
    re.compile(r"(?:curl|wget)\s+.*-X\s+POST\b"),
)


def analyze(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_scan_package_json(root))
    findings.extend(_scan_pyproject(root))
    return findings


def _scan_package_json(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for pkg_path in root.rglob("package.json"):
        if any(part == "node_modules" for part in pkg_path.parts):
            continue
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        name = data.get("name", "")
        scripts = data.get("scripts") or {}
        if not isinstance(scripts, dict):
            scripts = {}

        # 1. Lifecycle dropper / beacon
        for script_name, script in scripts.items():
            if not isinstance(script, str) or script_name not in _AUTO_RUN_NPM_SCRIPTS:
                continue
            if any(p.search(script) for p in _FETCH_EXEC_PATTERNS):
                findings.append(Finding(
                    rule="manifest.npm.lifecycle_dropper",
                    owasp=OwaspMcp.MCP04,
                    severity=Severity.CRITICAL,
                    file=pkg_path,
                    line=0,
                    evidence=f'"{script_name}": {script[:100]}',
                    detail=(
                        f'npm lifecycle script "{script_name}" downloads and executes remote code '
                        f"({script[:140]}). This runs automatically on `npm install` — the user does not get a prompt."
                    ),
                ))
            elif any(p.search(script) for p in _BEACON_PATTERNS):
                findings.append(Finding(
                    rule="manifest.npm.lifecycle_beacon",
                    owasp=OwaspMcp.MCP04,
                    severity=Severity.HIGH,
                    file=pkg_path,
                    line=0,
                    evidence=f'"{script_name}": {script[:100]}',
                    detail=(
                        f'npm lifecycle script "{script_name}" makes an HTTP POST during install. '
                        "Often used for install-time data exfiltration (machine info, env)."
                    ),
                ))

        # 2. Typosquat against known MCP names
        if name:
            for known in _KNOWN_MCP_NAMES:
                if name == known:
                    break  # exact match, not a squat
                if _is_typosquat(name, known):
                    findings.append(Finding(
                        rule="manifest.typosquat",
                        owasp=OwaspMcp.MCP04,
                        severity=Severity.HIGH,
                        file=pkg_path,
                        line=0,
                        evidence=f'name="{name}" close to "{known}"',
                        detail=(
                            f"Package name '{name}' is one edit away from the well-known MCP server "
                            f"'{known}'. Typosquat candidate — verify the publisher matches the expected one."
                        ),
                    ))
                    break
    return findings


def _scan_pyproject(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("pyproject.toml"):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            continue
        proj = data.get("project") or {}
        name = proj.get("name", "")
        if name:
            for known in _KNOWN_MCP_NAMES:
                if name == known:
                    break
                if _is_typosquat(name, known):
                    findings.append(Finding(
                        rule="manifest.typosquat",
                        owasp=OwaspMcp.MCP04,
                        severity=Severity.HIGH,
                        file=path,
                        line=0,
                        evidence=f'name="{name}" close to "{known}"',
                        detail=(
                            f"Package name '{name}' is one edit away from the well-known MCP server "
                            f"'{known}'. Typosquat candidate."
                        ),
                    ))
                    break

    # setup.py dropper heuristic — look for fetch+exec in any setup.py
    for setup in root.rglob("setup.py"):
        try:
            src = setup.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(p.search(src) for p in _FETCH_EXEC_PATTERNS):
            findings.append(Finding(
                rule="manifest.pypi.setup_dropper",
                owasp=OwaspMcp.MCP04,
                severity=Severity.CRITICAL,
                file=setup,
                line=1,
                evidence="setup.py contains shell fetch+exec",
                detail=(
                    "setup.py contains a shell fetch+exec pattern. setup.py executes at `pip install` "
                    "time — the user does not get a prompt before this runs."
                ),
            ))
    return findings


def _is_typosquat(candidate: str, target: str) -> bool:
    """Return True iff `candidate` is suspiciously close to `target`.

    Heuristic — covers the common squatting tactics:
    - normalized equality (hyphen / underscore / dot collapse)
    - one-char substitution, insertion, deletion (Levenshtein ≤ 1)
    - adjacent transposition (Damerau-Levenshtein ≤ 1)
    """
    if not candidate or candidate == target:
        return False
    a = candidate.lower()
    b = target.lower()
    # Normalize separators
    a_norm = a.replace("_", "-").replace(".", "-")
    b_norm = b.replace("_", "-").replace(".", "-")
    if a_norm == b_norm:
        return True
    if abs(len(a) - len(b)) > 2:
        return False
    if _edit_distance_at_most(a, b, 1):
        return True
    # Single adjacent transposition (Damerau)
    if _is_adjacent_transposition(a, b):
        return True
    return False


def _is_adjacent_transposition(a: str, b: str) -> bool:
    """True iff `a` and `b` differ by exactly one swap of adjacent characters."""
    if len(a) != len(b) or a == b:
        return False
    # Find first differing position
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    if i >= len(a) - 1:
        return False
    # Check swap of positions i and i+1
    if a[i] == b[i + 1] and a[i + 1] == b[i]:
        # Rest must match
        return a[i + 2:] == b[i + 2:]
    return False


def _edit_distance_at_most(a: str, b: str, k: int) -> bool:
    """Return True iff Levenshtein(a, b) <= k. Optimized for tiny k."""
    if abs(len(a) - len(b)) > k:
        return False
    if a == b:
        return True
    if k == 0:
        return False
    # k == 1: one insert / delete / substitute
    # Try substitution
    if len(a) == len(b):
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        if diffs <= 1:
            return True
    # Try insertion / deletion (delete a char from the longer one)
    long, short = (a, b) if len(a) > len(b) else (b, a)
    if len(long) - len(short) != 1:
        return False
    for i in range(len(long)):
        if long[:i] + long[i+1:] == short:
            return True
    return False
