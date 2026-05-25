"""Finding records emitted by the analyzer + intent classifier.

A Finding is a *single observation* over a specific file/line. The intent
classifier consumes a list of Findings and emits one Verdict per server.

Borrowed shape from aci/scanner/findings.py with one important change:
each Finding carries an `owasp` tag mapping it to the OWASP MCP Top 10
taxonomy. That mapping is the language CISOs are starting to learn — speaking
it from day one is part of the wedge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Literal


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MED = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls.__members__[s.upper()]

    def __str__(self) -> str:
        return self.name.lower()


# OWASP MCP Top 10 (beta, 2026). Source: owasp.org/www-project-mcp-top-10
# We tag only the categories we have rules for; the rest exist as constants
# so the verdict report can refer to them in "not covered in v0.1" disclosures.
class OwaspMcp:
    MCP01 = "MCP01:PromptInjection"
    MCP02 = "MCP02:PrivilegeEscalation"
    MCP03 = "MCP03:ToolPoisoning"
    MCP04 = "MCP04:SupplyChain"
    MCP05 = "MCP05:CommandInjectionExecution"
    MCP06 = "MCP06:IntentFlowSubversion"
    MCP07 = "MCP07:InsecureDeployment"
    MCP08 = "MCP08:AuthFailures"
    MCP09 = "MCP09:DataExposure"
    MCP10 = "MCP10:OverreliantAutomation"


# Verdict produced by the intent classifier over the full set of findings.
#
# Reading the verdict (this is the contract a CISO is meant to internalize):
#   benign      = tools were detected AND the analyzer extracted some behavior
#                 from at least one of them AND no intent rule fired
#                 (bounded by L4: novel attack shapes pass through)
#   shallow     = tools were detected AND every tool's behavior set is EMPTY,
#                 yet the source imports I/O-capable modules. MIS recognized
#                 the tools by name but failed to follow what they DO. Treat
#                 as "analyzed-but-shallow" — manual review of the call_tool
#                 dispatch / helper structure required.
#   unknown     = no tools were detected at all. SDK pattern not recognized
#                 (L13), or the source root is wrong, or all files failed
#                 to parse.
#   suspicious  = an intent rule fired with low/medium confidence.
#   malicious   = an intent rule fired with high confidence.
#
# Rank for --fail-on-verdict: benign < shallow < unknown < suspicious < malicious.
# `shallow` ranks above `benign` because it explicitly admits incomplete
# coverage. It ranks BELOW `unknown` because at least some tool names were
# extracted — slightly more analyzer engagement than a complete blank.
Verdict = Literal["benign", "shallow", "unknown", "suspicious", "malicious"]


@dataclass(frozen=True)
class Finding:
    """A single observation in one file. Multiple findings combine into a Verdict.

    Fields:
        rule        — stable id for the static rule that fired (e.g. "py.exfil.urllib_with_env")
        owasp       — OWASP MCP Top 10 tag (see OwaspMcp)
        severity    — INFO..CRITICAL (raw signal strength, BEFORE intent fusion)
        file        — absolute path to the source file where the rule fired
        line        — 1-based line number; 0 if not applicable (e.g. package-level finding)
        evidence    — short snippet (<120 chars) — what the rule actually saw
        detail      — full human-readable explanation suitable for the report

    Severity here is the *signal* strength of one observation, not the
    classifier's verdict. The classifier turns these into a verdict via
    rules in mis.classifier.intent.
    """
    rule: str
    owasp: str
    severity: Severity
    file: Path
    line: int
    evidence: str
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "owasp": self.owasp,
            "severity": str(self.severity),
            "file": str(self.file),
            "line": self.line,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class ScanResult:
    """Result of static analysis over a single MCP server package.

    Contains:
        root        — the extracted source root that was analyzed
        source      — the original source spec passed to the CLI (e.g. "npm:foo", "file:///tmp/bar")
        findings    — list of raw observations from analyzers
        tools       — list of MCP tools the analyzers identified (typed as a list[Any]
                      since the concrete ToolProfile type lives in analyzers.types and
                      we want to avoid a circular import). Empty list means MIS did NOT
                      recognize any tool registration in the source — see Verdict
                      docstring for why this matters.
        verdict     — set by classifier.intent.classify(); None until classified
        verdict_reason — human-readable explanation of the verdict
        verdict_confidence — 0.0..1.0 confidence in the verdict
        triage      — ordered list of the top-N findings to act on first
    """
    root: Path
    source: str
    findings: list[Finding] = field(default_factory=list)
    tools: list = field(default_factory=list)  # list[ToolProfile]; loose typing avoids import cycle
    # True iff some Python/JS file in the source imports an I/O-capable module
    # (httpx, requests, aiohttp, urllib, http, socket, nodemailer, axios, ...).
    # Used by the classifier to distinguish "benign because nothing to analyze"
    # (calculator) from "shallow because analyzer didn't follow the I/O".
    io_capable_imports_present: bool = False
    # v0.1.13 — host claims extracted from package.json / pyproject.toml.
    # Substrings the package self-declares as its target hosts (package
    # name parts, homepage, repository URL). r1.secret_to_request consults
    # these to downgrade verdict when the net-call URL host overlaps a
    # claim (legit API client talking to its declared service). Empty list
    # means no claims could be extracted (file:// source / no manifest).
    host_claims: list[str] = field(default_factory=list)
    verdict: Verdict | None = None
    verdict_reason: str = ""
    verdict_confidence: float = 0.0
    triage: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def by_owasp(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.owasp, []).append(f)
        return out

    def by_rule(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.rule, []).append(f)
        return out

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "root": str(self.root),
            "verdict": self.verdict or "unclassified",
            "verdict_reason": self.verdict_reason,
            "verdict_confidence": round(self.verdict_confidence, 2),
            "max_severity": str(self.max_severity),
            "tools_detected": len(self.tools),
            "tool_names": [getattr(t, "name", "?") for t in self.tools],
            "tools_with_behavior": sum(1 for t in self.tools if getattr(t, "behavior", None)),
            "io_capable_imports_present": self.io_capable_imports_present,
            "triage": [f.to_dict() for f in self.triage],
            "findings": [f.to_dict() for f in self.findings],
            "by_owasp": {k: [f.to_dict() for f in v] for k, v in self.by_owasp().items()},
        }
