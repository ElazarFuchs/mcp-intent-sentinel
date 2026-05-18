"""Unit tests for the intent classifier (rule level)."""
from __future__ import annotations

from pathlib import Path

from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.classifier.intent import classify
from mis.findings import Finding, OwaspMcp, ScanResult, Severity


def _empty(root: Path = Path("/tmp/x")) -> ScanResult:
    return ScanResult(root=root, source=str(root))


def test_empty_classifies_unknown_not_benign() -> None:
    """0 tools + 0 findings = MIS didn't understand the source. Must NOT be benign.

    This was the field-test miss in the user's manual run against mcp-server-fetch
    and modelcontextprotocol/servers: both returned 'benign' on silence. A CISO
    can't tell 'this server is safe' from 'MIS didn't recognize the SDK' if both
    show the same verdict.
    """
    r = _empty()
    hits = classify(r, tools=[])
    assert r.verdict == "unknown"
    assert hits == []
    assert r.verdict_confidence == 0.0  # explicitly: no claim made


def test_tool_with_pure_compute_is_benign() -> None:
    """A tool whose body was examined and tagged PURE_COMPUTE → benign.

    v0.1.5: the analyzer adds PURE_COMPUTE when it walked a tool body and saw
    no I/O of any kind. This counts as 'behavior extracted' so the classifier
    routes to benign rather than shallow.
    """
    from mis.analyzers.types import ToolProfile, BehaviorSignal
    r = _empty()
    tool = ToolProfile(name="echo", declared_description="echo input",
                       declared_intent="unknown",
                       behavior={BehaviorSignal.PURE_COMPUTE})
    classify(r, tools=[tool])
    assert r.verdict == "benign"
    assert r.verdict_confidence > 0.0


def test_tools_detected_but_empty_behavior_is_shallow() -> None:
    """The v0.1.5 leak fix: tools detected but zero behavior extracted = shallow.

    Previously this case routed to benign when no I/O-capable imports were
    detected (which a narrow substring list missed for Octokit, etc.). v0.1.5
    drops the io_capable requirement and trusts the per-tool behavior check.
    """
    from mis.analyzers.types import ToolProfile
    r = _empty()
    tool = ToolProfile(name="t", declared_description="d",
                       declared_intent="unknown", behavior=set())
    classify(r, tools=[tool])
    assert r.verdict == "shallow", r.verdict_reason


def test_secret_to_request_is_malicious() -> None:
    r = _empty()
    r.findings.append(Finding(
        rule="py.exfil.secret_in_request", owasp=OwaspMcp.MCP09,
        severity=Severity.CRITICAL, file=Path("x.py"), line=1, evidence="",
    ))
    hits = classify(r, tools=[])
    assert r.verdict == "malicious"
    assert any("secret_to_request" in h.rule_id for h in hits)


def test_bcc_injection_is_malicious() -> None:
    r = _empty()
    r.findings.append(Finding(
        rule="js.email.bcc_injection", owasp=OwaspMcp.MCP09,
        severity=Severity.CRITICAL, file=Path("x.js"), line=1, evidence="",
    ))
    classify(r, tools=[])
    assert r.verdict == "malicious"


def test_intent_mismatch_two_signals_is_malicious() -> None:
    r = _empty()
    t1 = ToolProfile(name="add", declared_description="Add two numbers",
                     declared_intent="math",
                     behavior={BehaviorSignal.NET_HTTP_OUTBOUND, BehaviorSignal.NET_HOST_LITERAL})
    t2 = ToolProfile(name="multiply", declared_description="Multiply two numbers",
                     declared_intent="math",
                     behavior={BehaviorSignal.EXEC_SHELL})
    classify(r, tools=[t1, t2])
    assert r.verdict == "malicious"


def test_single_intent_mismatch_is_suspicious() -> None:
    r = _empty()
    t = ToolProfile(name="add", declared_description="Add two numbers",
                    declared_intent="math",
                    behavior={BehaviorSignal.NET_HTTP_OUTBOUND})
    classify(r, tools=[t])
    assert r.verdict == "suspicious"


def test_typosquat_alone_is_suspicious_not_malicious() -> None:
    r = _empty()
    r.findings.append(Finding(
        rule="manifest.typosquat", owasp=OwaspMcp.MCP04,
        severity=Severity.HIGH, file=Path("package.json"), line=0,
        evidence='name="postmrak-mcp" close to "postmark-mcp"',
    ))
    classify(r, tools=[])
    # Typosquat alone should NOT escalate to malicious — that's an FP risk
    assert r.verdict == "suspicious"


def test_triage_caps_at_three() -> None:
    r = _empty()
    for i in range(10):
        r.findings.append(Finding(
            rule=f"r{i}", owasp=OwaspMcp.MCP03,
            severity=Severity.HIGH, file=Path("x.py"), line=i, evidence="",
        ))
    classify(r, tools=[])
    assert len(r.triage) == 3


def test_triage_orders_by_severity() -> None:
    r = _empty()
    f_low = Finding(rule="a", owasp=OwaspMcp.MCP03, severity=Severity.LOW,
                    file=Path("a"), line=1, evidence="")
    f_crit = Finding(rule="b", owasp=OwaspMcp.MCP09, severity=Severity.CRITICAL,
                     file=Path("b"), line=2, evidence="")
    r.findings = [f_low, f_crit]
    classify(r, tools=[])
    assert r.triage[0].severity == Severity.CRITICAL


def test_classifier_monotonic_up() -> None:
    """A finding that is malicious-grade cannot be de-escalated by adding
    benign-shaped findings.
    """
    r = _empty()
    r.findings.append(Finding(
        rule="py.exfil.secret_in_request", owasp=OwaspMcp.MCP09,
        severity=Severity.CRITICAL, file=Path("x.py"), line=1, evidence="",
    ))
    classify(r, tools=[])
    assert r.verdict == "malicious"

    # Add 10 "benign" tool profiles — verdict must NOT drop
    r2 = _empty()
    r2.findings.append(Finding(
        rule="py.exfil.secret_in_request", owasp=OwaspMcp.MCP09,
        severity=Severity.CRITICAL, file=Path("x.py"), line=1, evidence="",
    ))
    benign_tools = [
        ToolProfile(name=f"t{i}", declared_description="benign",
                    declared_intent="format", behavior=set())
        for i in range(10)
    ]
    classify(r2, tools=benign_tools)
    assert r2.verdict == "malicious"
