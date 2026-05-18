"""Rich-table and JSON rendering of a ScanResult + RuleHits.

Output discipline (from spec § 5.2):
- Verdict + confidence at the top — the one thing a CISO reads first.
- Top 3 triage findings next, with file:line and one-line explanation each.
- OWASP MCP Top 10 breakdown — categories CISOs already speak.
- Full findings table at the bottom (collapsible for the eyeballer).
- Reason for the verdict in plain English. No black box.
"""
from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mis.classifier.intent import RuleHit
from mis.findings import ScanResult, Severity, Verdict


_VERDICT_COLOR: dict[Verdict, str] = {
    "malicious": "red bold",
    "suspicious": "yellow bold",
    "benign": "green",
    # Both `unknown` and `shallow` use non-green colors so a glance at the
    # terminal does NOT confuse "MIS doesn't fully understand this" with
    # "this is safe". Magenta + cyan stand out from our other output.
    "unknown": "magenta bold",
    "shallow": "cyan bold",
}
_SEV_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MED: "yellow",
    Severity.LOW: "white",
    Severity.INFO: "dim",
}


def render_table(result: ScanResult, hits: list[RuleHit], console: Console | None = None) -> None:
    console = console or Console()

    verdict = result.verdict or "unclassified"
    verdict_color = _VERDICT_COLOR.get(verdict, "white")
    title = Text(f"MCP Intent Sentinel — verdict: ", style="bold")
    title.append(verdict.upper(), style=verdict_color)
    title.append(f"  (confidence {result.verdict_confidence:.2f})", style="dim")

    console.rule(title)
    console.print(f"[dim]Source:[/dim] {result.source}")
    console.print(f"[dim]Root:[/dim]   {result.root}")
    # Tools-detected line: makes coverage gaps visible at-a-glance. If this
    # says "0 tools", the verdict cannot be trusted regardless of color.
    tool_count = len(result.tools)
    if tool_count == 0:
        console.print(f"[dim]Tools detected:[/dim] [magenta bold]0[/magenta bold] [dim](analyzer did not understand the source)[/dim]")
    else:
        names = ", ".join(getattr(t, "name", "?") for t in result.tools[:8])
        more = "" if tool_count <= 8 else f" (+{tool_count - 8} more)"
        console.print(f"[dim]Tools detected:[/dim] {tool_count} [dim]({names}{more})[/dim]")
    console.print()
    console.print(Panel(result.verdict_reason or "(no reason given)", title="Reason", border_style=verdict_color))

    if result.triage:
        _render_triage(result, console)
    if hits:
        _render_rule_hits(hits, console)
    _render_owasp_breakdown(result, console)
    if result.findings:
        _render_full_findings(result, console)
    elif verdict in {"unknown", "shallow"}:
        # Don't print a green "no findings" message — it's misleading for both
        # epistemic verdicts. The Reason panel already explained the situation.
        pass
    else:
        console.print("[green]No findings produced by static analysis.[/green]")
    _render_footer(result, console)


def _render_triage(result: ScanResult, console: Console) -> None:
    console.print()
    console.rule("[bold]Top 3 findings to act on first[/bold]", align="left")
    for i, f in enumerate(result.triage, 1):
        sev_color = _SEV_COLOR[f.severity]
        rel = _short_path(f.file, result.root)
        console.print(
            f"{i}. [{sev_color}]{str(f.severity).upper():<8}[/{sev_color}] "
            f"[bold]{f.rule}[/bold]  ({f.owasp})  {rel}:{f.line}"
        )
        if f.detail:
            console.print(f"   [dim]{f.detail}[/dim]")
        if f.evidence:
            console.print(f"   [italic]-> {f.evidence}[/italic]")


def _render_rule_hits(hits: list[RuleHit], console: Console) -> None:
    console.print()
    console.rule("[bold]Why the verdict[/bold]", align="left")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rule")
    table.add_column("Verdict")
    table.add_column("Confidence", justify="right")
    table.add_column("Reason")
    for h in hits:
        color = _VERDICT_COLOR.get(h.verdict, "white")
        table.add_row(
            h.rule_id,
            f"[{color}]{h.verdict}[/{color}]",
            f"{h.confidence:.2f}",
            h.reason,
        )
    console.print(table)


def _render_owasp_breakdown(result: ScanResult, console: Console) -> None:
    by_owasp = result.by_owasp()
    if not by_owasp:
        return
    console.print()
    console.rule("[bold]OWASP MCP Top 10 breakdown[/bold]", align="left")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_column("Max severity")
    for cat in sorted(by_owasp):
        fs = by_owasp[cat]
        max_sev = max(f.severity for f in fs)
        table.add_row(cat, str(len(fs)), f"[{_SEV_COLOR[max_sev]}]{str(max_sev)}[/{_SEV_COLOR[max_sev]}]")
    console.print(table)


def _render_full_findings(result: ScanResult, console: Console) -> None:
    console.print()
    console.rule("[bold]All findings[/bold]", align="left")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("OWASP")
    table.add_column("File")
    table.add_column("Line", justify="right")
    table.add_column("Evidence")
    for f in sorted(result.findings, key=lambda x: -int(x.severity)):
        rel = _short_path(f.file, result.root)
        table.add_row(
            f"[{_SEV_COLOR[f.severity]}]{str(f.severity)}[/{_SEV_COLOR[f.severity]}]",
            f.rule,
            f.owasp,
            rel,
            str(f.line),
            f.evidence[:60],
        )
    console.print(table)


def _render_footer(result: ScanResult, console: Console) -> None:
    console.print()
    msg = (
        "[dim]Read LIMITATIONS.md before reaching conclusions: "
        "a 'benign' verdict reflects what v0.1 rules cover (L4), "
        "not a proof of safety.[/dim]"
    )
    console.print(msg)


def render_json(result: ScanResult, hits: list[RuleHit]) -> str:
    """JSON output for CI consumers. Shape is stable across v0.1.x."""
    data: dict[str, object] = result.to_dict()
    data["rule_hits"] = [
        {
            "rule_id": h.rule_id,
            "verdict": h.verdict,
            "confidence": round(h.confidence, 2),
            "reason": h.reason,
        }
        for h in hits
    ]
    return json.dumps(data, indent=2, default=str)


def _short_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
