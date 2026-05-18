"""`mis` CLI — single subcommand for v0.1.

    mis scan <source>      # verdict + triage on one MCP server package
    mis scan --json ...    # machine-readable for CI

A future v0.2 adds:
    mis diff <prev> <next> # semantic rug-pull detection (L8)
    mis ingest <registry>  # bulk scan across an MCP registry index (L9)
"""
from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from mis import __version__
from mis.engine import scan as _scan
from mis.extractors import ExtractionError
from mis.findings import Severity
from mis.report import render_json, render_table


# Force UTF-8 on stdout where supported (Windows defaults to a Hebrew/CP1255
# codepage on this user's machine, which can't encode arrows or zero-width
# code points that show up in tool descriptions).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, OSError):
    pass


app = typer.Typer(
    name="mis",
    help=(
        "MCP Intent Sentinel — verdict engine for MCP servers. "
        "Static analysis + intent classification with OWASP MCP Top 10 mapping."
    ),
    no_args_is_help=True,
)
# legacy_windows=False enables ANSI mode, avoiding the rich Win32 console
# path that crashes on non-CP1255 code points.
console = Console(legacy_windows=False)


@app.command()
def scan(
    source: str = typer.Argument(
        ...,
        help=(
            "Source spec. Examples: ./path/to/server | file:///abs/path "
            "| github:owner/repo[#ref] | npm:pkg[@ver] | pypi:pkg[==ver]"
        ),
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
    fail_at: str = typer.Option(
        "high", "--fail-at",
        help="Exit non-zero if max finding severity ≥ this level (info|low|med|high|critical).",
    ),
    fail_on_verdict: str = typer.Option(
        "shallow", "--fail-on-verdict",
        help=(
            "Exit non-zero if verdict is at this rank or worse "
            "(benign < shallow < unknown < suspicious < malicious). Default 'shallow' "
            "so CI fails on servers MIS did not fully analyze — change to 'suspicious' "
            "only if you accept partial-coverage scans as 'safe enough to install'."
        ),
    ),
    allow_unknown: bool = typer.Option(
        False, "--allow-unknown",
        help="Treat an 'unknown' verdict as success in the exit code. Off by default.",
    ),
    allow_shallow: bool = typer.Option(
        False, "--allow-shallow",
        help="Treat a 'shallow' verdict as success in the exit code. Off by default.",
    ),
) -> None:
    """Scan an MCP server source and emit a verdict + findings."""
    try:
        threshold = Severity.from_str(fail_at)
    except KeyError:
        console.print(f"[red]bad --fail-at[/red]: {fail_at}. Use info|low|med|high|critical.")
        raise typer.Exit(2)
    if fail_on_verdict not in {"benign", "shallow", "unknown", "suspicious", "malicious"}:
        console.print(
            f"[red]bad --fail-on-verdict[/red]: {fail_on_verdict}. "
            "Use benign|shallow|unknown|suspicious|malicious."
        )
        raise typer.Exit(2)

    try:
        result, hits = _scan(source)
    except ExtractionError as e:
        console.print(f"[red]extraction failed[/red]: {e}")
        raise typer.Exit(2)
    except Exception as e:  # noqa: BLE001 — surface any unexpected error cleanly
        console.print(f"[red]unexpected error[/red]: {type(e).__name__}: {e}")
        raise typer.Exit(2)

    if json_out:
        # Print to stdout so it's pipe-friendly; don't use rich for JSON
        sys.stdout.write(render_json(result, hits) + "\n")
    else:
        render_table(result, hits, console)

    # Exit code: highest of the two fail conditions
    severity_fail = result.max_severity >= threshold
    actual_rank = _verdict_rank(result.verdict or "benign")
    # --allow-{unknown,shallow} carve out exactly those verdicts
    if (allow_unknown and result.verdict == "unknown") or \
       (allow_shallow and result.verdict == "shallow"):
        verdict_fail = False
    else:
        verdict_fail = actual_rank >= _verdict_rank(fail_on_verdict)
    if severity_fail or verdict_fail:
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print version and exit."""
    console.print(f"mcp-intent-sentinel {__version__}")


def _verdict_rank(v: str) -> int:
    # Mirrors mis.classifier.intent._VERDICT_RANK exactly. Keep them in sync.
    return {"benign": 0, "shallow": 1, "unknown": 2, "suspicious": 3, "malicious": 4}.get(v, 0)


if __name__ == "__main__":
    app()
