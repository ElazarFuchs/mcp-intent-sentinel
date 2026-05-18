"""Eval harness: download every server in eval/registry.py, run MIS on it,
collect the verdicts and counts, write a result file and a human report.

Usage:
    python -m eval.run                                # full run, default output dir
    python -m eval.run --out eval/results/dryrun     # custom output dir
    python -m eval.run --limit 10                    # first N entries only (debug)
    python -m eval.run --resume                      # skip entries already in the existing run JSON
    python -m eval.run --baseline                    # ALSO run mcp-scan inspect side-by-side
                                                       (note: mcp-scan inspects configs / tool descs at
                                                        runtime — see LIMITATIONS.md L10 for why it's
                                                        NOT a direct head-to-head, only a complement)

What it does NOT do:
- It does NOT execute any server. Static analysis only — the same posture
  as MIS itself. `mcp-scan inspect` (if --baseline) is the one exception
  and is documented; we surface that this is a different category.

What's surfaced in the report:
- verdict distribution across the registry
- shallow rate (= MIS's own admission of incomplete coverage)
- unknown rate (= MIS didn't detect any tools)
- "FP candidates" (real popular servers MIS classified malicious / suspicious —
  manual review required; this is the FP signal we have until L11 lands a
  formally labeled benign corpus)
- timings (p50 / p95 per server)
- list of failed downloads (entries the harness couldn't fetch)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mis.engine import scan as mis_scan
from mis.extractors import ExtractionError

from eval.registry import ALL_SERVERS, ServerEntry


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_one(entry: ServerEntry) -> dict:
    """Scan a single registry entry. Returns a record dict with full result."""
    record: dict = {
        "name": entry.name,
        "source": entry.source,
        "ecosystem": entry.ecosystem,
        "expected_class": entry.expected_class,
        "notes": entry.notes,
        "ok": False,
        "duration_seconds": None,
        "error": None,
        "verdict": None,
        "verdict_confidence": None,
        "verdict_reason": None,
        "tools_detected": None,
        "tool_names": None,
        "tools_with_behavior": None,
        "io_capable_imports_present": None,
        "findings_count": None,
        "max_severity": None,
        "rule_hits": None,
    }
    start = time.perf_counter()
    try:
        result, hits = mis_scan(entry.source)
        record["ok"] = True
        record["verdict"] = result.verdict
        record["verdict_confidence"] = round(result.verdict_confidence, 2)
        record["verdict_reason"] = result.verdict_reason[:400]
        record["tools_detected"] = len(result.tools)
        record["tool_names"] = [getattr(t, "name", "?") for t in result.tools]
        record["tools_with_behavior"] = sum(1 for t in result.tools if getattr(t, "behavior", None))
        record["io_capable_imports_present"] = bool(result.io_capable_imports_present)
        record["findings_count"] = len(result.findings)
        record["max_severity"] = str(result.max_severity)
        record["rule_hits"] = [
            {"rule_id": h.rule_id, "verdict": h.verdict, "confidence": round(h.confidence, 2),
             "reason": h.reason[:200]}
            for h in hits
        ]
    except ExtractionError as e:
        record["error"] = f"extraction: {e}"
    except Exception as e:  # noqa: BLE001 — we want to capture and continue
        record["error"] = f"{type(e).__name__}: {e}"
    finally:
        record["duration_seconds"] = round(time.perf_counter() - start, 2)
    return record


def run_baseline_mcp_scan(entry: ServerEntry, scanned_root: Path) -> Optional[dict]:
    """OPTIONAL: invoke `mcp-scan inspect` on a config that points at the
    server. This is NOT an apples-to-apples comparison — mcp-scan scans
    runtime/config artifacts, not source. Documented as such in the report
    and in LIMITATIONS.md L10.

    Returns None if mcp-scan unavailable or scan failed.
    """
    # mcp-scan needs a config file pointing at the server's stdio command.
    # For PyPI: `python -m <module>`; for npm: `npx <package>`. Building a
    # working command per-server requires per-server knowledge. As a stand-in
    # for the eval, we run `mcp-scan inspect` against a synthetic config that
    # points at the server's main entry — this only reports tool descriptions,
    # which still gives us a signal on whether mcp-scan can read this server.
    # Many servers will fail this step because their command needs args/env.
    #
    # We accept that. The goal of --baseline here is to demonstrate the
    # category difference, not to score mcp-scan on a task it wasn't built for.
    try:
        # Heuristic: just check that mcp-scan is callable and report tool count
        # if it succeeds. Detail-comparison is for v0.2.
        cmd = ["mcp-scan", "inspect", "--json"]
        proc = subprocess.run(cmd, capture_output=True, timeout=30, cwd=str(scanned_root))
        out = (proc.stdout or b"").decode("utf-8", errors="replace")
        return {
            "rc": proc.returncode,
            "stdout_first_200": out[:200],
            "note": "mcp-scan inspect is config/runtime-oriented, not source — see LIMITATIONS L10",
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"rc": -1, "error": str(e)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run MIS evaluation against the real-server registry.")
    ap.add_argument("--out", default="eval/results/latest", help="Output directory")
    ap.add_argument("--limit", type=int, default=None, help="Scan only first N entries (debug)")
    ap.add_argument("--baseline", action="store_true",
                    help="Also invoke `mcp-scan inspect` per entry. Note: NOT an apples-to-apples comparison.")
    ap.add_argument("--resume", action="store_true",
                    help="Skip entries already present in <out>/run.json")
    args = ap.parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_path = out_dir / "run.json"

    # Resume support
    existing: list[dict] = []
    if args.resume and run_path.exists():
        try:
            existing = json.loads(run_path.read_text(encoding="utf-8")).get("records", [])
        except (json.JSONDecodeError, OSError):
            existing = []
    done_names = {r["name"] for r in existing}

    entries = ALL_SERVERS if args.limit is None else ALL_SERVERS[: args.limit]
    todo = [e for e in entries if e.name not in done_names]

    print(f"[eval] {len(todo)} entries to scan ({len(done_names)} already done from previous run)",
          file=sys.stderr)
    records = list(existing)
    for i, entry in enumerate(todo, 1):
        print(f"[eval] ({i}/{len(todo)}) {entry.name} ...", file=sys.stderr)
        rec = run_one(entry)
        if args.baseline and rec["ok"]:
            # We don't currently have the extracted root path returned from MIS
            # (cleanup happens automatically) — so the baseline step here is a
            # stub that proves we CAN invoke mcp-scan but doesn't pretend to do
            # a per-server side-by-side. Future work: thread the scanned root
            # back through MIS so we can hand it to mcp-scan too.
            rec["baseline_mcp_scan"] = run_baseline_mcp_scan(entry, Path("."))
        records.append(rec)
        # Persist after each scan so a crash doesn't lose progress
        _write_run(run_path, records)

    print(f"[eval] done. {sum(1 for r in records if r['ok'])} / {len(records)} successful scans.",
          file=sys.stderr)
    # Write the report
    report_path = out_dir / "report.md"
    report = _build_report(records, args.baseline)
    report_path.write_text(report, encoding="utf-8")
    print(f"[eval] wrote {report_path}", file=sys.stderr)
    print(f"[eval] wrote {run_path}", file=sys.stderr)
    return 0


def _write_run(path: Path, records: list[dict]) -> None:
    payload = {
        "run_started_at": _now_iso(),
        "records": records,
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _build_report(records: list[dict], baseline_used: bool) -> str:
    n = len(records)
    ok = [r for r in records if r["ok"]]
    failed = [r for r in records if not r["ok"]]

    verdict_counts: dict[str, int] = {}
    for r in ok:
        verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1

    # FP CANDIDATES: real publicly-published servers MIS classified as
    # malicious or suspicious. Each one needs manual review — either MIS
    # found a real issue worth reporting upstream, OR it's an FP we need to
    # tighten. Either way, NEVER hide them.
    fp_candidates = [r for r in ok if r["verdict"] in {"malicious", "suspicious"}]
    shallow_list = [r for r in ok if r["verdict"] == "shallow"]
    unknown_list = [r for r in ok if r["verdict"] == "unknown"]
    benign_list = [r for r in ok if r["verdict"] == "benign"]

    # Timings
    times = [r["duration_seconds"] for r in ok if r["duration_seconds"] is not None]
    p50 = round(statistics.median(times), 2) if times else None
    p95 = round(sorted(times)[int(0.95 * len(times)) - 1], 2) if len(times) >= 20 else None
    total = round(sum(times), 1) if times else 0

    lines: list[str] = []
    lines.append(f"# MIS evaluation report — {_now_iso()}")
    lines.append("")
    lines.append(f"Registry size: **{n}** servers scanned. **{len(ok)}** successful, **{len(failed)}** failed to download.")
    lines.append(f"Total scan time: {total}s (p50 {p50}s, p95 {p95 if p95 else 'n/a'}s).")
    lines.append("")
    lines.append("## Verdict distribution (successful scans only)")
    lines.append("")
    lines.append("| Verdict | Count | % |")
    lines.append("|---|---:|---:|")
    if ok:
        for v in ["malicious", "suspicious", "unknown", "shallow", "benign"]:
            c = verdict_counts.get(v, 0)
            pct = round(100 * c / len(ok), 1)
            lines.append(f"| {v} | {c} | {pct}% |")
    lines.append("")
    lines.append(
        f"**Shallow rate** ({len(shallow_list)}/{len(ok) or 1}) measures how often "
        "MIS recognized tools but couldn't follow behavior — the L18 / coverage ceiling. "
        "**Unknown rate** measures unrecognized SDK patterns. These two together are "
        "MIS's own coverage gap, surfaced honestly by the verdict scheme — they are "
        "NOT the FP rate."
    )
    lines.append("")

    if fp_candidates:
        lines.append("## FP candidates — REAL servers MIS classified as malicious / suspicious")
        lines.append("")
        lines.append(
            "Each entry below is a public, popular server that MIS verdicted as a threat. "
            "**One of two things is true** for each:"
        )
        lines.append(
            "1. MIS found a real issue worth reporting upstream (true positive — file an issue "
            "with the package's maintainers), OR"
        )
        lines.append("2. The rule that fired is over-aggressive (false positive — tighten in v0.1.4+).")
        lines.append("")
        lines.append("Manual review required for each. **Never hide this list.**")
        lines.append("")
        lines.append("| Name | Verdict | Confidence | Top rule | Reason |")
        lines.append("|---|---|---:|---|---|")
        for r in fp_candidates:
            top_rule = (r["rule_hits"] or [{}])[0].get("rule_id", "—")
            reason = (r["verdict_reason"] or "")[:120].replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| `{r['name']}` | {r['verdict']} | {r['verdict_confidence']} | {top_rule} | {reason} |"
            )
        lines.append("")
    else:
        lines.append("## FP candidates")
        lines.append("")
        lines.append("None. **No real public server in this registry classified as malicious or suspicious.**")
        lines.append("")

    lines.append("## Shallow list — MIS coverage ceiling on real servers")
    lines.append("")
    if shallow_list:
        lines.append(
            f"{len(shallow_list)} server(s) where MIS detected tools but extracted zero behavior "
            "signals from any of them — not even PURE_COMPUTE. These are MIS's blind spots — most "
            "commonly class-method dispatch (L18), helpers across modules, or other unrecognized "
            "dispatch shapes. Until these are lifted, MIS verdicts `shallow` rather than pretending "
            "to know."
        )
        lines.append("")
        lines.append("| Name | Ecosystem | Tools detected | I/O imports? |")
        lines.append("|---|---|---:|---|")
        for r in shallow_list:
            lines.append(
                f"| `{r['name']}` | {r['ecosystem']} | {r['tools_detected']} "
                f"({', '.join(r['tool_names'][:3])}{'...' if len(r['tool_names']) > 3 else ''}) "
                f"| {r['io_capable_imports_present']} |"
            )
    else:
        lines.append("No servers verdicted shallow. (Either MIS is fully covering the registry, or the registry is too small.)")
    lines.append("")

    lines.append("## Unknown list — SDKs MIS doesn't recognize")
    lines.append("")
    if unknown_list:
        lines.append(f"{len(unknown_list)} server(s) where MIS did not detect any tool registration. "
                     "These flag SDK patterns we need to add support for (L13).")
        lines.append("")
        for r in unknown_list:
            lines.append(f"- `{r['name']}` ({r['ecosystem']})")
    else:
        lines.append("None. Every successful scan detected at least one tool.")
    lines.append("")

    # v0.1.5: split the benign list into "with behavior" vs "zero behavior".
    # The latter is the leak the user caught in v0.1.4 — tools detected but
    # zero behavior extracted should NOT have routed to benign. The classifier
    # rule was tightened in v0.1.5; this split is here so we can SEE in the
    # report whether any zero-behavior benign entries are still leaking.
    benign_with_behavior = [r for r in benign_list if (r.get("tools_with_behavior") or 0) > 0]
    benign_zero_behavior = [r for r in benign_list if (r.get("tools_with_behavior") or 0) == 0]

    lines.append(f"## Benign list ({len(benign_list)})")
    lines.append("")
    lines.append(
        f"**Split**: {len(benign_with_behavior)} with extracted behavior, "
        f"{len(benign_zero_behavior)} with ZERO behavior extracted."
    )
    lines.append("")
    if benign_zero_behavior:
        lines.append(
            "**Zero-behavior benign entries are the leak metric.** v0.1.5 closed "
            "the most common path; if any entries appear below, it's a new leak "
            "shape that wasn't covered and should be triaged before trusting the "
            "benign rate as a wedge claim."
        )
        lines.append("")
        for r in benign_zero_behavior:
            lines.append(
                f"- ⚠️ `{r['name']}` — {r['tools_detected']} tool(s), "
                f"**0 with behavior** (likely shallow-leak)"
            )
        lines.append("")
    if benign_with_behavior:
        lines.append(
            "These are real public servers MIS verdicted `benign` AND extracted "
            "behavior from at least one tool. CANDIDATES for the formal benign "
            "corpus (L11). Each still needs independent confirmation — `benign` "
            "is bounded by what the v0.1 ruleset covers (L4)."
        )
        lines.append("")
        for r in benign_with_behavior:
            lines.append(
                f"- `{r['name']}` — {r['tools_detected']} tool(s), "
                f"{r['tools_with_behavior']} with behavior, confidence {r['verdict_confidence']}"
            )
    lines.append("")

    if failed:
        lines.append(f"## Failed downloads ({len(failed)})")
        lines.append("")
        lines.append(
            "These entries could not be fetched from the registry (package retired, "
            "renamed, network issue, etc.). They are NOT counted in the distribution above."
        )
        lines.append("")
        for r in failed:
            lines.append(f"- `{r['name']}` — {r['error']}")
        lines.append("")

    lines.append("## Baseline scanner notes")
    lines.append("")
    if baseline_used:
        lines.append(
            "`mcp-scan` (now `snyk-agent-scan`) was invoked alongside. **It is NOT a "
            "head-to-head comparison.** mcp-scan inspects MCP config files and "
            "runtime tool descriptions — it does NOT analyze server source code. "
            "MIS analyzes source pre-install; mcp-scan analyzes configuration / "
            "runtime artifacts. They are complementary categories, not competing "
            "scanners. The numbers in `baseline_mcp_scan` keys in run.json reflect "
            "whether the tool was callable, not a scoring comparison."
        )
    else:
        lines.append(
            "Baseline scanner integration not requested in this run (use `--baseline`). "
            "Even with it, see LIMITATIONS.md L10: mcp-scan and MIS scan different "
            "artifacts. A direct head-to-head requires a baseline that does static "
            "source analysis — none of the currently-deployed scanners do."
        )
    lines.append("")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
