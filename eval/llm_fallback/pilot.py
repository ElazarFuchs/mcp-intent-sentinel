"""Pilot driver: re-classify v0.1.7 `unknown` rows using the LLM fallback.

Loop:
  1. Read eval/results/v0.1.7/run.json.
  2. For every row with verdict == "unknown" (or --include-shallow), download
     the package (mis.extractors.extract), bundle its source, and call
     `eval.llm_fallback.analyzer.analyze(...)`.
  3. Convert the returned tool/signal list into ToolProfile objects and feed
     them into `mis.classifier.intent.classify(...)`. The verdict the
     classifier produces is the "with-LLM" verdict.
  4. Record before/after per row + roll up the cohort delta.

Outputs:
    <out>/pilot.json    — per-row records (before verdict, after verdict,
                          tools extracted, signals, raw LLM notes, cost).
    <out>/pilot.md      — human report with the delta table.

Cost (rough): 20 unknowns × ~30k input tokens × Sonnet ≈ $2-4 for a full
run on the v0.1.7 unknown cohort.

Usage:
    export OPENROUTER_API_KEY=sk-or-...
    python -m eval.llm_fallback.pilot
    python -m eval.llm_fallback.pilot --in eval/results/v0.1.7/run.json --limit 5
    python -m eval.llm_fallback.pilot --include-shallow   # also try to lift shallow rows
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mis import __version__ as mis_version
from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.analyzers.python import _guess_intent
from mis.classifier.intent import classify
from mis.extractors import extract, ExtractionError
from mis.findings import ScanResult

from eval.llm_fallback.analyzer import analyze as llm_analyze, analyze_with_union


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_profiles(extracted_tools: list[dict]) -> list[ToolProfile]:
    """Convert the LLM's tool descriptors into ToolProfile objects so the
    classifier can consume them. Behavior signals that aren't in the enum
    are dropped (defense-in-depth — the analyzer also validates, but parse
    drift between versions shouldn't crash here)."""
    profiles: list[ToolProfile] = []
    for t in extracted_tools:
        signals: set[BehaviorSignal] = set()
        for s in t.get("behavior_signals", []):
            try:
                signals.add(BehaviorSignal[s])
            except KeyError:
                continue
        desc = t.get("description") or ""
        profile = ToolProfile(
            name=t.get("name") or "<unnamed>",
            declared_description=desc,
            declared_params=[],
            behavior=signals,
        )
        profile.declared_intent = _guess_intent(desc, profile.name)
        profiles.append(profile)
    return profiles


def _classify_with_profiles(profiles: list[ToolProfile]) -> tuple[str, list[str], str]:
    """Run the existing classifier against synthesized ToolProfiles. Returns
    (verdict, rule_hit_ids, reason)."""
    # Build a minimal ScanResult — the classifier reads .findings and the
    # tools we pass in. We pass NO findings (LLM signals already live on the
    # profiles), so only rules that consult `tools` (r4.intent_mismatch) and
    # rules driven by per-tool behavior will fire. Pure-finding rules (r1
    # secret_to_request, r6 command_injection) need findings — and the LLM
    # path doesn't synthesize findings by design (those would be claims the
    # LLM made, scored at full classifier confidence — we don't want that).
    #
    # The signals on profiles still let r4 fire: a 'math'-intent tool with
    # NET_HTTP_OUTBOUND triggers intent-mismatch. That's the main lift we
    # expect from the LLM path on cleanly-benign-shaped servers: r4 says
    # nothing fired -> classifier returns benign instead of unknown.
    result = ScanResult(
        root=Path("<llm-fallback>"),
        source="<llm-fallback>",
        findings=[],
        tools=profiles,
    )
    hits = classify(result, profiles)
    return (
        result.verdict or "unclassified",
        [h.rule_id for h in hits],
        (result.verdict_reason or "")[:200],
    )


def _process(rec: dict, *, api_key: str, secondary_model: str | None = None) -> dict:
    """Run extraction + LLM + classification on a single eval row.

    v0.1.17 — when `secondary_model` is provided, the LLM extraction uses
    `analyze_with_union` (silent-omission defense per L22). Otherwise a
    single-model `analyze` call (legacy behavior).
    """
    source = rec["source"]
    out: dict = {
        "name": rec["name"],
        "ecosystem": rec["ecosystem"],
        "source": source,
        "before_verdict": rec["verdict"],
        "before_rule_hits": rec.get("rule_hits") or [],
        "before_tools": rec.get("tools_detected"),
        "extracted_tools": [],
        "extracted_signals_per_tool": [],
        "after_verdict": None,
        "after_rule_hits": [],
        "after_reason": "",
        "llm_extraction_notes": "",
        "llm_parse_error": None,
        "llm_api_error": None,
        "llm_latency_s": 0.0,
        "llm_input_tokens": None,
        "llm_output_tokens": None,
        "moved": False,
        "extraction_error": None,
        "timestamp": _now_iso(),
    }

    # Step 1: extract the package source to a temp dir.
    try:
        with extract(source) as extracted:
            if secondary_model:
                # Multi-model union — silent-omission defense (L22).
                # Uses the analyzer's DEFAULT_MODEL as primary unless the
                # caller has overridden; we don't expose --primary-model
                # in the pilot because the default has been the baseline
                # for every prior pilot run and we want apples-to-apples.
                from eval.llm_fallback.analyzer import DEFAULT_MODEL
                ext = analyze_with_union(
                    Path(extracted.root),
                    primary_model=DEFAULT_MODEL,
                    secondary_model=secondary_model,
                    api_key=api_key,
                )
            else:
                ext = llm_analyze(Path(extracted.root), api_key=api_key)
    except ExtractionError as e:
        out["extraction_error"] = f"ExtractionError: {e}"
        return out
    except Exception as e:
        out["extraction_error"] = f"{type(e).__name__}: {e}"
        return out

    out["llm_extraction_notes"] = ext.extraction_notes
    out["llm_parse_error"] = ext.parse_error
    out["llm_api_error"] = ext.api_error
    out["llm_latency_s"] = ext.latency_s
    out["llm_input_tokens"] = ext.input_tokens
    out["llm_output_tokens"] = ext.output_tokens
    out["extracted_tools"] = [t["name"] for t in ext.tools]
    out["extracted_signals_per_tool"] = [
        {"tool": t["name"], "signals": t["behavior_signals"]} for t in ext.tools
    ]

    if ext.api_error or ext.parse_error:
        return out
    if not ext.tools:
        return out  # LLM saw nothing — stays unknown

    # Step 2: feed extracted tools into the classifier.
    profiles = _build_profiles(ext.tools)
    verdict, hits, reason = _classify_with_profiles(profiles)

    # For the "no rule fired" case the classifier in mis.classifier.intent
    # returns unknown if tools is empty, otherwise benign. We expose this as
    # the after_verdict. Map "unclassified" (no verdict set) to "benign".
    if verdict == "unclassified":
        verdict = "benign"

    out["after_verdict"] = verdict
    out["after_rule_hits"] = hits
    out["after_reason"] = reason
    out["moved"] = (out["before_verdict"] != verdict)
    return out


def _summarize(rows: list[dict]) -> dict:
    by_before: dict[str, int] = {}
    by_after:  dict[str, int] = {}
    moved = 0
    for r in rows:
        by_before[r["before_verdict"]] = by_before.get(r["before_verdict"], 0) + 1
        after = r["after_verdict"] or r["before_verdict"]
        by_after[after] = by_after.get(after, 0) + 1
        if r["moved"]:
            moved += 1
    total_in_tokens  = sum((r["llm_input_tokens"]  or 0) for r in rows)
    total_out_tokens = sum((r["llm_output_tokens"] or 0) for r in rows)
    return {
        "n": len(rows),
        "moved": moved,
        "moved_pct": round(100.0 * moved / len(rows), 1) if rows else 0.0,
        "before_distribution": by_before,
        "after_distribution":  by_after,
        "total_input_tokens":  total_in_tokens,
        "total_output_tokens": total_out_tokens,
        "errors": sum(1 for r in rows if r["llm_api_error"] or r["llm_parse_error"] or r["extraction_error"]),
    }


def _render(rows: list[dict], summary: dict) -> str:
    lines: list[str] = []
    lines.append(f"# LLM-fallback pilot — MIS v{mis_version}, {_now_iso()}")
    lines.append("")
    lines.append(f"**N**: {summary['n']} rows (only those with verdict=`unknown` in the input run).")
    lines.append(f"**Moved out of unknown**: {summary['moved']} ({summary['moved_pct']}%).")
    lines.append(f"**Errors** (API / parse / extraction): {summary['errors']}.")
    lines.append("")
    lines.append("## Distribution before vs after\n")
    lines.append("| verdict | before | after |")
    lines.append("|---|---:|---:|")
    keys = sorted(set(list(summary["before_distribution"].keys()) + list(summary["after_distribution"].keys())))
    for k in keys:
        b = summary["before_distribution"].get(k, 0)
        a = summary["after_distribution"].get(k, 0)
        lines.append(f"| {k} | {b} | {a} |")
    lines.append("")
    lines.append("## Per-row\n")
    lines.append("| package | before | after | extracted tools | signals (first 3) | LLM notes |")
    lines.append("|---|---|---|---:|---|---|")
    for r in rows:
        sigs = []
        for entry in r["extracted_signals_per_tool"][:3]:
            sigs.append(f"{entry['tool']}:{','.join(entry['signals'][:3])}")
        sigs_str = " ; ".join(sigs)[:80]
        after = r["after_verdict"] or "—"
        err = r["llm_api_error"] or r["llm_parse_error"] or r["extraction_error"] or ""
        notes = (r["llm_extraction_notes"] or err)[:80].replace("|", "/")
        n_tools = len(r["extracted_tools"])
        lines.append(f"| `{r['name']}` | {r['before_verdict']} | {after} | {n_tools} | {sigs_str} | {notes} |")
    lines.append("")
    lines.append(f"## Cost\n")
    lines.append(f"- Total input tokens: {summary['total_input_tokens']:,}")
    lines.append(f"- Total output tokens: {summary['total_output_tokens']:,}")
    lines.append(f"- Estimated cost (Sonnet 4.5 rates): "
                 f"${(summary['total_input_tokens']/1e6)*3.0 + (summary['total_output_tokens']/1e6)*15.0:.2f}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in",   dest="inp",  default="eval/results/v0.1.7/run.json")
    ap.add_argument("--out",  default=None)
    ap.add_argument("--include-shallow", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument(
        "--secondary-model",
        default=None,
        help=(
            "v0.1.17 — when set, run LLM extraction on BOTH models and UNION "
            "the tool/signal sets (silent-omission defense, L22). Example: "
            "--secondary-model openai/gpt-5. Doubles per-call cost; intended "
            "for high-stakes pilot runs, not the default."
        ),
    )
    args = ap.parse_args()

    src = Path(args.inp)
    if not src.exists():
        print(f"ERROR: input not found: {src}", file=sys.stderr); return 2

    api_key = args.api_key or None
    import os
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("ERROR: set OPENROUTER_API_KEY env var or pass --api-key", file=sys.stderr); return 2

    data = json.loads(src.read_text(encoding="utf-8"))
    records = data if isinstance(data, list) else data.get("records", [])

    cohort = [r for r in records if r.get("ok") and (
        r.get("verdict") == "unknown" or (args.include_shallow and r.get("verdict") == "shallow")
    )]
    if args.limit:
        cohort = cohort[: args.limit]
    if not cohort:
        print("No cohort rows to process (no `unknown` rows in the input).", file=sys.stderr); return 0

    out_dir = Path(args.out or f"eval/llm_fallback/results/v{mis_version}")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[start] {len(cohort)} unknown rows; out={out_dir}", flush=True)
    t0 = time.time()
    rows: list[dict] = []
    for i, rec in enumerate(cohort, 1):
        result = _process(rec, api_key=api_key, secondary_model=args.secondary_model)
        rows.append(result)
        # Persist after every row so a mid-run crash leaves a usable partial.
        (out_dir / "pilot.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        after = result["after_verdict"] or "—"
        n_tools = len(result["extracted_tools"])
        err = result["llm_api_error"] or result["llm_parse_error"] or result["extraction_error"] or ""
        marker = "MOVED" if result["moved"] else "stayed"
        print(f"  [{i:>3}/{len(cohort)}] {rec['source'][:55]:<55} "
              f"-> tools={n_tools:>2} verdict {result['before_verdict']:>9}->{after:>9} "
              f"({marker}){' ' + err[:40] if err else ''}", flush=True)

    summary = _summarize(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "pilot.md").write_text(_render(rows, summary), encoding="utf-8")
    print(f"\n[done] {time.time()-t0:.0f}s wall. {summary['moved']}/{summary['n']} rows moved.")
    print(f"  json:  {out_dir/'pilot.json'}")
    print(f"  md:    {out_dir/'pilot.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
