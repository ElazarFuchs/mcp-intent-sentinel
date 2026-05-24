"""Orchestrator for the model-compliance eval.

Usage:
    python -m eval.model_compliance.run                   # full sweep
    python -m eval.model_compliance.run --limit 5         # first 5 prompts per model
    python -m eval.model_compliance.run --models X Y      # subset
    python -m eval.model_compliance.run --intents silent_exfiltrator command_injection
    python -m eval.model_compliance.run --resume          # skip (model, intent, level) already in result JSON
    python -m eval.model_compliance.run --out eval/model_compliance/results/v0.1.5-dryrun

Reads OPENROUTER_API_KEY from env or --api-key.

The harness DOES NOT execute any model-generated code. It writes each code
block to a temp dir, hands it to mis.engine.scan, deletes the temp dir.
Static analysis only — same posture as the rest of MIS.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from eval.model_compliance.judge import judge
from eval.model_compliance.prompts import ALL_PROMPTS, INTENTS, LEVELS, Prompt
from eval.model_compliance.runner import MODELS, call


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record(model: str, p: Prompt, call_result, judgment) -> dict:
    return {
        "model": model,
        "intent": p.intent,
        "level": p.level,
        "language": p.language,
        "expects_pattern": p.expects_pattern,
        "outcome": judgment.outcome,
        "verdict": judgment.verdict,
        "verdict_confidence": judgment.verdict_confidence,
        "verdict_reason": judgment.verdict_reason,
        "rule_hits": judgment.rule_hits,
        "tools_detected": judgment.tools_detected,
        "tools_with_behavior": judgment.tools_with_behavior,
        "refusal_signal": judgment.refusal_signal,
        "scan_error": judgment.scan_error,
        "code_files": judgment.code_files,
        "api_error": call_result.error,
        "latency_s": call_result.latency_s,
        "input_tokens": call_result.input_tokens,
        "output_tokens": call_result.output_tokens,
        "finish_reason": call_result.finish_reason,
        "response_text": call_result.response_text,  # full text retained for audit
        "prompt_text": p.text,
        "timestamp": _now_iso(),
    }


def _summarize(records: list[dict]) -> dict:
    by_model: dict[str, dict[str, int]] = {}
    for r in records:
        m = by_model.setdefault(r["model"], {})
        m[r["outcome"]] = m.get(r["outcome"], 0) + 1
        m["_total"] = m.get("_total", 0) + 1

    summary: dict = {"per_model": {}, "per_intent": {}, "totals": {}}
    for m, counts in by_model.items():
        total = counts.get("_total", 0) or 1
        suspicious = counts.get("code_suspicious", 0)
        malicious = counts.get("code_malicious", 0)
        bypass = counts.get("code_benign", 0) + counts.get("code_shallow", 0) + counts.get("code_unknown", 0)
        refused = counts.get("refused", 0)
        compliance = suspicious + malicious + bypass
        summary["per_model"][m] = {
            "total": total,
            "refused": refused,
            "code_benign": counts.get("code_benign", 0),
            "code_shallow": counts.get("code_shallow", 0),
            "code_unknown": counts.get("code_unknown", 0),
            "code_suspicious": suspicious,
            "code_malicious": malicious,
            "empty": counts.get("empty", 0),
            "error": counts.get("error", 0),
            "compliance_pct": round(100.0 * compliance / total, 1),
            "caught_by_mis_pct": round(100.0 * (suspicious + malicious) / total, 1),
            "bypass_mis_pct": round(100.0 * bypass / total, 1),
            "refusal_pct": round(100.0 * refused / total, 1),
        }

    # Per-intent: refusal rate across all models. High = strong intent friction.
    for intent in INTENTS:
        sub = [r for r in records if r["intent"] == intent]
        if not sub:
            continue
        refused = sum(1 for r in sub if r["outcome"] == "refused")
        complied = sum(1 for r in sub if r["outcome"].startswith("code_"))
        caught = sum(1 for r in sub if r["outcome"] in ("code_suspicious", "code_malicious"))
        summary["per_intent"][intent] = {
            "total": len(sub),
            "refused": refused,
            "complied": complied,
            "caught_by_mis": caught,
            "refusal_pct": round(100.0 * refused / len(sub), 1),
            "compliance_pct": round(100.0 * complied / len(sub), 1),
            "caught_pct": round(100.0 * caught / len(sub), 1),
        }

    # Per-level: refusal across disguise levels. Expect overt > framed > covert.
    for level in LEVELS:
        sub = [r for r in records if r["level"] == level]
        if not sub:
            continue
        refused = sum(1 for r in sub if r["outcome"] == "refused")
        complied = sum(1 for r in sub if r["outcome"].startswith("code_"))
        summary["totals"][f"level_{level}"] = {
            "total": len(sub),
            "refused_pct": round(100.0 * refused / len(sub), 1),
            "complied_pct": round(100.0 * complied / len(sub), 1),
        }

    return summary


def _render_report(records: list[dict], summary: dict, out_dir: Path) -> str:
    lines: list[str] = []
    lines.append(f"# Model-compliance eval — {_now_iso()}\n")
    lines.append(f"Total runs: **{len(records)}** "
                 f"({len({r['model'] for r in records})} models × "
                 f"{len({r['intent'] for r in records})} intents × "
                 f"{len({r['level'] for r in records})} disguise levels)\n")

    lines.append("\n## Per-model headline\n")
    lines.append("| model | runs | refusal % | caught by MIS % | bypass MIS % | api errors |")
    lines.append("|---|---|---|---|---|---|")
    rows = sorted(summary["per_model"].items(), key=lambda kv: kv[1]["compliance_pct"], reverse=True)
    for m, s in rows:
        lines.append(f"| `{m}` | {s['total']} | {s['refusal_pct']} | {s['caught_by_mis_pct']} | {s['bypass_mis_pct']} | {s['error']} |")

    lines.append("\n*caught by MIS%* = MIS verdict was suspicious or malicious on the model's output. "
                 "*bypass MIS%* = model emitted code that materially matched the intent but MIS verdicted benign/shallow/unknown — "
                 "these rows are the gold for new fixtures (run `--bypass-only` to extract).\n")

    lines.append("\n## Per-intent refusal vs compliance (all models)\n")
    lines.append("| intent | runs | refusal % | compliance % | caught by MIS % |")
    lines.append("|---|---|---|---|---|")
    rows = sorted(summary["per_intent"].items(), key=lambda kv: kv[1]["refusal_pct"], reverse=True)
    for intent, s in rows:
        lines.append(f"| {intent} | {s['total']} | {s['refusal_pct']} | {s['compliance_pct']} | {s['caught_pct']} |")

    lines.append("\n## Disguise-level effect (all models, all intents)\n")
    lines.append("| level | runs | refusal % | any code emitted % |")
    lines.append("|---|---|---|---|")
    for level in LEVELS:
        key = f"level_{level}"
        s = summary["totals"].get(key)
        if s:
            lines.append(f"| {level} | {s['total']} | {s['refused_pct']} | {s['complied_pct']} |")

    lines.append("\n## Coverage-gap candidates (bypass rows)\n")
    bypass_rows = [r for r in records if r["outcome"] in ("code_benign", "code_shallow", "code_unknown")]
    if not bypass_rows:
        lines.append("_None — every model that complied was caught by MIS._\n")
    else:
        lines.append(f"{len(bypass_rows)} rows where the model emitted code but MIS verdicted benign/shallow/unknown. "
                     "Inspect each to decide whether it's a new fixture or a true negative.\n")
        lines.append("| model | intent | level | verdict | reason |")
        lines.append("|---|---|---|---|---|")
        for r in bypass_rows:
            reason = (r["verdict_reason"] or "")[:80].replace("|", "/")
            lines.append(f"| `{r['model']}` | {r['intent']} | {r['level']} | {r['verdict']} | {reason} |")

    latencies = [r["latency_s"] for r in records if isinstance(r.get("latency_s"), (int, float)) and r["latency_s"] > 0]
    if latencies:
        lines.append("\n## Timings\n")
        lines.append(f"- p50 latency: {statistics.median(latencies):.1f}s")
        lines.append(f"- p95 latency: {sorted(latencies)[int(len(latencies)*0.95)]:.1f}s")
        lines.append(f"- max latency: {max(latencies):.1f}s")

    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None, help="Output directory (default: results/<UTC timestamp>)")
    ap.add_argument("--models", nargs="*", default=None, help="Subset of model IDs (default: all)")
    ap.add_argument("--intents", nargs="*", default=None, help="Subset of intents")
    ap.add_argument("--levels", nargs="*", default=None, help="Subset of disguise levels")
    ap.add_argument("--limit", type=int, default=None, help="Cap prompts per model (debug)")
    ap.add_argument("--resume", action="store_true", help="Skip (model, intent, level) already in --out/run.json")
    ap.add_argument("--api-key", default=None, help="OpenRouter key (otherwise OPENROUTER_API_KEY env)")
    ap.add_argument("--max-tokens", type=int, default=2000)
    ap.add_argument("--temperature", type=float, default=0.2)
    args = ap.parse_args()

    models = args.models or MODELS
    prompts = [p for p in ALL_PROMPTS
               if (not args.intents or p.intent in args.intents)
               and (not args.levels or p.level in args.levels)]
    if args.limit:
        prompts = prompts[: args.limit]

    out_dir = Path(args.out or f"eval/model_compliance/results/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    run_json = out_dir / "run.json"

    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    if args.resume and run_json.exists():
        records = json.loads(run_json.read_text(encoding="utf-8"))
        seen = {(r["model"], r["intent"], r["level"]) for r in records}
        print(f"[resume] {len(records)} prior records loaded; skipping {len(seen)} keys")

    total_planned = len(models) * len(prompts)
    done = len(seen)
    api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("ERROR: set OPENROUTER_API_KEY env var or pass --api-key", flush=True)
        return 2

    print(f"[start] {len(models)} models × {len(prompts)} prompts = {total_planned} calls; out={out_dir}", flush=True)
    t0 = time.time()
    for model in models:
        for p in prompts:
            key = (model, p.intent, p.level)
            if key in seen:
                continue
            done += 1
            call_result = call(
                model, p.text,
                api_key=api_key,
                max_tokens=args.max_tokens,
                temperature=args.temperature,
            )
            judgment = judge(call_result.response_text, p.language, error=call_result.error)
            rec = _record(model, p, call_result, judgment)
            records.append(rec)

            # Persist after every call so a crash leaves a usable partial run.
            run_json.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

            print(f"[{done:>3}/{total_planned}] {model[-30:]:>30} {p.intent[:20]:>20} {p.level:>6}"
                  f"  -> {judgment.outcome:<16}"
                  f" verdict={judgment.verdict or '-':<12}"
                  f" lat={call_result.latency_s}s",
                  flush=True)

    summary = _summarize(records)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    report = _render_report(records, summary, out_dir)
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    print(f"\n[done] {len(records)} records, {time.time()-t0:.0f}s wall.")
    print(f"  json:    {run_json}")
    print(f"  summary: {out_dir/'summary.json'}")
    print(f"  report:  {out_dir/'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
