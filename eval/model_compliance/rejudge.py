"""Re-run `judge()` against every cached response in an existing run.json.

No model API calls — this is the deterministic-half of the eval, exercising
the current MIS version against frozen model outputs. Used to validate that
analyzer/classifier changes (e.g. v0.1.6 host-fingerprint + module-level
secrets + dict-literal tools) actually move the needle on the eval.

Usage:
    python -m eval.model_compliance.rejudge \\
        --in eval/model_compliance/results/v0.1.5-full/run.json \\
        --out eval/model_compliance/results/v0.1.6-rejudged

Writes a new run.json (with re-judged outcomes), summary.json, report.md,
and delta.md (the per-row diff vs the original).
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from eval.model_compliance.judge import judge
from eval.model_compliance.run import _record, _summarize, _render_report


class _StubCall:
    """Adapter so _record(model, p, call_result, judgment) can be reused
    against a cached row without re-issuing an API call. Mirrors the field
    set of runner.Call that _record consumes."""
    def __init__(self, rec):
        self.model = rec["model"]
        self.prompt_text = rec["prompt_text"]
        self.response_text = rec["response_text"]
        self.error = rec["api_error"]
        self.latency_s = rec["latency_s"]
        self.input_tokens = rec["input_tokens"]
        self.output_tokens = rec["output_tokens"]
        self.finish_reason = rec["finish_reason"]


class _StubPrompt:
    def __init__(self, rec):
        self.intent = rec["intent"]
        self.level = rec["level"]
        self.language = rec["language"]
        self.text = rec["prompt_text"]
        self.expects_pattern = rec["expects_pattern"]


def _render_delta(before: list[dict], after: list[dict]) -> str:
    """Per-row diff: which (model,intent,level) outcomes changed and how."""
    idx_b = {(r["model"], r["intent"], r["level"]): r for r in before}
    idx_a = {(r["model"], r["intent"], r["level"]): r for r in after}
    keys = sorted(set(idx_b) | set(idx_a))

    changed: list[tuple[str, str, str, str, str, str, str]] = []
    for k in keys:
        b = idx_b.get(k)
        a = idx_a.get(k)
        if not (a and b):
            continue
        if a["outcome"] != b["outcome"] or a["verdict"] != b["verdict"]:
            changed.append((k[0], k[1], k[2],
                            b["outcome"], a["outcome"],
                            b["verdict"] or "-", a["verdict"] or "-"))

    # Categorize: improvement = bypass→caught; regression = caught→bypass.
    caught = {"code_suspicious", "code_malicious"}
    bypass = {"code_benign", "code_shallow", "code_unknown"}

    improvements = [c for c in changed if c[3] in bypass and c[4] in caught]
    regressions  = [c for c in changed if c[3] in caught and c[4] in bypass]
    other        = [c for c in changed if c not in improvements and c not in regressions]

    lines = []
    lines.append(f"# Re-judge delta — {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")
    lines.append(f"Total rows: {len(after)}")
    lines.append(f"Changed:    {len(changed)}")
    lines.append(f"  Improvements (bypass → caught): {len(improvements)}")
    lines.append(f"  Regressions  (caught → bypass): {len(regressions)}")
    lines.append(f"  Other       (bypass ↔ bypass / etc.): {len(other)}")
    lines.append("")

    def _section(title: str, rows: list) -> None:
        lines.append(f"## {title} ({len(rows)})")
        lines.append("")
        if not rows:
            lines.append("_none_")
            lines.append("")
            return
        lines.append("| model | intent | level | before | after | before verdict | after verdict |")
        lines.append("|---|---|---|---|---|---|---|")
        for m, intent, lvl, bo, ao, bv, av in rows:
            lines.append(f"| `{m}` | {intent} | {lvl} | {bo} | {ao} | {bv} | {av} |")
        lines.append("")

    _section("Improvements", improvements)
    _section("Regressions", regressions)
    _section("Other", other)

    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="Existing run.json to re-judge")
    ap.add_argument("--out", required=True, help="Output dir for rejudged run.json/summary/report/delta")
    args = ap.parse_args()

    src = Path(args.inp)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    before = json.loads(src.read_text(encoding="utf-8"))
    print(f"Loaded {len(before)} cached rows from {src}")

    after: list[dict] = []
    counts = {"changed": 0, "improved": 0, "regressed": 0}
    caught = {"code_suspicious", "code_malicious"}
    bypass = {"code_benign", "code_shallow", "code_unknown"}

    for i, rec in enumerate(before, 1):
        new_judgment = judge(rec["response_text"], rec["language"], error=rec["api_error"])
        new_rec = _record(rec["model"], _StubPrompt(rec), _StubCall(rec), new_judgment)
        # Preserve timestamp of the original API call; this is a re-judge, not a re-run.
        new_rec["timestamp"] = rec["timestamp"]
        after.append(new_rec)

        if new_rec["outcome"] != rec["outcome"]:
            counts["changed"] += 1
            if rec["outcome"] in bypass and new_rec["outcome"] in caught:
                counts["improved"] += 1
            elif rec["outcome"] in caught and new_rec["outcome"] in bypass:
                counts["regressed"] += 1
        if i % 30 == 0:
            print(f"  [{i:>3}/{len(before)}] {counts}", flush=True)

    (out_dir / "run.json").write_text(json.dumps(after, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = _summarize(after)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "report.md").write_text(_render_report(after, summary, out_dir), encoding="utf-8")
    (out_dir / "delta.md").write_text(_render_delta(before, after), encoding="utf-8")

    print(f"\n[done] {len(after)} rows re-judged. {counts['changed']} changed "
          f"({counts['improved']} improvements, {counts['regressed']} regressions).")
    print(f"  json:    {out_dir/'run.json'}")
    print(f"  summary: {out_dir/'summary.json'}")
    print(f"  report:  {out_dir/'report.md'}")
    print(f"  delta:   {out_dir/'delta.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
