"""Generate needs_review stubs from a 51-server eval run.

Reads `eval/results/v0.1.X/run.json`, drops any package already present in
`eval/labeled/labels.json`, and writes a `needs_review.json` with one stub
per remaining package. The stub carries MIS's verdict as a hint — NOT as
the label. A reviewer must read the source and commit a real label before
the row migrates into `labels.json`.

Usage:
    python -m eval.labeled.bootstrap                            # uses v0.1.7
    python -m eval.labeled.bootstrap --eval-results eval/results/v0.1.7
    python -m eval.labeled.bootstrap --out eval/labeled/needs_review.json

The output file is a review queue, not a corpus. It MUST NOT be loaded
by `run.py` as if its `candidate_label` field were ground truth — that
would defeat the entire point of L11.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def _unversion(source: str) -> str:
    """Strip a version pin off an extractor source spec, dedup-safe across
    scoped npm packages (where `@` is part of the name, not the version sep).

    Examples:
        npm:postmark-mcp@1.0.16                       -> npm:postmark-mcp
        npm:@modelcontextprotocol/server-everything   -> npm:@modelcontextprotocol/server-everything
        npm:@scope/pkg@2.3.4                          -> npm:@scope/pkg
        pypi:mcp-server-fetch==2025.4.7               -> pypi:mcp-server-fetch
        pypi:mcp-server-time                          -> pypi:mcp-server-time
    """
    if source.startswith("pypi:"):
        return source.split("==", 1)[0]
    if source.startswith("npm:@"):
        # Scoped — `@` at column 4 is part of the name. Version sep is the
        # SECOND `@` (rsplit picks it).
        parts = source.rsplit("@", 1)
        # Heuristic: if the right-hand side starts with a digit, it's a version.
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0]
        return source
    if source.startswith("npm:"):
        return source.split("@", 1)[0]
    return source


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval-results", default="eval/results/v0.1.7")
    ap.add_argument("--labels",       default="eval/labeled/labels.json")
    ap.add_argument("--out",          default="eval/labeled/needs_review.json")
    args = ap.parse_args()

    eval_run = Path(args.eval_results) / "run.json"
    if not eval_run.exists():
        print(f"ERROR: {eval_run} not found")
        return 2

    labeled = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    already = {_unversion(entry["source"]) for entry in labeled["labels"]}

    eval_data = json.loads(eval_run.read_text(encoding="utf-8"))
    records = eval_data if isinstance(eval_data, list) else eval_data.get("records", [])

    stubs: list[dict] = []
    for rec in records:
        if not rec.get("ok"):
            continue
        source = rec.get("source")
        if not source:
            continue
        # Match by un-versioned source key — labels can pin a different version.
        if _unversion(source) in already:
            continue
        verdict = rec.get("verdict")
        # Reviewer-priority hint — what's most worth manual time:
        #   threat verdicts: confirm-or-clear FPs (high priority)
        #   shallow/unknown: closes the coverage gap once labeled
        #   benign: lowest priority — MIS agrees with no-issue, but a confident
        #           benign label still adds a TN data point
        priority = {
            "malicious":  1,
            "suspicious": 2,
            "shallow":    3,
            "unknown":    4,
            "benign":     5,
        }.get(verdict, 6)
        stubs.append({
            "name": rec.get("name") or source,
            "ecosystem": rec.get("ecosystem"),
            "source": source,                  # un-pinned; reviewer pins on label
            "candidate_label": "needs_review",
            "mis_verdict_hint": verdict,
            "mis_verdict_confidence_hint": rec.get("verdict_confidence"),
            "review_priority": priority,
            "rule_hits_hint": rec.get("rule_hits") or [],
            "generated_from": str(eval_run),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    stubs.sort(key=lambda s: (s["review_priority"], s["name"]))
    Path(args.out).write_text(json.dumps({"stubs": stubs}, indent=2, ensure_ascii=False),
                              encoding="utf-8")
    print(f"Wrote {len(stubs)} stubs to {args.out}")
    by_priority = {}
    for s in stubs:
        by_priority.setdefault(s["mis_verdict_hint"] or "extract_fail", 0)
        by_priority[s["mis_verdict_hint"] or "extract_fail"] += 1
    for k, v in sorted(by_priority.items()):
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
