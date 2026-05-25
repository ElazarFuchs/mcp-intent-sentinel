"""L11 harness: scan every labeled package with MIS, compare verdict to label.

This is the metrics-on-ground-truth half of the eval suite. The 51-server
`eval/run.py` measures verdict DISTRIBUTION on a representative sample; this
harness measures verdict ACCURACY on a smaller, human-labeled set.

Usage:
    python -m eval.labeled.run                                  # full run
    python -m eval.labeled.run --out eval/labeled/results/dryrun
    python -m eval.labeled.run --labels eval/labeled/labels.json --out ...

Writes:
    <out>/confusion.json   — every row + the classification (TP/FP/TN/FN/etc.)
    <out>/confusion.md     — human-readable summary + the per-class metrics

Definitions (see eval/labeled/README.md for the full matrix):
    TP  — label malicious or suspicious, MIS verdict suspicious or malicious.
    FP  — label benign,    MIS verdict suspicious or malicious.
    TN  — label benign,    MIS verdict benign.
    FN  — label malicious, MIS verdict benign.
    coverage-gap — label *,            MIS verdict shallow or unknown.
                   NOT counted as error — MIS admitted it couldn't analyze.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from mis import __version__ as mis_version
from mis.engine import scan as mis_scan
from mis.extractors import ExtractionError


_THREAT_VERDICTS = {"suspicious", "malicious"}
_COVERAGE_VERDICTS = {"shallow", "unknown"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _classify(label: str, verdict: str | None) -> str:
    """Return one of: TP, FP, TN, FN, coverage_gap, error, unknown_label."""
    if verdict is None:
        return "error"
    if verdict in _COVERAGE_VERDICTS:
        return "coverage_gap"
    if label == "benign":
        if verdict == "benign":
            return "TN"
        if verdict in _THREAT_VERDICTS:
            return "FP"
        return "unknown_label"
    if label in {"suspicious", "malicious"}:
        if verdict in _THREAT_VERDICTS:
            return "TP"
        if verdict == "benign":
            return "FN"
        return "unknown_label"
    return "unknown_label"


def _run_one(entry: dict) -> dict:
    """Scan a single labeled entry. Returns a row dict."""
    row = {
        "name": entry["name"],
        "ecosystem": entry["ecosystem"],
        "source": entry["source"],
        "label": entry["label"],
        "confidence": entry["confidence"],
        "reviewer": entry["reviewer"],
        "date_labeled": entry["date_labeled"],
        "rationale_first_60": entry["rationale"][:60],
        "ok": False,
        "duration_seconds": None,
        "error": None,
        "verdict": None,
        "verdict_confidence": None,
        "verdict_reason": None,
        "rule_hits": None,
        "tools_detected": None,
        "tools_with_behavior": None,
        "classification": "error",
    }
    start = time.perf_counter()
    try:
        result, hits = mis_scan(entry["source"])
        row["ok"] = True
        row["verdict"] = result.verdict
        row["verdict_confidence"] = round(result.verdict_confidence, 2)
        row["verdict_reason"] = (result.verdict_reason or "")[:300]
        row["rule_hits"] = [h.rule_id for h in (hits or [])]
        tools = list(getattr(result, "tools", []) or [])
        row["tools_detected"] = len(tools)
        row["tools_with_behavior"] = sum(1 for t in tools if getattr(t, "behavior", None))
    except ExtractionError as e:
        row["error"] = f"ExtractionError: {e}"
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
    row["duration_seconds"] = round(time.perf_counter() - start, 2)
    row["classification"] = _classify(entry["label"], row["verdict"])
    return row


def _confusion(rows: list[dict]) -> dict:
    """Build the per-cell confusion matrix and the headline metrics."""
    cells: dict[tuple[str, str], int] = {}
    by_class: dict[str, int] = {
        "TP": 0, "FP": 0, "TN": 0, "FN": 0,
        "coverage_gap": 0, "error": 0, "unknown_label": 0,
    }
    for r in rows:
        by_class[r["classification"]] = by_class.get(r["classification"], 0) + 1
        if r["verdict"] is not None:
            cells[(r["label"], r["verdict"])] = cells.get((r["label"], r["verdict"]), 0) + 1

    tp = by_class["TP"]; fp = by_class["FP"]; tn = by_class["TN"]; fn = by_class["FN"]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall    = tp / (tp + fn) if (tp + fn) else None

    return {
        "by_class": by_class,
        "cells": [
            {"label": k[0], "verdict": k[1], "count": v}
            for k, v in sorted(cells.items())
        ],
        "metrics": {
            "precision": round(precision, 3) if precision is not None else None,
            "recall":    round(recall,    3) if recall    is not None else None,
            "n_threat_labels": tp + fn,
            "n_benign_labels": tn + fp,
            "n_total":          sum(by_class.values()),
        },
    }


def _render(rows: list[dict], conf: dict, mis_v: str) -> str:
    out: list[str] = []
    out.append(f"# Labeled-corpus confusion — MIS v{mis_v}, {_now_iso()}\n")
    m = conf["metrics"]
    out.append(f"**N**: {m['n_total']} labeled rows ({m['n_threat_labels']} threat, {m['n_benign_labels']} benign).")
    if m["precision"] is not None:
        out.append(f"**Precision** (on threat verdicts): {m['precision']}")
    if m["recall"] is not None:
        out.append(f"**Recall**: {m['recall']}")
    out.append("")
    out.append("Precision/recall are defined ONLY over (TP+FP) / (TP+FN). Coverage-gap")
    out.append("verdicts (`shallow` / `unknown`) are NOT errors — MIS admitted it couldn't analyze")
    out.append("— and are reported separately.\n")

    out.append("## Counts by classification\n")
    out.append("| classification | count | meaning |")
    out.append("|---|---:|---|")
    desc = {
        "TP": "label malicious/suspicious  →  MIS verdict malicious/suspicious",
        "FP": "label benign  →  MIS verdict malicious/suspicious",
        "TN": "label benign  →  MIS verdict benign",
        "FN": "label malicious/suspicious  →  MIS verdict benign",
        "coverage_gap": "label *  →  MIS verdict shallow/unknown (not an error)",
        "error":        "MIS extraction failed (download / parse)",
        "unknown_label": "label not in {benign, suspicious, malicious} — data bug",
    }
    for k in ("TP", "FP", "TN", "FN", "coverage_gap", "error", "unknown_label"):
        out.append(f"| {k} | {conf['by_class'][k]} | {desc[k]} |")
    out.append("")

    out.append("## Per-row\n")
    out.append("| name | label | verdict | classification | rule_hits | tools | confidence |")
    out.append("|---|---|---|---|---|---:|---:|")
    for r in rows:
        hits = ", ".join(r["rule_hits"] or [])[:60]
        v = r["verdict"] or "ERROR"
        cls = r["classification"]
        cls_mark = {"TP": "TP", "FP": "**FP**", "FN": "**FN**", "TN": "TN",
                    "coverage_gap": "coverage", "error": "error"}.get(cls, cls)
        out.append(
            f"| `{r['name']}` | {r['label']} | {v} | {cls_mark} | {hits} | "
            f"{r['tools_detected'] if r['tools_detected'] is not None else '-'} | "
            f"{r['confidence']} |"
        )
    out.append("")

    # Coverage detail — which labeled rows MIS couldn't see through
    cov = [r for r in rows if r["classification"] == "coverage_gap"]
    if cov:
        out.append("## Coverage gaps on labeled rows\n")
        out.append("These rows have a label but MIS verdicted `shallow` / `unknown`. Each one")
        out.append("is an SDK-coverage signal — closing the gap would let MIS confirm-or-deny")
        out.append("the label. NOT an error in the FP/FN sense; an error of omission to track.\n")
        out.append("| name | label | verdict | reason |")
        out.append("|---|---|---|---|")
        for r in cov:
            reason = (r["verdict_reason"] or "")[:80].replace("|", "/")
            out.append(f"| `{r['name']}` | {r['label']} | {r['verdict']} | {reason} |")
        out.append("")

    durs = [r["duration_seconds"] for r in rows if isinstance(r["duration_seconds"], (int, float))]
    if durs:
        out.append("## Timings\n")
        out.append(f"- p50 latency: {statistics.median(durs):.1f}s")
        out.append(f"- max latency: {max(durs):.1f}s")

    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="eval/labeled/labels.json")
    ap.add_argument("--out",    default=None)
    ap.add_argument("--limit",  type=int, default=None)
    args = ap.parse_args()

    labels_path = Path(args.labels)
    if not labels_path.exists():
        print(f"ERROR: labels file not found: {labels_path}", file=sys.stderr)
        return 2

    data = json.loads(labels_path.read_text(encoding="utf-8"))
    entries = data["labels"]
    if args.limit:
        entries = entries[:args.limit]

    out_dir = Path(args.out or f"eval/labeled/results/v{mis_version}")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[start] MIS v{mis_version}, {len(entries)} labeled entries, out={out_dir}", flush=True)
    t0 = time.time()
    rows: list[dict] = []
    for i, entry in enumerate(entries, 1):
        row = _run_one(entry)
        rows.append(row)
        cls = row["classification"]
        v = row["verdict"] or row["error"] or "?"
        print(f"  [{i:>3}/{len(entries)}] {entry['source'][:50]:<50}  label={entry['label']:<10} "
              f"verdict={v:<12} -> {cls}", flush=True)

    conf = _confusion(rows)
    (out_dir / "confusion.json").write_text(
        json.dumps({"mis_version": mis_version, "rows": rows, "confusion": conf},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "confusion.md").write_text(_render(rows, conf, mis_version), encoding="utf-8")
    print(f"\n[done] {time.time()-t0:.0f}s wall.")
    print(f"  json: {out_dir/'confusion.json'}")
    print(f"  md:   {out_dir/'confusion.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
