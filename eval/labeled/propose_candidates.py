"""Generate labels_candidates.json — AI-proposed labels queued for human review.

The labeling protocol in eval/labeled/README.md explicitly rejects AI-only
review for the ground-truth corpus (labels.json):

> Weak evidence (`confidence ≤ 0.5`):
>   - AI-only review (no human eyes).
> Weak-evidence labels are NOT shipped to `labels.json` by design.

This script doesn't violate that — it writes to a SEPARATE file
(`labels_candidates.json`) that's an explicit review queue. The user
reads each entry, agrees or disagrees, and promotes to labels.json
manually (deleting the candidate entry once promoted).

Inputs:
- eval/llm_fallback/results/<latest>/pilot.json — LLM-extracted tools +
  signals on the 20 v0.1.7 unknowns.
- eval/labeled/labels.json — to skip packages already labeled.

For each candidate:
- ai_confidence is clamped to 0.5-0.6 per protocol (weak evidence).
- proposed_label is derived from the cached pilot's after_verdict
  with a one-step-down haircut (LLM said malicious -> we propose
  suspicious; LLM said benign -> we propose benign; shallow/unknown ->
  needs_review).
- The full LLM rationale and signal set is preserved in `ai_evidence`
  so the human reviewer can audit the proposal without re-running.

Usage:
    python -m eval.labeled.propose_candidates
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


# Map cached pilot after_verdict -> candidate label (one step down on
# severity; AI shouldn't claim "malicious" at weak confidence).
_VERDICT_DOWNGRADE = {
    "malicious":  ("suspicious", 0.60),
    "suspicious": ("suspicious", 0.55),
    "benign":     ("benign",     0.55),
    "shallow":    ("needs_review", 0.50),
    "unknown":    ("needs_review", 0.50),
}


def _unversion(source: str) -> str:
    """Same dedup logic as bootstrap.py — npm-scoped-aware."""
    if source.startswith("pypi:"):
        return source.split("==", 1)[0]
    if source.startswith("npm:@"):
        parts = source.rsplit("@", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0]
        return source
    if source.startswith("npm:"):
        return source.split("@", 1)[0]
    return source


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot",  default="eval/llm_fallback/results/v0.1.10/pilot.json")
    ap.add_argument("--labels", default="eval/labeled/labels.json")
    ap.add_argument("--out",    default="eval/labeled/labels_candidates.json")
    args = ap.parse_args()

    pilot_path = Path(args.pilot)
    if not pilot_path.exists():
        print(f"ERROR: pilot results not found: {pilot_path}")
        return 2

    labeled = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    already = {_unversion(entry["source"]) for entry in labeled["labels"]}

    pilot = json.loads(pilot_path.read_text(encoding="utf-8"))

    candidates: list[dict] = []
    for r in pilot:
        if _unversion(r["source"]) in already:
            continue
        before = r["before_verdict"]
        after = r["after_verdict"]
        if not after or after == "error":
            continue
        proposed, ai_conf = _VERDICT_DOWNGRADE.get(after, ("needs_review", 0.50))
        if proposed == "needs_review":
            # Don't write needs_review into candidates — that's redundant
            # with the existing needs_review.json bootstrap output.
            continue
        candidates.append({
            "name": r["name"],
            "ecosystem": r["ecosystem"],
            "source": r["source"],
            "proposed_label": proposed,
            "ai_confidence": ai_conf,
            "ai_rationale": (
                f"AI proposal from LLM-fallback pilot (v0.1.10). The LLM extracted "
                f"{len(r['extracted_tools'])} tool(s) from the package source: "
                f"{', '.join(r['extracted_tools'][:5])}"
                f"{', ...' if len(r['extracted_tools']) > 5 else ''}. "
                f"LLM notes: \"{(r['llm_extraction_notes'] or '').strip()[:200]}\". "
                f"MIS v0.1.10 classifier verdict on the LLM-extracted signals: {after}. "
                f"AI-proposed label is one severity step below the verdict — `{proposed}` — "
                f"because AI-only review qualifies as weak evidence per the eval/labeled "
                f"protocol; the proposal needs human source-reading to promote to "
                f"labels.json. The full LLM signal extraction per tool is in `ai_evidence` "
                f"below; the v0.1.7 static-MIS verdict was `{before}`."
            ),
            "needs_human_review": True,
            "ai_evidence": {
                "static_mis_v0.1.7_verdict": before,
                "llm_classifier_v0.1.10_verdict": after,
                "extracted_tools_count": len(r["extracted_tools"]),
                "extracted_signals_per_tool": r["extracted_signals_per_tool"],
                "llm_extraction_notes": r["llm_extraction_notes"],
                "source_pilot_run": str(pilot_path),
            },
        })

    # Sort: malicious candidates first (most worth reviewing), then suspicious,
    # then benign. Within each, alphabetical.
    severity = {"malicious": 0, "suspicious": 1, "benign": 2, "needs_review": 3}
    candidates.sort(key=lambda c: (severity.get(c["proposed_label"], 9), c["name"]))

    out = {
        "version": 1,
        "generated_from_pilot": str(pilot_path),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n_candidates": len(candidates),
        "candidates": candidates,
    }
    Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(candidates)} candidates to {args.out}")
    by_label: dict[str, int] = {}
    for c in candidates:
        by_label[c["proposed_label"]] = by_label.get(c["proposed_label"], 0) + 1
    for k, v in sorted(by_label.items()):
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
