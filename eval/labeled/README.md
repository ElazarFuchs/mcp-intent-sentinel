# Labeled corpus (L11)

> **Status:** seed only. The framework is shipped; the corpus grows by manual
> review. Every label added here is a claim — back it with a rationale and
> initials before committing.

This directory closes the methodological gap surfaced as
[LIMITATIONS.md L11](../../LIMITATIONS.md): every claim MIS makes about its own
false-positive / false-negative rate has to compare against ground truth. The
51-server `eval/registry.py` measures verdict distribution on a representative
sample, but it does NOT carry human labels — so claims like "MIS's FP rate is
12%" are anecdotal until each "benign" verdict is independently confirmed.

`labels.json` is that ground truth. `run.py` is the harness that compares MIS's
verdict to the label, producing a confusion matrix per MIS version.

## Layout

```
eval/labeled/
├── README.md       (this file)
├── labels.json     (the ground truth — append-only, version-controlled)
├── run.py          (scans every labeled pkg, compares vs label, writes confusion.md)
├── bootstrap.py    (ingests eval/results/v0.1.X/ and emits needs_review stubs)
├── propose_candidates.py
│                   (reads the cached LLM-fallback pilot output and emits
│                    labels_candidates.json — AI-proposed labels at weak
│                    confidence, queued for human review)
├── needs_review.json
│                   (bootstrap output — packages MIS sees but no label exists yet,
│                    sorted by review priority)
├── labels_candidates.json
│                   (AI-proposed labels at confidence ≤ 0.6 — NOT a substitute
│                    for human-vetted labels.json entries. The user reads each
│                    candidate, agrees / disagrees, and promotes (with their
│                    own rationale + initials) to labels.json, deleting the
│                    candidate entry once promoted.)
└── results/
    └── v0.1.X/
        ├── confusion.json   (machine-readable)
        └── confusion.md     (human-readable)
```

## The protocol

A label is a claim that **a specific version of a specific package on a
specific registry** is benign / suspicious / malicious. Three rules:

1. **Pin the version.** `npm:foo@1.2.3`, not `npm:foo`. Latest can change
   under you; a label that doesn't pin is a label that may not match what
   was reviewed.
2. **State the rationale.** One paragraph minimum. What did you read, what
   did you conclude, what could change your mind.
3. **Sign and date.** Reviewer initials + ISO date. If multiple reviewers
   agree, list both.

The label classes — match MIS's verdict scheme:

| Label | Meaning |
|---|---|
| `benign` | Behavior matches the declared purpose, no exfil channels, no shell injection, no supply-chain dropper, no description poisoning. |
| `suspicious` | Has a real risk signal (net-on-import / typosquat-name / odd description) but isn't conclusive exfil. Worth caution; not worth quarantine. |
| `malicious` | Confirmed exfil / RCE / supply-chain hijack / tool poisoning. Backed by source-reading or a public CVE. |

The label is the **ground truth** — MIS's verdict can disagree, and that
disagreement is the signal we want to surface (TP / FP / TN / FN).

## What counts as evidence

Strong evidence (`confidence ≥ 0.9`):
- A public CVE or vendor advisory with the package named and the malicious
  behavior described.
- Source-reading by ≥2 independent reviewers who reach the same conclusion.
- Reproduction of the malicious behavior in a sandbox (`benign` cannot be
  established by reproduction alone — absence isn't proof of absence —
  but `malicious` can).

Medium evidence (`confidence ≈ 0.7`):
- Source-reading by one experienced reviewer, no contradicting signals.
- Vendor-published source with active maintenance, public bug tracker, no
  suspicious patterns visible in cursory review.

Weak evidence (`confidence ≤ 0.5`):
- Reputation only ("the maintainer is well-known").
- Indirect signal ("Anthropic published it" → presumed benign).
- AI-only review (no human eyes).

**Weak-evidence labels are NOT shipped to `labels.json`.** They go in
`labels_candidates.json` or a separate review queue, never into the corpus
that the harness compares MIS against. Weak evidence in the corpus would
generate false confidence in MIS metrics — exactly the failure mode this
file exists to prevent.

## Confusion matrix interpretation

Rows = true label. Columns = MIS verdict.

|              | mis:benign | mis:shallow | mis:unknown | mis:suspicious | mis:malicious |
|---|---|---|---|---|---|
| **label:benign**     | TN | coverage-gap | coverage-gap | **FP** | **FP** |
| **label:suspicious** | downgrade | coverage-gap | coverage-gap | TP | TP-overcall |
| **label:malicious**  | **FN** | **FN-shallow** | **FN-unknown** | TP-undercall | TP |

Notes:
- `coverage-gap` (shallow/unknown on labeled-benign) is NOT an error — it's
  MIS admitting it couldn't analyze. Tracked separately from FP rate.
- `FN-shallow` and `FN-unknown` on labeled-malicious ARE errors of omission
  (we missed it AND admitted we couldn't see it — better than `FN` outright,
  but the malicious package still went out to users).
- `TP-overcall` (malicious verdict on labeled-suspicious) is conservative
  but acceptable — better to over-flag than under-flag at runtime.
- `TP-undercall` (suspicious verdict on labeled-malicious) is a partial win;
  the verdict surfaced something, but understated the severity.

## Seed entries (v0.1.7)

5 hand-vetted labels — 1 public-disclosure malicious + 4 Anthropic-monorepo
benigns. v0.1.13 added 10 more synthetic-labeled entries from the test
corpus — see "Synthetic fixtures as labels" below.

| name | label | source | reviewer | confidence |
|---|---|---|---|---|
| `postmark-mcp` | malicious | npm:postmark-mcp@1.0.16 | EF | 0.99 |
| `mcp-server-time` | benign | pypi:mcp-server-time | EF | 0.85 |
| `@modelcontextprotocol/server-everything` | benign | npm:@modelcontextprotocol/server-everything | EF | 0.85 |
| `@modelcontextprotocol/server-filesystem` | benign | npm:@modelcontextprotocol/server-filesystem | EF | 0.80 |
| `mcp-server-fetch` | benign | pypi:mcp-server-fetch | EF | 0.85 |

`postmark-mcp@1.0.16` is the known in-the-wild backdoor disclosed in 2025
(the `postmark_backdoor` fixture in `tests/corpus/malicious/` is modeled on
it). The Anthropic-monorepo entries are widely-installed, source-public, and
have been reviewed by both the project authors and outside scanners — high
but not perfect confidence (`benign` is asymptotic; new commits could
change this — version-pinning is the mitigation).

## Synthetic fixtures as labels (v0.1.13)

Pre-v0.1.13 the corpus had exactly one `malicious` entry — `postmark-mcp@1.0.16`
— which was YANKED from npm after disclosure, so the harness reported it
as `error` and recall was effectively undefined. v0.1.13 added the 10
in-house `tests/corpus/malicious/*` fixtures as `file://` labels with a
`synthetic: true` flag.

Every synthetic label is honest about what it is — these fixtures were
hand-authored as regression tests by MIS authors, so labels against them
measure MIS's *agreement with its own taste*, NOT MIS's recall on
in-the-wild malware. They are useful as non-zero TP data points for
detecting regressions, and as a smoke test that the harness end-to-end
works — but they MUST NOT be cited as evidence that MIS catches real-
world threats. The `synthetic: true` field on every fixture-derived
entry exists so reports can split synthetic-vs-in-the-wild and never
claim general recall from synthetic-only data.

When (if) more in-the-wild malicious MCP packages get publicly
disclosed, they should be labeled WITHOUT the `synthetic` flag, and
the cited recall numbers should be split (synthetic recall: high;
in-the-wild recall: TBD until the corpus grows).

## AI-proposed candidates (labels_candidates.json)

`propose_candidates.py` reads the cached LLM-fallback pilot output and
emits `labels_candidates.json` — AI-proposed labels for packages MIS-
unknown'd in v0.1.7 that the LLM-fallback path was able to extract tools
from. Per the labeling protocol above, AI-only review is weak evidence
and these proposals MUST NOT enter `labels.json` automatically. The
candidates file is a review queue: each entry has `ai_confidence` (0.5-
0.6), `ai_rationale` (what the LLM extracted), `ai_evidence` (the full
LLM tool / signal list), and `needs_human_review: true`.

Promotion workflow:
1. Read the AI proposal + evidence.
2. Open the package source (`pip download` / `npm pack`) and read enough
   to back the label yourself.
3. If you agree: write your own rationale (your read of the source, not
   a copy of the AI rationale), set `confidence` 0.7-0.9, sign with
   your initials, and append to `labels.json`. Delete the candidate
   from `labels_candidates.json`.
4. If you disagree: write a one-line note about why in the candidate
   and either reduce `ai_confidence` to 0.3 (review-needed flag stays
   set) or delete the candidate outright if it's clearly wrong.

This separation is the methodological commitment — `labels.json` is
ground truth, `labels_candidates.json` is a triage queue, AI never
crosses the line into ground truth without you in the loop.

## Adding a label

1. Open the source for the candidate package (`npm pack`, `pip download`,
   or browse on registry).
2. Read enough of it to back the label. For most servers that's the
   tool registrations + body of every tool. For bundled npm output, that's
   harder — note bundling in the rationale and consider whether the label
   should be deferred.
3. Append an entry to `labels.json`. The schema is strict — fields:
   `name`, `ecosystem` (npm/pypi), `source` (versioned spec MIS can extract),
   `label` (benign/suspicious/malicious), `rationale` (one paragraph),
   `reviewer` (initials), `date_labeled` (ISO date), `confidence` (0.5-0.99).
4. Run `python -m eval.labeled.run` to see how MIS verdicts your new
   addition.
5. Commit with a short message naming the package + label.

## What this is NOT

- It is NOT a replacement for the 51-server eval. That eval measures
  distribution on a sample drawn for representativeness, not for label
  certainty. This file measures *accuracy* on a smaller, ground-truthed
  set.
- It is NOT a public-facing list of "good MCP servers" or "bad MCP servers".
  Labels are for measuring MIS, not for endorsing or warning about
  packages. A `malicious` label here is a research label, not a CVE.
- It is NOT static. Labels can be revised (with rationale) if new evidence
  emerges. `confidence` should drop as time-since-last-review increases.
