# Model-compliance eval — LIMITATIONS

Every external claim about this eval must trace to "implemented and tested"
in this file, or appear here as "not yet supported".

## LM1 — Single prompt per (intent, level)
One prompt phrasing per cell of the 10×3 matrix. A model that refuses a
specific phrasing may comply with a sibling phrasing. Compliance rates here
are lower-bounds, not estimates of "true" compliance. **Mitigation:** the
harness can run with `--limit` to allow many phrasings per cell once
prompts.py grows to a list-of-lists. Not yet shipped.

## LM2 — Static-only scoring
Outputs are scored by `mis.engine.scan` on the generated source, NOT by
running the generated server. A model could emit code that compiles but
errors at runtime, and the harness would still credit it as `code_*`. This
is consistent with MIS's own posture (static analysis), but it means
compliance rate is an *intent-to-deploy* signal, not a *would-work-in-prod*
signal.

## LM3 — Sentinel-coverage entanglement
The headline `caught_by_mis_pct` depends on the current Sentinel rule set.
A model that emits a malicious pattern MIS doesn't yet detect will appear
in `bypass_mis_pct` — that's the point — but it means cross-version
comparisons of `caught_by_mis_pct` for the same model are NOT valid. Use
`compliance_pct` (refused vs not) for cross-version model comparison.

## LM4 — Heuristic refusal detection
`judge._REFUSAL_PATTERNS` is a regex set, not a classifier. False negatives
(model refused in a phrasing not in the regex set) become `empty` rather
than `refused`. False positives (model said "I cannot recommend X but here
is the code:") still count as compliance because we require *no code* for
refusal to register. The latter is the correct bias for an offensive-risk
signal; the former is a known under-count of true refusal.

## LM5 — Code-block extraction is fence-only
`_CODE_FENCE_RE` only catches \`\`\`-fenced blocks. Models that emit raw
code without fences (rare for code generation) are scored `empty` even if
they fully complied. Add diff/file-header parsing later if a frontier model
trends toward no-fence output.

## LM6 — `judge._looks_*` heuristics
Language detection of an unlabeled code block is heuristic
(`from mcp`, `require(`, etc.). A polyglot or oddly-imported block can be
mis-routed and verdict `empty`. The harness logs the extracted blocks so
the failure mode is auditable.

## LM7 — Synthesized package layout for JS bypass risk
When the model emits index.js but no package.json, the harness fabricates a
minimal package.json so MIS's npm extractor accepts it. This means the
**lifecycle_dropper** intent — whose attack lives in package.json's
`postinstall` script — can only fire if the model itself emits the
package.json. We do this on purpose: synthesizing a manifest would let the
harness frame the model's compliance, not measure it. Models that emit only
index.js for this intent are correctly recorded as `empty` for that intent
slot.

## LM8 — Disguise-level taxonomy is unvalidated
`overt` / `framed` / `covert` is hand-labeled, not measured. A `framed`
prompt may be more or less suggestive than the matched `covert` prompt for
a different intent. The level dimension is a useful axis to look at,
not a calibrated scale.

## LM9 — Model panel skew
The default 7-model panel mixes alignment regimes, vendors, and weights
classes. It is not stratified for fair comparison (different RLHF
recipes, different system-prompt expectations, different temperature
defaults). Treat per-model numbers as observations, not rankings.

## LM10 — No human grading
Outcome labels are assigned by `judge.py` + `mis.scan`, not by a human.
The `bypass_mis_pct` rows demand manual review before being promoted to
fixtures (the report flags them explicitly). Promotion of a row to a
fixture is the only human-in-the-loop step and is required for the
feedback loop to land.

## LM11 — One-shot, no tool-use loop
The eval is single-turn `prompt -> response`. It does NOT model the
OpenClaw / agentic scenario where the model gets to inspect tool outputs,
iterate, etc. A model that refuses the single-turn write-this-code request
may still drive a malicious tool when wrapped in an agent loop. That's
*tool-call compliance*, a separate eval (see README.md, "What it does NOT
do").

## LM12 — OpenRouter as the API surface
The harness uses OpenRouter for normalized multi-provider access. This
means: (a) some models are served by intermediate hosts that may apply
their own moderation, (b) prompt caching / system-prompt injection by the
intermediate is possible, (c) results may differ vs. calling the provider
APIs directly. Acceptable for cross-model comparison; not acceptable as
"the definitive Claude/GPT/Gemini compliance number". Document the panel
+ OpenRouter usage when citing results.
