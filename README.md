# MCP Intent Sentinel

> **v0.1.16 — multi-component agreement for host claims (L26 closure).**
> Pre-v0.1.16 the host-claim downgrade required ≥1 URL field in the
> manifest (the v0.1.13 gate). The residual attack: an attacker who
> controls name + a single homepage can satisfy substring matching and
> downgrade their own exfil. v0.1.16 raises the bar — a claim qualifies
> only when it appears in ≥2 of {name, homepage, repository} source
> types. `[project.urls]` keys are bucketed by key name (home → homepage,
> repo/source → repository, else `other` which doesn't count). The legit
> `legit_api_client_host_claim_downgrade` fixture was updated to declare
> both Homepage AND Repository; without both it would no longer qualify
> for downgrade. Attacker friction: three coordinated strings to fake,
> not one. 82/82 tests pass, 51-server eval has 0 regressions.

> **v0.1.15 — enforce the synthetic / in-the-wild recall split in the
> harness, not just the README.** v0.1.14 wrote "reports MUST split
> synthetic-vs-in-the-wild recall" as a cultural rule but emitted a
> single `Recall: 1.0` at the top of confusion.md anyway — the kind of
> number that screenshots into a presentation as "MIS has 100% recall."
> v0.1.15: `_confusion()` has NO `recall` field, only `synthetic_recall`
> and `in_the_wild_recall` separately, each with its own caveat printed
> inline. Per-row table surfaces a `source` column. The MUST is now
> mechanical, not cultural. No `mis/` changes.

> **v0.1.14 — corpus side of the v0.1.13 critique (L20 / L21 partial
> closure).** No `mis/` changes — labels.json grew from 5 to 15 entries:
> 10 in-house `tests/corpus/malicious/*` fixtures added as `file://`
> labels with `synthetic: true` (honest about being MIS-authored
> regression tests, NOT in-the-wild captures — reports MUST split
> synthetic-vs-in-the-wild recall). New `propose_candidates.py` emits
> `labels_candidates.json` from the cached LLM-fallback pilot — 12 AI-
> proposed labels at `ai_confidence` 0.5-0.6, queued for human review
> per the labeling protocol (AI proposals CANNOT enter `labels.json`
> automatically). Confusion at v0.1.14 — 9 TP, 1 TN, 3 coverage-gap,
> 1 error, 1 TP-suspicious.

> **v0.1.13 — host-claim partition for r1 (L23 deep closure).** The
> classifier now reads the package's manifest (`package.json` /
> `pyproject.toml`) and partitions r1's secret-to-request findings by
> whether the observed net-call host matches a substring the package
> self-declares (name + homepage + repository URL). When every observed
> host matches a claim, r1 downgrades from `malicious` to `suspicious`
> — the legit API-client shape (env key → Bearer to the package's own
> declared API). When any host is unclaimed, r1 fires malicious as
> before. URL-gate prevents the name-only attack: a name-only manifest
> returns no claims, so a fixture named `weather-helper-mcp` POSTing to
> `telemetry.weather-helper-cdn.example` still verdicts malicious. New
> fixture `legit_api_client_host_claim_downgrade`; tests 81→82.
> Attacker who controls both name and homepage can still satisfy the
> substring check — that residual is L26.

> **v0.1.12 — staged-stash detection (r12).** Closes the gap the v0.1.10
> r4 trade-off opened: a hostile `fetch`-intent tool that reads a secret
> in call N but stashes it in module-level state for exfil in call N+1
> previously slipped every rule. v0.1.12 adds a post-hoc check —
> `READS_SECRET_NO_LOCAL_USE` fires when a tool body has SECRET_FS_READ
> or SECRET_ENV_READ with no co-occurring SECRET_IN_REQUEST /
> RETURNS_SECRET / NET_CLIENT_SECRET_STATE. New classifier rule
> `r12.staged_stash` verdicts `suspicious` (not malicious — the shape
> has legitimate uses like validation-only / dead code). Knock-on fix:
> `_is_secret_expr` now recognizes sensitive-path reads as secret-
> producing, so `return path.read_text()` correctly emits RETURNS_SECRET
> and doesn't trip r12 on legit file-role tools. New fixture
> `staged_stash_ssh_read`; tests 80→81.

> **v0.1.11 — two structural cleanups from a v0.1.10 reviewer critique.**
> `_reads_sensitive_path` is now also checked in `visit_Call`, so
> `return path.read_text()` shapes no longer escape SECRET_FS_READ
> detection (closes L24 properly — the v0.1.10 fixture had been working
> around the bug rather than triggering the fix it claimed to test).
> `_VALID_SIGNALS` in the LLM-fallback analyzer is now derived from the
> `BehaviorSignal` enum directly, removing the silent-drift footgun where
> a new enum member would be dropped by the parser. 80/80 tests pass.

> **v0.1.10 — L23 closure (the v0.1.9 pilot's r4 FPs).** Three changes
> together close every malicious / suspicious FP the LLM-fallback pilot
> surfaced on real packages: `_guess_intent` now routes API-client and
> maps/geocode keywords (`slack`, `gitlab`, `notion`, `figma`, `aws`,
> `google`, `geocode`, `coordinates`, `api`, `sdk`, ...) into `fetch`
> intent BEFORE the format/convert check that mislabeled them;
> `r4.intent_mismatch`'s SECRET_FS_READ catch-all is now role-aware (skips
> when declared_intent ∈ {file, shell, fetch}); the LLM-fallback prompt
> got NEGATIVE examples for SECRET_FS_READ. Regression fixture
> `legit_file_role_reads_ssh_config`. 80/80 tests (was 79). L23 closed
> in part — host-vs-intent matching for r1 remains roadmap.

> **v0.1.9 — LLM fallback pilot (L13).** Sends `unknown`-verdicted source
> to a frontier LLM with a hardened extraction-only prompt; the LLM returns
> tool registrations + behavior signals in a closed-enum JSON schema; the
> existing deterministic classifier consumes those features as if they came
> from an AST analyzer. First sweep on the 20 v0.1.7 unknowns: **18 / 20
> (90%) moved out of `unknown`** for $0.95 in OpenRouter spend. Pilot lives
> in [eval/llm_fallback/](eval/llm_fallback/) and is NOT in the production
> scan path; the 3 `malicious` verdicts the pilot produced are existing-
> rule FPs (r4 mismatching on filesystem-server / google-maps / figma),
> tracked as [L23](LIMITATIONS.md). Trust-boundary risks are tracked as
> [L22](LIMITATIONS.md).

> **v0.1.8 — labeled corpus (L11) framework lands.** `eval/labeled/` is the
> ground-truth half of the eval suite: a versioned `labels.json` of
> human-vetted package classifications and a harness that compares MIS's
> verdict to the label, emitting a confusion matrix (TP / FP / TN / FN /
> coverage-gap). Seed = 5 entries; corpus grows by manual review per the
> protocol in [eval/labeled/README.md](eval/labeled/README.md). Weak-evidence
> labels (reputation only, AI-only review) do NOT enter the corpus by
> design. Bootstrap script ingests the 51-server eval and emits
> `needs_review.json` stubs sorted by reviewer-priority. The framework
> closes [LIMITATIONS L11](LIMITATIONS.md); recall is uninformative at
> seed size (see L21) and label-set bias is tracked as L20.

> **v0.1.7 — three FP fixes after a reviewer critique of the v0.1.5
> 51-server eval:** `r6.command_injection` is now role-aware (a kubectl /
> docker / terraform server that shells out with tool input is doing its
> declared job, not committing RCE — `_guess_intent` widened, classifier
> rule exempts when every tool with the signal is shell-role);
> `r9.net_on_import`'s regex no longer matches bare
> `import fetch from "node-fetch"`; both JS paths skip top-level net
> detection on bundled / minified files (where "top-level" no longer maps
> to "fires at import time"). `mcp-server-kubernetes` moved from
> `malicious` to `benign`; `@modelcontextprotocol/server-gitlab` and
> `@notionhq/notion-mcp-server` moved from `suspicious` to `unknown` —
> an honest "I don't recognize this bundled shape" instead of crying wolf.
> 79/79 tests (was 77, +2 regression fixtures). Details in
> [LIMITATIONS.md](LIMITATIONS.md).

> **v0.1.6 — model-compliance loop.** Prompted 7 frontier LLMs to generate
> the 10 malicious-corpus patterns at 3 disguise levels (210 calls). 0% refusal
> across every model and level. The interesting failure mode: alignment-tuned
> models often refuse env-var exfil and substitute host fingerprint
> (`platform.platform()` + `socket.gethostname()`) over the same outbound
> channel — same beacon, less sensitive payload, slips past env-only scanners.
> Writeup: [eval/model_compliance/FINDING.md](eval/model_compliance/FINDING.md).
> New rule `r11.fingerprint_to_request` (verdict `suspicious`) + 3 new fixtures
> lifted catch rate on `official_sdk_exfil` from 4.8% → 19.0% on the cached
> dataset, zero regressions.

> **Headline finding (v0.1.5, 51 real public MCP servers from npm + PyPI):**
> **33 downloaded successfully. Of those, ~9% got a real behavioral verdict
> (malicious / suspicious / clean-with-extracted-behavior). ~24% were
> recognized but the analyzer couldn't follow their logic. ~55% used SDK
> patterns it didn't even recognize.** On a randomly-chosen real-world MCP
> server today, automated semantic analysis says *"I don't fully know"*
> roughly 4 times out of 5.
>
> All numbers are reproducible from `eval/` — see [eval/README.md](eval/README.md).
> The raw `run.json` for every record is committed under
> [`eval/results/v0.1.5/run.json`](eval/results/v0.1.5/run.json); the
> per-server summary is at [`eval/results/v0.1.5/report.md`](eval/results/v0.1.5/report.md).
>
> ⚠️ **NOT production.** Read [`LIMITATIONS.md`](./LIMITATIONS.md) before
> drawing any security conclusion from any MIS verdict.

## Why publish this number

The best public audit of MCP scanners ([appsecsanta, April 2026](https://appsecsanta.com/))
concluded that YARA-style tools catch surface patterns but **can't tell a
standard MCP instruction from an adversarial one**, and that manual review
remains the most reliable method. That statement is about today's deployed
scanners. The question MIS asks: what can a **semantic, intent-level**
analyzer (cross-function taint + behavior extraction + alias tracking +
state-poisoning detection) do instead — and, more importantly, where does
*it* go blind?

The answer is the number above. The contribution here isn't the analyzer
itself — it's the **measurement discipline around it**:

- **Five verdicts, not three.** Most tools collapse "I couldn't analyze this"
  into "this is clean" — a quiet false-green that burns trust the first time
  a CISO runs the tool on their own server. MIS adds `unknown` (no tools
  detected, SDK pattern not recognized) and `shallow` (tools recognized but
  the behavior extraction came up empty) above `benign`. CI defaults to
  failing on both.
- **The benign list is split in the report.** `with extracted behavior`
  (the real benign candidates) is reported separately from `zero behavior`
  (a regression signal — this should be 0). v0.1.4 had a leak that pushed
  4 servers into benign without behavior; v0.1.5 surfaces it as a built-in
  self-check.
- **The eval harness publishes failed downloads by name.** 18 of the 51
  registry entries failed to fetch (renamed, retired, registry errors).
  Reporting them explicitly stops the denominator from getting silently
  curated.

## The measured baseline (v0.1.5 on 51 servers)

| What | Count | % of 33 scanned |
|---|---:|---:|
| Downloaded successfully | 33 / 51 | — |
| **Failed to download** (renamed/retired/archive errors) | **18 / 51** | — |
| malicious | 1 | 3.0% |
| suspicious | 2 | 6.1% |
| **unknown** (SDK pattern not recognized) | **18** | **54.5%** |
| **shallow** (tools detected, behavior not extractable) | **8** | **24.2%** |
| **benign** (all entries have extracted behavior — 0 leak) | **4** | **12.1%** |

The 18 "failed downloads" are not analysis failures — they're packages
that don't currently install with `npm pack` / `pip download` (typically
because the package was renamed or retired between v0.1.3's registry write
and the v0.1.5 re-run). They're listed by name with the error string in
[`eval/results/v0.1.5/report.md`](eval/results/v0.1.5/report.md) so anyone
can confirm the denominator wasn't curated.

The 18 `unknown` and 8 `shallow` entries are MIS's own coverage gap, named.
Most of `unknown` is the long tail of TypeScript dispatch patterns we
haven't taught the analyzer yet; most of `shallow` is class-based dispatch
(L18 in LIMITATIONS).

## What MIS does

A CLI: `mis scan <source>` emits a verdict + a top-3 triage list + JSON
output suitable for CI. Five-way verdict:

| Verdict | Meaning | CI default |
|---|---|---|
| `malicious` | An intent rule fired with high confidence | exit 1 |
| `suspicious` | An intent rule fired with low/medium confidence | exit 1 |
| `unknown` | No tool registration detected (SDK pattern unsupported) — **NOT a safe verdict** | exit 1 (`--allow-unknown` to opt out) |
| `shallow` | Tools detected, zero behavior extracted from any of them — **NOT a safe verdict** | exit 1 (`--allow-shallow` to opt out) |
| `benign` | Tools detected, behavior extracted from at least one, no rule fired (bounded by [L4](./LIMITATIONS.md)) | exit 0 |

`--fail-on-verdict` rank: `benign < shallow < unknown < suspicious < malicious`.
Default = `shallow`. Both epistemic verdicts (`shallow`, `unknown`) fail CI
by default — opt out explicitly with `--allow-shallow` / `--allow-unknown`.

## What's under the hood

Static analysis only — no sandbox, no execution. Two analyzers feed a
11-rule intent classifier:

- **Python analyzer** (`mis/analyzers/python.py`) — AST + per-tool body
  analysis. Covers FastMCP (`@mcp.tool()`) and the official low-level SDK
  (`@server.list_tools()` + `@server.call_tool()` with per-tool branch
  attribution). Cross-function taint via per-module function summaries
  (L2 partial closure). Net-client alias tracking (`requests.Session()`,
  `httpx.Client()`, ...). State-poisoning detection.
- **JS/TS analyzer** (`mis/analyzers/js_ast.py`) — esprima AST + binding-aware
  tool detection. Covers `server.registerTool(name, config, handler)` with
  Identifier resolution, `server.setRequestHandler(ListToolsRequestSchema, ...)`,
  legacy `server.tool(...)`. Same alias tracking + cross-function taint
  + state-poisoning as the Python analyzer. TypeScript source files fall
  back to a regex analyzer for the per-file gap.
- **Manifest analyzer** — npm lifecycle dropper / setup.py dropper /
  Damerau-Levenshtein typosquat detection.

Intent classifier rules emit a verdict with a one-paragraph reason in
plain English. Monotonic-up: rules can escalate but never lower the
verdict. The top-3 triage list is OWASP MCP Top 10 - tagged.

## Install + use

```bash
pip install -e .

# Local source directory
mis scan ./path/to/mcp-server

# Remote
mis scan github:anthropic/mcp-server-git
mis scan npm:postmark-mcp@1.0.16
mis scan pypi:mcp-server-fetch

# Machine-readable for CI
mis scan --json npm:foo
```

## Reproduce the measurement

```bash
pip install -e .
python -m eval.run --out eval/results/my-rerun
# → ~5–10 minutes; npm + pip on PATH required.
# Output: eval/results/my-rerun/{report.md, run.json}.
```

See [eval/README.md](eval/README.md) for the full reproduction guide,
expected pitfalls, and how to add a server to the registry.

## What's NOT in v0.1.5

The list is long and labeled. Headlines:

- **L1 — No sandboxed behavioral analysis.** Static only.
- **L2 partial — Inter-procedural taint covers module-level only.** Class
  methods are invisible (L18). Deeper helper chains (helper-of-helper)
  lose signal.
- **L8 — No rug-pull / mutation detection.** Each scan is a snapshot.
- **L10 — No measurement against deployed scanners.** mcp-scan (= snyk-
  agent-scan) is the only OSS MCP scanner, but it inspects MCP **configs +
  runtime tool descriptions**, not source. Not a head-to-head category.
- **L11 — Labeled corpus is seeded, not extensive.** v0.1.8 ships the
  framework + 5 seed labels in [eval/labeled/](eval/labeled/); precision is
  computable, recall is uninformative until more malicious labels land
  (L21 documents why postmark-mcp@1.0.16 returns `error`).
- **L13 — Tool registration coverage is partial.** 20 servers (60.6% of the
  v0.1.7 scanned set) are `unknown` because their SDK pattern isn't covered.

Read [LIMITATIONS.md](./LIMITATIONS.md) for L1..L26 in full.

## Layout

```
mis/
├── analyzers/
│   ├── python.py       # AST analyzer (FastMCP + official low-level SDK)
│   ├── js_ast.py       # esprima AST analyzer (closes L3)
│   ├── js.py           # regex fallback for TS source / parse failures
│   ├── manifest.py     # package.json / pyproject.toml / setup.py
│   └── types.py        # ToolProfile + BehaviorSignal enum
├── classifier/intent.py # 11 rules → verdict + reason
├── extractors/         # file:// / github: / npm: / pypi:
├── report/render.py    # rich-table + JSON
├── cli.py              # `mis` typer app
├── engine.py           # scan() entry point
└── findings.py         # Finding + ScanResult + OWASP MCP constants

eval/
├── README.md           # reproduction guide
├── registry.py         # the 51 servers
├── run.py              # harness
└── results/{v0.1.3,v0.1.4,v0.1.5}/{report.md,run.json}

tests/                  # 82 unit + integration tests, 24 fixtures
```

## Relationship to neighbor projects

| Project | Layer | Status |
|---|---|---|
| `mcp-trust` | Sigstore-style trust + runtime proxy | v0.1-alpha |
| `arsp` | Runtime security plane: capability tokens, IFC, output sealing | research |
| `agent-config-injection` | Workspace config-file injection scanner (`.cursorrules`, `mcp.json`) | v0.1.8 |
| **`mcp-intent-sentinel`** (this) | Pre-install intent classification of MCP server source | v0.1.16 |

The composition story: `agent-config-injection` scans config files in a
workspace, `mcp-intent-sentinel` scans the server source before install,
`mcp-trust` verifies the signed artifact at distribution, `arsp` enforces
capabilities at runtime. None of them solves the whole problem alone.

## If MIS is blind somewhere

Open an issue. If you find a server the eval misclassified — a real
malicious one verdicted shallow/unknown/benign, or a real benign one
verdicted malicious/suspicious — that's the most useful contribution
possible. The point of the eval harness is to let us argue from numbers.

If you work on MCP / agent security and want to compare notes on the
semantic-analysis problem specifically, I'd value that conversation.

## License

[Apache 2.0](./LICENSE).
