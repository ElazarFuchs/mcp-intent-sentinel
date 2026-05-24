# MCP Intent Sentinel

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
10-rule intent classifier:

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
- **L11 — No formal label on the benign list.** v0.1.5's 4 benign entries
  are candidates for a labeled corpus; until that labeling exists, the
  "FP rate" is a current-run statement, not a property of MIS.
- **L13 — Tool registration coverage is partial.** 18 servers (54.5% of the
  v0.1.5 scanned set) are `unknown` because their SDK pattern isn't covered.

Read [LIMITATIONS.md](./LIMITATIONS.md) for L1..L20 in full.

## Layout

```
mis/
├── analyzers/
│   ├── python.py       # AST analyzer (FastMCP + official low-level SDK)
│   ├── js_ast.py       # esprima AST analyzer (closes L3)
│   ├── js.py           # regex fallback for TS source / parse failures
│   ├── manifest.py     # package.json / pyproject.toml / setup.py
│   └── types.py        # ToolProfile + BehaviorSignal enum
├── classifier/intent.py # 10 rules → verdict + reason
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

tests/                  # 77 unit + integration tests, 19 fixtures
```

## Relationship to neighbor projects

| Project | Layer | Status |
|---|---|---|
| `mcp-trust` | Sigstore-style trust + runtime proxy | v0.1-alpha |
| `arsp` | Runtime security plane: capability tokens, IFC, output sealing | research |
| `agent-config-injection` | Workspace config-file injection scanner (`.cursorrules`, `mcp.json`) | v0.1.8 |
| **`mcp-intent-sentinel`** (this) | Pre-install intent classification of MCP server source | v0.1.6 |

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
