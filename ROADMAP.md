# ROADMAP

This is the planned path from v0.1.4 (today) to v1.0.0 (production). Items
are ordered by dependency, not by priority. Every item retires a numbered
LIMITATION (L1..L20) — keep that mapping when re-prioritizing.

## v0.1.5 — benign-rate leak fix (shipped)

User caught that v0.1.4's BENIGN jump (12.1% → 24.2%) was partially fake:
`server-github` (26 tools, 0 behavior) was classified `benign` because
`_has_io_capable_imports` was a narrow substring list that missed Octokit.
v0.1.5 rewrote that detection to AST-based broad-imports check + added a
PURE_COMPUTE coverage marker so trivial tools (calc, echo) keep verdict
`benign` while opaque ones route to `shallow`.

Re-run eval confirms: BENIGN dropped 24.2% → 12.1%, SHALLOW rose 12.1% →
24.2% — the 4 servers that leaked are now correctly `shallow`. The report
now publishes a `with behavior / zero behavior` split as a self-check.
74 tests passing.

## v0.1.4 — real AST JS analyzer (shipped)

Closed L3 for JS files. esprima-based AST replaces the regex `js.py`.
Five npm servers moved from `unknown` to `benign`/`suspicious` in the
re-run eval; UNKNOWN rate dropped from 69.7% → 54.5% (−15.2pp).
TypeScript source files still fall back to regex (deferred to v0.2).
73 tests passing.

## v0.1.3 — eval harness (shipped)

User-imposed embargo on new detectors until MIS could measure itself.
v0.1.3 shipped `eval/run.py` + a registry of ~50 real public servers
from PyPI/npm. The harness emits `eval/results/<run>/report.md` with
verdict distribution, FP candidates, shallow-rate, and download failures.
No detector changes. L10 and L11 are partially closed — they're now
measurement statements with a denominator we control.

## Reordering note (post-v0.1.1)

The v0.1.0 ROADMAP put eval (L10) and diff (L8) in v0.2 and sandbox (L1) in
v0.3. Field-testing v0.1.0 against real servers exposed that the actual
priority is **detection coverage** — without it, the product is blind to most
real-world MCP servers, and any eval result becomes meaningless because the
baseline of "what MIS sees" is too narrow. v0.1.1 closed the worst case of
this (official low-level SDK, formerly invisible — see L13 partial closure),
but more SDK patterns remain unsupported. v0.2 below leads with closing the
rest of the registration gap BEFORE the eval harness, because:

1. An eval harness comparing MIS to mcp-scan on a corpus MIS can't read is
   not measuring the product's wedge — it's measuring its blind spot.
2. A CISO demo on a real internal server that yields `unknown` is recoverable
   ("we don't cover this SDK yet"). A demo that yields wrong `malicious` or
   wrong `benign` because of partial coverage is not.

## v0.1.5 — chip at the remaining 18 unknowns + r6 tightening (NEXT)

Goal: continue closing the SDK-coverage gap one shape at a time, using the
eval as a measurement engine after each change.

- **Investigate `mcp-server-git` / `mcp-server-time` Python pattern**.
  Likely the Anthropic-shipped `mcp[cli]` package's `@asyncio_tool` decorator
  or similar variation. One detector should close both unknowns.
- **TypeScript dispatch shapes** in the 16 remaining npm unknowns.
  Triage by reading their `dist/` and adding patterns one at a time;
  each addition has a measurable eval delta.
- **r6 (`command_injection`) tightening**: distinguish `subprocess.X(cmd.split())`
  (arg-list-form, weak surface) from `subprocess.X(cmd, shell=True)` or
  `subprocess.X(f"cmd {input}", shell=True)` (shell-form, strong surface).
  `mcp-server-kubernetes` is the regression fixture this needs to flip
  from `malicious` to `benign` / `suspicious`.

## v0.1.6 — formal labeling on the eval corpus

Goal: turn v0.1.3's measured numbers into trustworthy ones.

- **Manual labeling pass on the benign list** (closes the rest of L11).
  Commit `eval/labels.json`: name → verified_benign | verified_malicious |
  uncertain. Re-run eval to publish a real FP rate with a denominator.
- **Triage every FP candidate from v0.1.3 report.** For each entry MIS
  classified as malicious / suspicious on a real public server:
  - If real: file an upstream issue (preferably coordinated disclosure).
  - If FP: identify which rule over-fired, tighten in v0.1.4 with a
    regression fixture that documents the new boundary.
- **Add L18-driven detection coverage** (class-method dispatch). Probably
  the highest-leverage detector work the v0.1.3 shallow-rate exposes —
  every `class_based_*` shallow becomes either benign-with-behavior or
  malicious-with-finding once it lands.

## v0.2 — coverage + diff

Goal: SDK coverage parity with the ecosystem; rug-pull detection (§ 5.3.4).

### 2.A Coverage

- **TypeScript SDK manual handler style** (closes part of L13).
  - Detect `server.setRequestHandler(CallToolRequestSchema, ...)` patterns
    in the official `@modelcontextprotocol/sdk` JS/TS SDK.
  - Detect tools declared in a `ListToolsRequestSchema` handler returning
    `{ tools: [...] }`.
- **Python FastMCP imperative API** (closes part of L13).
  - Detect `mcp.add_tool(callable, name=..., description=...)` call-style
    registration.
- **Aliased decorators** (closes part of L13).
  - Track `from mcp.server import tool as register` imports and treat
    `@register` the same as `@tool`.
- **More call_tool dispatch shapes** (closes L15).
  - Dict lookup (`HANDLERS = {"X": handle_x}` + `HANDLERS[name](args)`)
  - `getattr(self, f"handle_{name}")(args)` polymorphic dispatch
  - Decorator-registered subhandlers

### 2.B Evidence (already partially landed in v0.1.3 — strengthen)

- **Side-by-side `mcp-scan inspect` comparison** (closes the remainder of L10).
  v0.1.3 noted mcp-scan is config-oriented, not source. v0.2 wires a tool
  that boots a server via `npx` / `uvx`, runs `mcp-scan inspect` on the
  config that points at it, and compares the *tool description layer*.
  This is NOT a wedge claim ("better than mcp-scan") — it's a coverage
  demo ("MIS sees source-level intent; mcp-scan sees runtime
  descriptions; both are needed").
- **Grow the registry to 100+ servers** including long-tail community.
  The v0.1.3 list skews canonical; broaden it.

### 2.C Rug-pull (parallel-trackable with 2.B)

- **`mis diff <prev> <next>`** (closes L8).
  - Tool fingerprint = `(name, declared_intent, sorted(BehaviorSignals))`.
  - Diff: per-tool added / removed / changed signals.
  - Verdict escalation: any new signal in `{NET_HTTP_OUTBOUND, EXEC_SHELL,
    SECRET_FS_READ}` flips verdict to `suspicious` even if the static rules
    don't fire on the new version alone.
- **`mis ingest <registry>`** (partial closure of L9).
  - Walk a manifest directory or registry index; produce one JSON line per
    scanned server. Designed for CI cron, not interactive use.

## v0.3 — sandbox (long lead)

Goal: close the static-analysis ceiling (L1, L2, L7).

- **Sandbox runner** (closes L1).
  - Per-OS: Firejail (Linux), `sandbox-exec` (macOS), Job Objects (Windows).
  - Each tool called with benign synthetic inputs from its JSON schema.
  - Observe: fs reads, exec spawns, egress per (host, port, bytes).
- **Inter-procedural taint** (closes L2).
  - Build def/use graph during AST walk; propagate taint across calls within
    the same module first, then across imports in the same package.
- **setup.py cmdclass detection** (closes L7).
  - AST-detect `setup(cmdclass={"install": MyInstall})` where `MyInstall`
    overrides `run()` with non-boilerplate code.

## v0.4 — gateway for IDE wiring

Goal: turn `mis scan` into something an IDE plugin can call at install time.

- **CLI mode + library API parity.**
- **gRPC/JSON-RPC server for IDE integration** (long-tail use case from the
  spec's "explicitly NOT v0.1" tier — small-team ops).
- **Optional `--llm-judge` layer** (Haiku 4.5), mirroring the
  `agent-config-injection` pattern. Default off; opt-in for organizations
  that have the budget.

## v1.0 — production claims

The minimum bar to retire the "NOT production" disclaimer:

1. L10 closed with measured numbers (NOT "scanners miss X" — actual rates).
2. L11 closed with FP rate ≤ 3% on ≥ 100 real benign MCP servers.
3. L1 closed (sandbox runner shipped).
4. L8 closed (`mis diff` ships and is used in CI by at least one design partner).
5. At least one paying pilot (per spec § 11: "1 pilot משלם לפני סוף MVP v1").
6. LIMITATIONS.md has ≤ 4 entries that are NOT closed.

Until all six are true, this stays "NOT production" — same discipline as
`pipi-mcp-poc` and `arsp`.

## Out of scope forever

- Signature verification — that's `mcp-trust`. We focus on intent of the code
  the publisher *did* sign.
- Runtime enforcement — that's `arsp`. We are the install-time gate.
- Agent configuration scanning (`.cursorrules`, `mcp.json`, etc.) — that's
  `agent-config-injection`. We scan server packages.

The four products compose. None of them solves the whole problem alone, and
none of them should pretend to.
