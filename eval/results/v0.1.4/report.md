# MIS evaluation report — 2026-05-18T10:30:46Z

Registry size: **51** servers scanned. **33** successful, **18** failed to download.
Total scan time: 286.6s (p50 2.88s, p95 19.82s).

## Verdict distribution (successful scans only)

| Verdict | Count | % |
|---|---:|---:|
| malicious | 1 | 3.0% |
| suspicious | 2 | 6.1% |
| unknown | 18 | 54.5% |
| shallow | 4 | 12.1% |
| benign | 8 | 24.2% |

**Shallow rate** (4/33) measures how often MIS recognized tools but couldn't follow behavior — the L18 / coverage ceiling. **Unknown rate** measures unrecognized SDK patterns. These two together are MIS's own coverage gap, surfaced honestly by the verdict scheme — they are NOT the FP rate.

## FP candidates — REAL servers MIS classified as malicious / suspicious

Each entry below is a public, popular server that MIS verdicted as a threat. **One of two things is true** for each:
1. MIS found a real issue worth reporting upstream (true positive — file an issue with the package's maintainers), OR
2. The rule that fired is over-aggressive (false positive — tighten in v0.1.4+).

Manual review required for each. **Never hide this list.**

| Name | Verdict | Confidence | Top rule | Reason |
|---|---|---:|---|---|
| `@modelcontextprotocol/server-gitlab` | suspicious | 0.75 | r9.net_on_import | 1 network call(s) at module top scope — they fire at import time, before the user invokes any tool. Common pattern in in |
| `@notionhq/notion-mcp-server` | suspicious | 0.75 | r9.net_on_import | 1 network call(s) at module top scope — they fire at import time, before the user invokes any tool. Common pattern in in |
| `mcp-server-kubernetes` | malicious | 0.85 | r6.command_injection | 5 site(s) where tool-input data flows into a shell/subprocess call. If the command is built via string concatenation or  |

## Shallow list — MIS coverage ceiling on real servers

4 server(s) where MIS detected tools but extracted zero behavior, despite I/O-capable imports being present. These are MIS's blind spots — most commonly class-method dispatch (L18) or imperative tool registration not yet supported. Until these are lifted, MIS verdicts `shallow` rather than pretending to know.

| Name | Ecosystem | Tools detected | I/O imports? |
|---|---|---:|---|
| `mcp-server-fetch` | pypi | 1 (fetch) | True |
| `mcp-server-sqlite` | pypi | 6 (read_query, write_query, create_table...) | True |
| `mcp-pandoc` | pypi | 1 (convert-contents) | True |
| `mcp-server-wikipedia` | pypi | 5 (search_articles, get_summaries, get_toc...) | True |

## Unknown list — SDKs MIS doesn't recognize

18 server(s) where MIS did not detect any tool registration. These flag SDK patterns we need to add support for (L13).

- `mcp-server-git` (pypi)
- `mcp-server-time` (pypi)
- `@modelcontextprotocol/server-filesystem` (npm)
- `@modelcontextprotocol/server-memory` (npm)
- `@modelcontextprotocol/server-puppeteer` (npm)
- `@modelcontextprotocol/server-postgres` (npm)
- `@modelcontextprotocol/server-google-maps` (npm)
- `@modelcontextprotocol/server-brave-search` (npm)
- `@modelcontextprotocol/server-slack` (npm)
- `@modelcontextprotocol/server-aws-kb-retrieval` (npm)
- `@modelcontextprotocol/server-gdrive` (npm)
- `@playwright/mcp` (npm)
- `@executeautomation/playwright-mcp-server` (npm)
- `mcp-server-kubernetes` (npm)
- `mcp-server-commands` (npm)
- `mcp-figma` (npm)
- `@browsermcp/mcp` (npm)
- `@21st-dev/magic` (npm)

## Benign list (8)

These are real public servers MIS verdicted `benign` (tools detected, behavior extracted, no intent rule fired). They are CANDIDATES for the formal benign corpus (L11). Each one needs an independent confirmation that no compromise is present — `benign` is bounded by what the v0.1 ruleset covers (L4).

- `@modelcontextprotocol/server-everything` — 10 tool(s), 0 with behavior, confidence 0.6
- `@modelcontextprotocol/server-github` — 26 tool(s), 0 with behavior, confidence 0.6
- `@modelcontextprotocol/server-redis` — 4 tool(s), 0 with behavior, confidence 0.6
- `@modelcontextprotocol/server-everart` — 1 tool(s), 0 with behavior, confidence 0.6
- `mcp-shell-server` — 3 tool(s), 3 with behavior, confidence 0.6
- `mcp-server-mysql` — 6 tool(s), 0 with behavior, confidence 0.6
- `mcp-server-jupyter` — 6 tool(s), 0 with behavior, confidence 0.6
- `mcp-server-perplexity` — 1 tool(s), 1 with behavior, confidence 0.6

## Failed downloads (18)

These entries could not be fetched from the registry (package retired, renamed, network issue, etc.). They are NOT counted in the distribution above.

- `@modelcontextprotocol/server-sequentialthinking` — extraction: npm pack failed: 
- `@modelcontextprotocol/server-sentry` — extraction: npm pack failed: 
- `@modelcontextprotocol/server-time` — extraction: npm pack failed: 
- `@modelcontextprotocol/server-fetch` — extraction: npm pack failed: 
- `@modelcontextprotocol/server-sqlite` — extraction: npm pack failed: 
- `@modelcontextprotocol/server-git` — extraction: npm pack failed: 
- `mcp-server-jira` — extraction: npm pack failed: 
- `mcp-server-elasticsearch` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-elasticsearch (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: py
- `mcp-server-docker` — extraction: pip download failed: 
[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.exe -m pip install --upgrade pip
ERROR: Invalid member in the tar file C:\Users\User\AppData\Local\Temp\p
- `mcp-server-data-exploration` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-data-exploration (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run:
- `mcp-server-rest` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-rest (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.exe 
- `mcp-server-azure-devops` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-azure-devops (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: pyt
- `mcp-server-youtube` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-youtube (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.e
- `mcp-server-shodan` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-shodan (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.ex
- `mcp-confluence` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-confluence (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.exe -
- `mcp-server-prometheus` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-prometheus (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: pytho
- `mcp-server-todoist` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-todoist (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.e
- `mcp-server-airtable` — extraction: pip download failed: ERROR: Could not find a version that satisfies the requirement mcp-server-airtable (from versions: none)

[notice] A new release of pip is available: 25.3 -> 26.1.1
[notice] To update, run: python.

## Baseline scanner notes

Baseline scanner integration not requested in this run (use `--baseline`). Even with it, see LIMITATIONS.md L10: mcp-scan and MIS scan different artifacts. A direct head-to-head requires a baseline that does static source analysis — none of the currently-deployed scanners do.

