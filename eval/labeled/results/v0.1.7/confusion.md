# Labeled-corpus confusion — MIS v0.1.7, 2026-05-25T06:55:58Z

**N**: 5 labeled rows (0 threat, 1 benign).

Precision/recall are defined ONLY over (TP+FP) / (TP+FN). Coverage-gap
verdicts (`shallow` / `unknown`) are NOT errors — MIS admitted it couldn't analyze
— and are reported separately.

## Counts by classification

| classification | count | meaning |
|---|---:|---|
| TP | 0 | label malicious/suspicious  →  MIS verdict malicious/suspicious |
| FP | 0 | label benign  →  MIS verdict malicious/suspicious |
| TN | 1 | label benign  →  MIS verdict benign |
| FN | 0 | label malicious/suspicious  →  MIS verdict benign |
| coverage_gap | 3 | label *  →  MIS verdict shallow/unknown (not an error) |
| error | 1 | MIS extraction failed (download / parse) |
| unknown_label | 0 | label not in {benign, suspicious, malicious} — data bug |

## Per-row

| name | label | verdict | classification | rule_hits | tools | confidence |
|---|---|---|---|---|---:|---:|
| `postmark-mcp` | malicious | ERROR | error |  | - | 0.99 |
| `mcp-server-time` | benign | unknown | coverage |  | 0 | 0.85 |
| `@modelcontextprotocol/server-everything` | benign | benign | TN |  | 10 | 0.9 |
| `@modelcontextprotocol/server-filesystem` | benign | unknown | coverage |  | 0 | 0.8 |
| `mcp-server-fetch` | benign | shallow | coverage |  | 1 | 0.85 |

## Coverage gaps on labeled rows

These rows have a label but MIS verdicted `shallow` / `unknown`. Each one
is an SDK-coverage signal — closing the gap would let MIS confirm-or-deny
the label. NOT an error in the FP/FN sense; an error of omission to track.

| name | label | verdict | reason |
|---|---|---|---|
| `mcp-server-time` | benign | unknown | Static analysis did not detect any MCP tool registration in this source. This is |
| `@modelcontextprotocol/server-filesystem` | benign | unknown | Static analysis did not detect any MCP tool registration in this source. This is |
| `mcp-server-fetch` | benign | shallow | Tools were detected (1) but MIS extracted ZERO behavior signals from any of them |

## Timings

- p50 latency: 5.9s
- max latency: 35.9s
