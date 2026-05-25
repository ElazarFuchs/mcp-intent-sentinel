# Labeled-corpus confusion — MIS v0.1.13, 2026-05-25T12:47:19Z

**N**: 15 labeled rows (10 threat, 1 benign).
**Precision** (on threat verdicts): 1.0
**Recall**: 1.0

Precision/recall are defined ONLY over (TP+FP) / (TP+FN). Coverage-gap
verdicts (`shallow` / `unknown`) are NOT errors — MIS admitted it couldn't analyze
— and are reported separately.

## Counts by classification

| classification | count | meaning |
|---|---:|---|
| TP | 10 | label malicious/suspicious  →  MIS verdict malicious/suspicious |
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
| `fixture:postmark_backdoor` | malicious | malicious | TP | r2.bcc_injection | 1 | 0.99 |
| `fixture:silent_exfiltrator` | malicious | malicious | TP | r1.secret_to_request, r4.intent_mismatch | 1 | 0.99 |
| `fixture:tool_shadowing` | malicious | malicious | TP | r1.secret_to_request, r4.intent_mismatch | 1 | 0.99 |
| `fixture:hidden_instruction` | malicious | malicious | TP | r5.tool_poisoning | 1 | 0.99 |
| `fixture:command_injection` | malicious | malicious | TP | r6.command_injection | 2 | 0.99 |
| `fixture:lifecycle_dropper` | malicious | malicious | TP | r3.lifecycle_dropper | 1 | 0.99 |
| `fixture:official_sdk_exfil` | malicious | malicious | TP | r1.secret_to_request | 1 | 0.99 |
| `fixture:openai_key_in_header` | malicious | malicious | TP | r1.secret_to_request | 1 | 0.99 |
| `fixture:helper_exfil` | malicious | malicious | TP | r1.secret_to_request | 1 | 0.99 |
| `fixture:runtime_context_exfil` | suspicious | suspicious | TP | r11.fingerprint_to_request | 1 | 0.95 |

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

- p50 latency: 0.0s
- max latency: 18.8s
