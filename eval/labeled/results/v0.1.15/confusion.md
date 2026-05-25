# Labeled-corpus confusion — MIS v0.1.14, 2026-05-25T13:23:10Z

**N**: 15 labeled rows (11 threat, 1 benign).
**Precision** (on threat verdicts): 1.0

## Recall (split — see L20/L21)

- **synthetic_recall: 1.0**  (10/10, N=10; coverage-gaps=0, errors=0)
  - Synthetic recall measures MIS against fixtures authored by MIS authors to test their own rules. This is rule-self-test, NOT evidence of real-world coverage. DO NOT cite as 'MIS recall'.
- **in_the_wild_recall: undefined**  (N=1 labeled, 1 unfetchable, 0 actually testable)
  - In-the-wild recall is the only number that estimates real-world coverage. Undefined until the corpus contains testable in-the-wild malicious labels (postmark-mcp@1.0.16 was yanked and now errors).

Precision is computed over (TP+FP) regardless of synthetic vs in-the-wild —
a false positive on a synthetic-labeled benign is the same kind of error as on
an in-the-wild benign. Coverage-gap verdicts (`shallow` / `unknown`) are NOT
errors — MIS admitted it couldn't analyze — and are NOT counted in recall's
denominator; they're surfaced separately above.

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

| name | source | label | verdict | classification | tools | conf |
|---|---|---|---|---|---:|---:|
| `postmark-mcp` | in-the-wild | malicious | ERROR | error | - | 0.99 |
| `mcp-server-time` | in-the-wild | benign | unknown | coverage | 0 | 0.85 |
| `@modelcontextprotocol/server-everything` | in-the-wild | benign | benign | TN | 10 | 0.9 |
| `@modelcontextprotocol/server-filesystem` | in-the-wild | benign | unknown | coverage | 0 | 0.8 |
| `mcp-server-fetch` | in-the-wild | benign | shallow | coverage | 1 | 0.85 |
| `fixture:postmark_backdoor` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:silent_exfiltrator` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:tool_shadowing` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:hidden_instruction` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:command_injection` | synthetic | malicious | malicious | TP | 2 | 0.99 |
| `fixture:lifecycle_dropper` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:official_sdk_exfil` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:openai_key_in_header` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:helper_exfil` | synthetic | malicious | malicious | TP | 1 | 0.99 |
| `fixture:runtime_context_exfil` | synthetic | suspicious | suspicious | TP | 1 | 0.95 |

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
- max latency: 32.5s
