# LLM-fallback pilot — MIS v0.1.16, 2026-05-25T14:23:25Z

**N**: 2 rows (only those with verdict=`unknown` in the input run).
**Moved out of unknown**: 2 (100.0%).
**Errors** (API / parse / extraction): 0.

## Distribution before vs after

| verdict | before | after |
|---|---:|---:|
| shallow | 0 | 2 |
| unknown | 2 | 0 |

## Per-row

| package | before | after | extracted tools | signals (first 3) | LLM notes |
|---|---|---|---:|---|---|
| `mcp-server-git` | unknown | shallow | 12 | git_add: ; git_branch: ; git_checkout: | models=anthropic/claude-sonnet-4.5+openai/gpt-5; both=12; primary-only=0; second |
| `mcp-server-time` | unknown | shallow | 2 | convert_time: ; get_current_time: | models=anthropic/claude-sonnet-4.5+openai/gpt-5; both=2; primary-only=0; seconda |

## Cost

- Total input tokens: 35,304
- Total output tokens: 3,216
- Estimated cost (Sonnet 4.5 rates): $0.15
