# LLM-fallback pilot — MIS v0.1.10, 2026-05-25T10:52:26Z

**N**: 20 rows (only those with verdict=`unknown` in the input run).
**Moved out of unknown**: 18 (90.0%).
**Errors** (API / parse / extraction): 0.

## Distribution before vs after

| verdict | before | after |
|---|---:|---:|
| benign | 0 | 12 |
| shallow | 0 | 6 |
| unknown | 20 | 2 |

## Per-row

| package | before | after | extracted tools | signals (first 3) | LLM notes |
|---|---|---|---:|---|---|
| `mcp-server-git` | unknown | shallow | 12 | git_status: ; git_diff_unstaged: ; git_diff_staged: | Git operations wrapper, no network/secret access, local repo manipulation only |
| `mcp-server-time` | unknown | shallow | 2 | get_current_time: ; convert_time: | Pure time/timezone conversion tools, no network or file system access |
| `@modelcontextprotocol/server-filesystem` | unknown | shallow | 14 | read_file: ; read_text_file: ; read_media_file: | filesystem server with sandboxed directory access, no network or secret operatio |
| `@modelcontextprotocol/server-memory` | unknown | shallow | 9 | create_entities: ; create_relations: ; add_observations: | Knowledge graph manager with local file persistence. All tools perform CRUD oper |
| `@modelcontextprotocol/server-puppeteer` | unknown | benign | 7 | puppeteer_navigate:NET_HOST_FROM_INPUT ; puppeteer_screenshot: ; puppeteer_click | Puppeteer browser automation tools. Navigate uses input URL. Evaluate executes a |
| `@modelcontextprotocol/server-postgres` | unknown | shallow | 1 | query: | PostgreSQL MCP server with read-only query tool; DB connection from CLI arg; no  |
| `@modelcontextprotocol/server-google-maps` | unknown | benign | 7 | maps_geocode:SECRET_ENV_READ,NET_HTTP_OUTBOUND,NET_HOST_LITERAL ; maps_reverse_g | Google Maps API wrapper; reads GOOGLE_MAPS_API_KEY from env, sends to googleapis |
| `@modelcontextprotocol/server-brave-search` | unknown | benign | 2 | brave_web_search:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,NET_HOST_FROM_INPUT ; brave_ | Both tools make HTTP requests to Brave API using env var BRAVE_API_KEY in header |
| `@modelcontextprotocol/server-slack` | unknown | benign | 8 | slack_list_channels:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,SECRET_ENV_READ ; slack_p | Slack API client; reads SLACK_BOT_TOKEN, SLACK_TEAM_ID, SLACK_CHANNEL_IDS from e |
| `@modelcontextprotocol/server-aws-kb-retrieval` | unknown | benign | 1 | retrieve_from_aws_kb:NET_HTTP_OUTBOUND,NET_HOST_FROM_INPUT,SECRET_ENV_READ | AWS SDK client reads credentials from env vars, makes API calls with user-suppli |
| `@modelcontextprotocol/server-gdrive` | unknown | benign | 1 | search:NET_HTTP_OUTBOUND,NET_HOST_FROM_INPUT | Google Drive API client; reads OAuth creds from FS; net calls use googleapis SDK |
| `@modelcontextprotocol/server-gitlab` | unknown | benign | 9 | create_or_update_file:SECRET_ENV_READ,NET_HTTP_OUTBOUND,NET_HOST_LITERAL ; searc | GitLab API client. Reads GITLAB_PERSONAL_ACCESS_TOKEN from env, uses it in Autho |
| `@notionhq/notion-mcp-server` | unknown | — | 0 |  | CLI entry point, no tool registrations found in this file |
| `@playwright/mcp` | unknown | — | 0 |  | Entry points only; tool registration in playwright-core/lib/coreBundle (external |
| `@executeautomation/playwright-mcp-server` | unknown | benign | 33 | start_codegen_session: ; end_codegen_session: ; get_codegen_session: | Playwright MCP server with browser automation and HTTP request tools. Source tru |
| `mcp-server-kubernetes` | unknown | benign | 23 | cleanup: ; kubectl_get:EXEC_SHELL ; kubectl_describe:EXEC_SHELL | Kubernetes MCP server with kubectl/helm wrappers; shell exec via execFileSync wi |
| `mcp-server-commands` | unknown | benign | 1 | run_process:EXEC_SHELL,EXEC_SHELL_WITH_INPUT | Tool spawns child processes via node:child_process.spawn; shell mode and executa |
| `mcp-figma` | unknown | benign | 18 | set_api_key: ; check_api_key: ; get_file:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,NET_ | Figma API client. All tools use axios to call api.figma.com with user-provided A |
| `@browsermcp/mcp` | unknown | shallow | 12 | browser_press_key: ; browser_wait: ; browser_get_console_logs: | Browser automation MCP server; all operations delegated via WebSocket to browser |
| `@21st-dev/magic` | unknown | benign | 4 | 21st_magic_component_builder:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,NET_HOST_FROM_IN | 4 tools registered; all make HTTP calls to external APIs (21st.dev, svgl.app); n |

## Cost

- Total input tokens: 258,373
- Total output tokens: 12,423
- Estimated cost (Sonnet 4.5 rates): $0.96
