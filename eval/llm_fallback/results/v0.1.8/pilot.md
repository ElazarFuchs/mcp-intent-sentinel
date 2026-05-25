# LLM-fallback pilot — MIS v0.1.8, 2026-05-25T07:30:55Z

**N**: 20 rows (only those with verdict=`unknown` in the input run).
**Moved out of unknown**: 18 (90.0%).
**Errors** (API / parse / extraction): 0.

## Distribution before vs after

| verdict | before | after |
|---|---:|---:|
| benign | 0 | 8 |
| malicious | 0 | 3 |
| shallow | 0 | 4 |
| suspicious | 0 | 3 |
| unknown | 20 | 2 |

## Per-row

| package | before | after | extracted tools | signals (first 3) | LLM notes |
|---|---|---|---:|---|---|
| `mcp-server-git` | unknown | shallow | 12 | git_status: ; git_diff_unstaged: ; git_diff_staged: | Git operations server, no network/secret/exec signals detected |
| `mcp-server-time` | unknown | shallow | 2 | get_current_time: ; convert_time: | Pure time/timezone computation tools, no network or filesystem access, no secret |
| `@modelcontextprotocol/server-filesystem` | unknown | malicious | 14 | read_file:SECRET_FS_READ ; read_text_file:SECRET_FS_READ ; read_media_file:SECRE | Filesystem server with path validation. Tools read/write within allowed director |
| `@modelcontextprotocol/server-memory` | unknown | shallow | 9 | create_entities: ; create_relations: ; add_observations: | Knowledge graph server with local file persistence. All operations are filesyste |
| `@modelcontextprotocol/server-puppeteer` | unknown | benign | 7 | puppeteer_navigate:NET_HTTP_OUTBOUND,NET_HOST_FROM_INPUT ; puppeteer_screenshot: | Puppeteer browser automation server. Reads PUPPETEER_LAUNCH_OPTIONS and ALLOW_DA |
| `@modelcontextprotocol/server-postgres` | unknown | benign | 1 | query:NET_HOST_FROM_INPUT,EXEC_DYNAMIC | PostgreSQL MCP server; db URL from argv; query tool executes user SQL (dynamic); |
| `@modelcontextprotocol/server-google-maps` | unknown | malicious | 7 | maps_geocode:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,NET_HOST_FROM_INPUT ; maps_rever | Google Maps API wrapper; reads GOOGLE_MAPS_API_KEY from env; all tools make HTTP |
| `@modelcontextprotocol/server-brave-search` | unknown | benign | 2 | brave_web_search:SECRET_ENV_READ,NET_HTTP_OUTBOUND,NET_HOST_LITERAL ; brave_loca | Both tools read BRAVE_API_KEY from process.env and include it in X-Subscription- |
| `@modelcontextprotocol/server-slack` | unknown | suspicious | 8 | slack_list_channels:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,SECRET_ENV_READ ; slack_p | Slack API client; reads SLACK_BOT_TOKEN, SLACK_TEAM_ID, SLACK_CHANNEL_IDS from e |
| `@modelcontextprotocol/server-aws-kb-retrieval` | unknown | benign | 1 | retrieve_from_aws_kb:SECRET_ENV_READ,NET_HTTP_OUTBOUND,NET_HOST_FROM_INPUT | AWS SDK client initialized with env credentials; tool sends queries to AWS Bedro |
| `@modelcontextprotocol/server-gdrive` | unknown | benign | 1 | search:NET_HTTP_OUTBOUND,NET_HOST_LITERAL | Google Drive API client; reads OAuth creds from filesystem; net calls via google |
| `@modelcontextprotocol/server-gitlab` | unknown | benign | 9 | create_or_update_file:NET_HTTP_OUTBOUND,NET_HOST_FROM_INPUT,SECRET_ENV_READ ; se | GitLab API client. All tools read GITLAB_PERSONAL_ACCESS_TOKEN env var and make  |
| `@notionhq/notion-mcp-server` | unknown | — | 0 |  | Large bundled CLI file, no MCP tool registrations found in scanned portion |
| `@playwright/mcp` | unknown | — | 0 |  | CLI wrapper and re-export module; no tool registrations found in provided source |
| `@executeautomation/playwright-mcp-server` | unknown | suspicious | 33 | start_codegen_session: ; end_codegen_session: ; get_codegen_session: | Playwright MCP server with browser automation and HTTP request tools. File uploa |
| `mcp-server-kubernetes` | unknown | benign | 23 | cleanup: ; kubectl_get:EXEC_SHELL ; kubectl_describe:EXEC_SHELL | Kubernetes MCP server with kubectl/helm wrappers. Multiple tools execute shell c |
| `mcp-server-commands` | unknown | benign | 1 | run_process:EXEC_SHELL,EXEC_SHELL_WITH_INPUT | spawn() with shell:true and user-controlled command_line/argv; stdin_text flows  |
| `mcp-figma` | unknown | malicious | 18 | set_api_key:SECRET_FS_READ ; check_api_key:SECRET_FS_READ ; get_file:NET_HTTP_OU | Figma API client. All tools read API key from ~/.mcp-figma/config.json and send  |
| `@browsermcp/mcp` | unknown | shallow | 12 | browser_press_key: ; browser_wait: ; browser_get_console_logs: | Browser automation MCP server; tools delegate to WebSocket-connected browser ext |
| `@21st-dev/magic` | unknown | suspicious | 4 | 21st_magic_component_builder:NET_HTTP_OUTBOUND,NET_HOST_LITERAL,NET_HOST_FROM_IN | 4 tools registered; all issue HTTP requests to external APIs; refine-ui reads lo |

## Cost

- Total input tokens: 253,573
- Total output tokens: 12,710
- Estimated cost (Sonnet 4.5 rates): $0.95
