"""Registry of ~50 real MCP servers to evaluate MIS against.

Selection rules (so the eval is honest, not stacked):

1. **Public, install-once.** Only packages installable via `pip` / `npm pack`
   without auth, keys, or login. No private indexes.
2. **Canonical + popular community.** Anchor on the
   modelcontextprotocol/servers monorepo, then add community servers that
   show up in the MCP registry index (modelcontextprotocol.io/servers) or
   that have non-trivial download counts.
3. **Mix SDK styles.** Both FastMCP (`@mcp.tool`) and the official low-level
   SDK (`@server.list_tools` + `@server.call_tool`) — otherwise we'd be
   testing only one detection path.
4. **NOT cherry-picked for MIS's strengths.** No avoiding class-based
   servers or imperative registration. If MIS verdicts `shallow` on a real
   server, that's a result, not a defect — it tells us coverage is missing.
5. **Resilient to failures.** Any candidate that fails to download is
   skipped with an error captured in the report. The eval reports BOTH
   the success set and the failure set, so we don't quietly hide them.

This list is not exhaustive (the MCP ecosystem is moving fast). It's
representative enough that MIS's verdict distribution on it is a credible
proxy for real-world behavior. Add to it over time.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ServerEntry:
    name: str           # human-readable label (e.g. "@modelcontextprotocol/server-everything")
    source: str         # MIS source spec ("npm:foo@1.2.3" / "pypi:bar" / etc.)
    ecosystem: str      # "npm" | "pypi"
    expected_class: str # "official_anthropic" | "community" — for grouping in the report
    notes: str = ""


# Anchor: the official Anthropic monorepo, both PyPI and npm releases.
# Names verified against modelcontextprotocol.io as of 2026-05 — some entries
# may have been renamed, retired, or moved between PyPI and npm; the harness
# reports any failure-to-download with the error, so churn is visible.
PYPI_OFFICIAL = [
    ServerEntry("mcp-server-fetch", "pypi:mcp-server-fetch", "pypi", "official_anthropic",
                "URL fetcher; tested in v0.1.2 directly"),
    ServerEntry("mcp-server-git", "pypi:mcp-server-git", "pypi", "official_anthropic",
                "git operations; subject of CVE-2025-68143/4/5"),
    ServerEntry("mcp-server-time", "pypi:mcp-server-time", "pypi", "official_anthropic",
                "time / timezone tool"),
    ServerEntry("mcp-server-sqlite", "pypi:mcp-server-sqlite", "pypi", "official_anthropic", ""),
]

NPM_OFFICIAL = [
    ServerEntry("@modelcontextprotocol/server-everything",
                "npm:@modelcontextprotocol/server-everything",
                "npm", "official_anthropic", "reference 'everything' server"),
    ServerEntry("@modelcontextprotocol/server-filesystem",
                "npm:@modelcontextprotocol/server-filesystem",
                "npm", "official_anthropic", "file system operations"),
    ServerEntry("@modelcontextprotocol/server-memory",
                "npm:@modelcontextprotocol/server-memory",
                "npm", "official_anthropic", "knowledge graph memory"),
    ServerEntry("@modelcontextprotocol/server-sequentialthinking",
                "npm:@modelcontextprotocol/server-sequentialthinking",
                "npm", "official_anthropic", "chain-of-thought helper"),
    ServerEntry("@modelcontextprotocol/server-puppeteer",
                "npm:@modelcontextprotocol/server-puppeteer",
                "npm", "official_anthropic", "browser automation"),
    ServerEntry("@modelcontextprotocol/server-postgres",
                "npm:@modelcontextprotocol/server-postgres",
                "npm", "official_anthropic", "PostgreSQL"),
    ServerEntry("@modelcontextprotocol/server-google-maps",
                "npm:@modelcontextprotocol/server-google-maps",
                "npm", "official_anthropic", "Google Maps API"),
    ServerEntry("@modelcontextprotocol/server-brave-search",
                "npm:@modelcontextprotocol/server-brave-search",
                "npm", "official_anthropic", "Brave Search API"),
    ServerEntry("@modelcontextprotocol/server-slack",
                "npm:@modelcontextprotocol/server-slack",
                "npm", "official_anthropic", "Slack integration"),
    ServerEntry("@modelcontextprotocol/server-aws-kb-retrieval",
                "npm:@modelcontextprotocol/server-aws-kb-retrieval",
                "npm", "official_anthropic", "AWS knowledge base"),
    ServerEntry("@modelcontextprotocol/server-github",
                "npm:@modelcontextprotocol/server-github",
                "npm", "official_anthropic", "GitHub API"),
    ServerEntry("@modelcontextprotocol/server-gdrive",
                "npm:@modelcontextprotocol/server-gdrive",
                "npm", "official_anthropic", "Google Drive"),
    ServerEntry("@modelcontextprotocol/server-gitlab",
                "npm:@modelcontextprotocol/server-gitlab",
                "npm", "official_anthropic", "GitLab API"),
    ServerEntry("@modelcontextprotocol/server-redis",
                "npm:@modelcontextprotocol/server-redis",
                "npm", "official_anthropic", "Redis"),
    ServerEntry("@modelcontextprotocol/server-sentry",
                "npm:@modelcontextprotocol/server-sentry",
                "npm", "official_anthropic", "Sentry error tracking"),
    ServerEntry("@modelcontextprotocol/server-time",
                "npm:@modelcontextprotocol/server-time",
                "npm", "official_anthropic", "time / timezone"),
    ServerEntry("@modelcontextprotocol/server-fetch",
                "npm:@modelcontextprotocol/server-fetch",
                "npm", "official_anthropic", "URL fetcher (npm variant)"),
    ServerEntry("@modelcontextprotocol/server-sqlite",
                "npm:@modelcontextprotocol/server-sqlite",
                "npm", "official_anthropic", "SQLite"),
    ServerEntry("@modelcontextprotocol/server-git",
                "npm:@modelcontextprotocol/server-git",
                "npm", "official_anthropic", "git operations (npm variant)"),
    ServerEntry("@modelcontextprotocol/server-everart",
                "npm:@modelcontextprotocol/server-everart",
                "npm", "official_anthropic", "EverArt image generation"),
]

# Popular community servers — drawn from modelcontextprotocol.io/servers and
# the wider ecosystem. Names checked at v0.1.3 write-time; entries that vanish
# from the registry over time will surface as download failures, not silent gaps.
NPM_COMMUNITY = [
    ServerEntry("@notionhq/notion-mcp-server",
                "npm:@notionhq/notion-mcp-server",
                "npm", "community", "Notion API (official by Notion)"),
    ServerEntry("@playwright/mcp",
                "npm:@playwright/mcp",
                "npm", "community", "Playwright browser automation"),
    ServerEntry("@executeautomation/playwright-mcp-server",
                "npm:@executeautomation/playwright-mcp-server",
                "npm", "community", "Playwright (community)"),
    ServerEntry("mcp-server-kubernetes",
                "npm:mcp-server-kubernetes",
                "npm", "community", "Kubernetes"),
    ServerEntry("mcp-shell-server",
                "npm:mcp-shell-server",
                "npm", "community", "Shell — high-risk surface; good coverage check"),
    ServerEntry("mcp-server-commands",
                "npm:mcp-server-commands",
                "npm", "community", "command runner"),
    ServerEntry("mcp-server-jira",
                "npm:mcp-server-jira",
                "npm", "community", "Jira"),
    ServerEntry("mcp-figma",
                "npm:mcp-figma",
                "npm", "community", "Figma API"),
    ServerEntry("@browsermcp/mcp",
                "npm:@browsermcp/mcp",
                "npm", "community", "browser control"),
    ServerEntry("@21st-dev/magic",
                "npm:@21st-dev/magic",
                "npm", "community", "UI generation tools"),
]

PYPI_COMMUNITY = [
    ServerEntry("mcp-server-mysql", "pypi:mcp-server-mysql", "pypi", "community", "MySQL"),
    ServerEntry("mcp-server-kubernetes", "pypi:mcp-server-kubernetes", "pypi", "community", "K8s"),
    ServerEntry("mcp-server-elasticsearch", "pypi:mcp-server-elasticsearch", "pypi", "community", "ElasticSearch"),
    ServerEntry("mcp-server-docker", "pypi:mcp-server-docker", "pypi", "community", "Docker"),
    ServerEntry("mcp-server-jupyter", "pypi:mcp-server-jupyter", "pypi", "community", "Jupyter"),
    ServerEntry("mcp-pandoc", "pypi:mcp-pandoc", "pypi", "community", "Pandoc converter"),
    ServerEntry("mcp-server-data-exploration", "pypi:mcp-server-data-exploration", "pypi", "community", ""),
    ServerEntry("mcp-server-rest", "pypi:mcp-server-rest", "pypi", "community", "REST adapter"),
    ServerEntry("mcp-server-azure-devops", "pypi:mcp-server-azure-devops", "pypi", "community", "Azure DevOps"),
    ServerEntry("mcp-server-perplexity", "pypi:mcp-server-perplexity", "pypi", "community", "Perplexity API"),
    ServerEntry("mcp-server-wikipedia", "pypi:mcp-server-wikipedia", "pypi", "community", "Wikipedia"),
    ServerEntry("mcp-server-youtube", "pypi:mcp-server-youtube", "pypi", "community", "YouTube"),
    ServerEntry("mcp-server-shodan", "pypi:mcp-server-shodan", "pypi", "community", "Shodan"),
    ServerEntry("mcp-confluence", "pypi:mcp-confluence", "pypi", "community", "Confluence"),
    ServerEntry("mcp-server-prometheus", "pypi:mcp-server-prometheus", "pypi", "community", "Prometheus"),
    ServerEntry("mcp-server-todoist", "pypi:mcp-server-todoist", "pypi", "community", "Todoist"),
    ServerEntry("mcp-server-airtable", "pypi:mcp-server-airtable", "pypi", "community", "Airtable"),
]


ALL_SERVERS: list[ServerEntry] = (
    PYPI_OFFICIAL + NPM_OFFICIAL + NPM_COMMUNITY + PYPI_COMMUNITY
)
