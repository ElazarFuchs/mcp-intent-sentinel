"""MIS evaluation harness.

The point of this package: prove (or disprove) MIS's wedge with measured
numbers, not assertions. The user's third-iteration feedback was decisive —
"in all three versions, the one who found the problem was me, manually."
This is the harness that makes MIS catch its own coverage gaps.

Modules:
- registry: ~50 real MCP servers from PyPI + npm (canonical + popular community)
- run     : download each, run MIS, capture verdict / tools / behavior / timing
- baseline: integration shim for mcp-scan (note: scans configs, not source —
            see LIMITATIONS.md L10 for why this is NOT a direct apples-to-apples)
- report  : aggregate results → verdict distribution, shallow rate, FP candidate list

Entry point: `python -m eval.run`.
"""
