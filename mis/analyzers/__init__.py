"""Static analyzers — produce Findings and ToolProfiles from extracted source.

Two analyzers in v0.1:
- mis.analyzers.python — AST-based; covers Python MCP servers (FastMCP, official SDK)
- mis.analyzers.js     — regex/heuristic; covers JS/TS MCP servers (official SDK, custom)

Each analyzer returns:
- a list[Finding] — raw observations
- a list[ToolProfile] — per-tool behavioral summary (used by the classifier)

The classifier (mis.classifier.intent) consumes both lists and produces the
verdict.
"""
from __future__ import annotations

from mis.analyzers.types import ToolProfile, BehaviorSignal

__all__ = ["ToolProfile", "BehaviorSignal"]
