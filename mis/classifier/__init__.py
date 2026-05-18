"""Intent classifier — turns raw findings + tool profiles into a verdict.

This is the core IP. Static analyzers produce *observations*; the classifier
produces *judgment*. Each rule fires with an explicit human-readable reason —
no black-box scoring.
"""
from __future__ import annotations

from mis.classifier.intent import classify, IntentRule, RuleHit

__all__ = ["classify", "IntentRule", "RuleHit"]
