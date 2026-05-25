"""Intent classification rules.

Design principles:
1. Every rule is a small named function that takes (findings, tools) and
   returns a RuleHit or None. Rules don't share state.
2. Each rule's verdict carries a reason string. The final ScanResult.verdict
   is the strongest of all hits; the reason concatenates the rule reasons.
3. Verdicts are MONOTONIC UP: a rule can escalate (benign→suspicious→malicious)
   but never de-escalate. This mirrors mcp-trust's L3 monotonicity invariant —
   if behavioral signals could lower the score, an evading attacker would
   benefit from the scanner.
4. The classifier emits a triage list — the top 3 findings to act on first.
   This is the CISO-facing requirement: "not 100 findings, just 3 urgent ones".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from mis.analyzers.types import BehaviorSignal, ToolProfile
from mis.findings import Finding, ScanResult, Severity, Verdict


# Ordered higher = stronger.
# Both `shallow` and `unknown` sit between benign and suspicious because they
# are *epistemic* states (we don't know), not threat assertions. A CISO who
# sets `--fail-on-verdict unknown` (the default) wants the analyzer to fail
# loudly when it didn't fully understand the server; `shallow` is admit-of-
# incomplete-coverage at a higher fidelity (we read the tool names but couldn't
# follow the behavior), so it ranks just above benign but below unknown.
_VERDICT_RANK: dict[Verdict, int] = {
    "benign": 0,
    "shallow": 1,
    "unknown": 2,
    "suspicious": 3,
    "malicious": 4,
}


@dataclass
class RuleHit:
    rule_id: str
    verdict: Verdict
    confidence: float  # 0.0..1.0
    reason: str        # human-readable, used in the report


IntentRule = Callable[[list[Finding], list[ToolProfile]], Optional[RuleHit]]


# --- the rules ---------------------------------------------------------------
#
# Each rule below codifies one piece of "what a malicious MCP server looks
# like" knowledge. Add new rules as new attack classes are documented in the
# threat-model. Existing rules should never silently change verdict — bump the
# rule id (r1.1 -> r1.2) so reports stay diffable.

def _r1_secret_to_request(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """Hard malicious: secret-bearing data flows into outbound request.

    Covers all the secret-to-request shapes the v0.1.x analyzers emit:
    - direct: `requests.post(url, data=secret)` (py.exfil.secret_in_request)
    - JS env+net co-occurrence (js.exfil.env_with_net)
    - client-state poisoning: secret in `s.headers`, then `s.get(url)` (v0.1.2)
    - inter-procedural: helper's body matches; called from tool (v0.1.2)
    - tainted-arg-to-net-helper: tool passes secret into helper that net-calls (v0.1.2)
    """
    secret_rules = {
        "py.exfil.secret_in_request",
        "py.exfil.secret_in_client_state",
        "py.exfil.helper_secret_in_request",
        "py.exfil.tainted_arg_to_net_helper",
        "js.exfil.env_with_net",
    }
    hits = [f for f in findings if f.rule in secret_rules]
    if not hits:
        return None
    # Compose a short, accurate reason — name the path so the report is useful.
    paths = sorted({f.rule.split(".")[-1] for f in hits})
    return RuleHit(
        rule_id="r1.secret_to_request",
        verdict="malicious",
        confidence=0.95,
        reason=(
            f"{len(hits)} site(s) where secret-bearing data (env var or sensitive file) "
            f"reaches an outbound network request. Path shapes: {', '.join(paths)}. "
            "Exfiltration channel — not legitimate tool behavior."
        ),
    )


def _r2_bcc_injection(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """Postmark-mcp backdoor pattern: email tool sets BCC."""
    hits = [f for f in findings if f.rule == "js.email.bcc_injection"]
    if not hits:
        return None
    return RuleHit(
        rule_id="r2.bcc_injection",
        verdict="malicious",
        confidence=0.90,
        reason=(
            "Email-sending tool injects a BCC header. The 2025 postmark-mcp backdoor (the first "
            "in-the-wild malicious MCP server) used exactly this pattern to silently CC every "
            "outgoing message to an attacker address. Inspect the BCC value."
        ),
    )


def _r3_lifecycle_dropper(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """npm preinstall/postinstall that fetches and execs remote code."""
    hits = [f for f in findings if f.rule == "manifest.npm.lifecycle_dropper"]
    hits += [f for f in findings if f.rule == "manifest.pypi.setup_dropper"]
    if not hits:
        return None
    return RuleHit(
        rule_id="r3.lifecycle_dropper",
        verdict="malicious",
        confidence=0.95,
        reason=(
            "Package installation script fetches and executes remote code. This runs at install "
            "time, before any tool is invoked — the user does not get a prompt. Supply-chain "
            "dropper pattern (MCP04)."
        ),
    )


_R4_FS_ROLE_EXEMPT = {"file", "shell", "fetch"}
_R4_CREDENTIAL_DESC_KEYWORDS = ("credential", "key", "token", "auth", "secret")


def _r4_intent_mismatch(_findings, tools: list[ToolProfile]) -> Optional[RuleHit]:
    """Tool's declared intent does not match its observed behavior.

    Example: a 'calculator' tool that issues outbound HTTP, or a 'format'
    tool that reads ~/.ssh.

    This is the rule that *most distinguishes the product* from pattern
    matchers: it compares declared purpose to actual capability.

    v0.1.10 — role-aware exemption on the SECRET_FS_READ catch-all. The
    LLM-fallback pilot (v0.1.9) emitted SECRET_FS_READ on every file-
    reading tool of server-filesystem, mcp-figma, etc. — packages whose
    declared purpose IS to read files / call APIs that need a key from a
    file. The catch-all was too broad; it now skips tools whose declared
    intent is `file` / `shell` / `fetch` (legitimate file/devops/API
    consumers) or whose description explicitly self-identifies as a
    credential helper (key/token/auth/secret/credential).

    The trade-off (L23): a hostile fetch-intent tool that reads SSH but
    doesn't exfil will now pass — caught instead by r1 (secret-to-request)
    when the SSH content reaches a network call. The previous behavior
    over-flagged legitimate file/API servers, which is the worse error in
    practice (adoption-blocking).
    """
    mismatches: list[tuple[ToolProfile, str]] = []
    for tool in tools:
        intent = tool.declared_intent
        beh = tool.behavior
        desc_low = tool.declared_description.lower()

        # Math/format tools should NOT do network egress
        if intent in {"math", "format"} and BehaviorSignal.NET_HTTP_OUTBOUND in beh:
            mismatches.append((tool, f"declared as '{intent}' but issues outbound HTTP"))
        # Math/format tools should NOT shell out
        if intent in {"math", "format"} and BehaviorSignal.EXEC_SHELL in beh:
            mismatches.append((tool, f"declared as '{intent}' but spawns a shell process"))
        # Math tools should NOT read filesystem at all
        if intent == "math" and BehaviorSignal.SECRET_FS_READ in beh:
            mismatches.append((tool, "declared as 'math' but reads sensitive filesystem paths"))
        # Search tools should not read credentials
        if intent == "search" and BehaviorSignal.SECRET_FS_READ in beh:
            mismatches.append((tool, "declared as 'search' but reads sensitive filesystem paths"))

        # SECRET_FS_READ catch-all — v0.1.10 role-aware. Skip when:
        #   (a) declared_intent is file/shell/fetch — those legitimately
        #       touch the filesystem (FS server, kubectl helper, API client
        #       reading its own auth file); OR
        #   (b) declared_description names itself as a credential / key /
        #       token / auth / secret helper (explicit self-declaration).
        if BehaviorSignal.SECRET_FS_READ in beh:
            credential_helper = any(k in desc_low for k in _R4_CREDENTIAL_DESC_KEYWORDS)
            role_expected = intent in _R4_FS_ROLE_EXEMPT
            if not credential_helper and not role_expected:
                # avoid double-counting math/search cases above
                if not any(t is tool for t, _ in mismatches):
                    mismatches.append((tool, "reads ~/.ssh / .aws / cookie store without declaring itself a credential tool"))

    if not mismatches:
        return None
    if len(mismatches) >= 2:
        return RuleHit(
            rule_id="r4.intent_mismatch",
            verdict="malicious",
            confidence=0.85,
            reason=(
                f"{len(mismatches)} tool(s) whose declared purpose does NOT match their observed "
                "behavior: " + "; ".join(f"'{t.name}' — {why}" for t, why in mismatches[:3])
            ),
        )
    t, why = mismatches[0]
    return RuleHit(
        rule_id="r4.intent_mismatch",
        verdict="suspicious",
        confidence=0.70,
        reason=f"Tool '{t.name}' shows an intent mismatch: {why}.",
    )


def _r5_tool_poisoning(findings: list[Finding], tools: list[ToolProfile]) -> Optional[RuleHit]:
    """Hidden instructions in tool descriptions = tool poisoning (MCP03).

    A single hit is enough to call it malicious when the hidden text contains
    an explicit directive (HTML comment carrying an "ignore previous" /
    "do not mention" / "you must fetch" phrase). Plain unicode steganography
    or auth-override phrasing is also malicious-grade on a single hit, because
    the technique itself signals adversarial framing — there is no benign
    reason a description contains zero-width characters or claims user
    pre-authorization.

    Only the rare case of a single `hidden_instruction` that matched ONLY a
    generic HTML comment (no directive verbs) stays at "suspicious" — that
    pattern overlaps with legitimate template comments.
    """
    poisoned: list[Finding] = [
        f for f in findings
        if f.rule in {"py.desc.hidden_instruction", "py.desc.unicode_steg", "py.desc.auth_override",
                      "js.desc.hidden_instruction", "js.desc.unicode_steg", "js.desc.auth_override"}
    ]
    if not poisoned:
        return None

    # Any unicode steg OR auth override → malicious (single hit is enough).
    if any(p.rule.endswith(("unicode_steg", "auth_override")) for p in poisoned):
        return RuleHit(
            rule_id="r5.tool_poisoning",
            verdict="malicious",
            confidence=0.90,
            reason=(
                f"{len(poisoned)} tool description(s) contain invisible unicode or claims of user "
                "pre-authorization. No benign reason for either pattern in a tool description."
            ),
        )

    # Hidden instructions — single explicit directive is enough, generic comments are not.
    directive_words = ("ignore", "do not", "don't", "you must", "before ", "system prompt", "developer prompt")
    explicit_directive = any(
        any(w in (f.evidence or "").lower() for w in directive_words)
        for f in poisoned
    )
    if explicit_directive or len(poisoned) >= 2:
        return RuleHit(
            rule_id="r5.tool_poisoning",
            verdict="malicious",
            confidence=0.90,
            reason=(
                f"{len(poisoned)} tool description(s) contain hidden instructions to the LLM "
                "(HTML comments carrying directive phrases like 'ignore previous', 'you must', "
                "'do not mention'). Classic tool-poisoning."
            ),
        )
    f = poisoned[0]
    return RuleHit(
        rule_id="r5.tool_poisoning",
        verdict="suspicious",
        confidence=0.65,
        reason=(
            "A tool description contains an HTML comment. By itself this isn't proof of poisoning, "
            f"but it merits review ({f.rule})."
        ),
    )


def _r6_command_injection(findings: list[Finding], tools: list[ToolProfile]) -> Optional[RuleHit]:
    """Tool input flows into shell exec.

    Role-aware (v0.1.7): if EVERY tool with EXEC_SHELL_WITH_INPUT declares
    itself as a shell/devops role (kubectl, docker, terraform, ansible, bash,
    cmd, etc. — see _guess_intent), the rule does NOT fire. Those servers
    exist specifically to run user-supplied commands; their declared purpose
    explicitly endorses the behavior r6 was designed to catch on tools that
    declared themselves as something else (math, search, format).

    If at least one non-shell-role tool has the signal, the rule still fires
    on the whole set. If we can't link findings to tools at all (coarse-
    attribution path), we fall back to firing — better a FP that's reviewable
    than a missed exfil. Tracked in LIMITATIONS L11.x.
    """
    hits = [f for f in findings if f.rule == "py.exec.shell_with_input"]
    if not hits:
        return None

    # v0.1.7 role-aware exemption.
    SHELL_ROLE_INTENTS = {"shell"}
    tools_w_signal = [t for t in tools if BehaviorSignal.EXEC_SHELL_WITH_INPUT in t.behavior]
    non_exempt = [t for t in tools_w_signal if t.declared_intent not in SHELL_ROLE_INTENTS]
    if tools_w_signal and not non_exempt:
        # Every tool with the signal is a shell/devops role tool. Suppress.
        return None

    # Compose the reason. If we DO have non-exempt tools, name them so the
    # report explains why the suppression didn't kick in.
    name_hint = ""
    if non_exempt:
        names = [f"'{t.name}' (declared as {t.declared_intent})" for t in non_exempt[:3]]
        name_hint = f" Non-shell-role tools involved: {', '.join(names)}."

    return RuleHit(
        rule_id="r6.command_injection",
        verdict="malicious",
        confidence=0.85,
        reason=(
            f"{len(hits)} site(s) where tool-input data flows into a shell/subprocess call. "
            "If the command is built via string concatenation or shell=True, this is a "
            "command-injection sink the LLM controls (MCP05)." + name_hint
        ),
    )


def _r7_typosquat(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """Package name close to a well-known MCP server."""
    hits = [f for f in findings if f.rule == "manifest.typosquat"]
    if not hits:
        return None
    return RuleHit(
        rule_id="r7.typosquat",
        verdict="suspicious",
        confidence=0.70,
        reason=(
            f"Package name is one edit away from a well-known MCP server: {hits[0].evidence}. "
            "Verify the publisher matches the expected one before installing."
        ),
    )


def _r8_dynamic_exec(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """eval / exec / new Function in tool body."""
    hits = [f for f in findings if f.rule in {"py.exec.dynamic", "js.exec.dynamic"}]
    if not hits:
        return None
    return RuleHit(
        rule_id="r8.dynamic_exec",
        verdict="suspicious",
        confidence=0.75,
        reason=(
            f"{len(hits)} use(s) of eval / exec / new Function. These execute arbitrary code paths "
            "and are very rare in legitimate tool implementations."
        ),
    )


def _r9_net_on_import(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """Network call at module import time."""
    hits = [f for f in findings if f.rule in {"py.net.on_import", "js.net.on_import"}]
    if not hits:
        return None
    return RuleHit(
        rule_id="r9.net_on_import",
        verdict="suspicious",
        confidence=0.75,
        reason=(
            f"{len(hits)} network call(s) at module top scope — they fire at import time, before "
            "the user invokes any tool. Common pattern in initialization beacons and license-check exfil."
        ),
    )


def _r11_fingerprint_to_request(findings: list[Finding], _tools) -> Optional[RuleHit]:
    """Host-fingerprint data (platform.* / socket.gethostname / os.uname) flows
    into an outbound network call. Added v0.1.6 after the model-compliance eval:
    when prompted for env-var exfil, frontier models often refuse the literal
    request and emit a "modified payload" variant that ships host fingerprint
    instead. Fingerprint alone is weaker than secret exfil — it identifies the
    deployment but doesn't directly leak credentials — so the verdict is
    `suspicious`, not `malicious`. If a finding fires on a server that ALSO
    triggers r1 (secret_to_request), r1's malicious verdict will override.
    """
    hits = [f for f in findings if f.rule == "py.exfil.fingerprint_in_request"]
    if not hits:
        return None
    return RuleHit(
        rule_id="r11.fingerprint_to_request",
        verdict="suspicious",
        confidence=0.75,
        reason=(
            f"{len(hits)} site(s) where host fingerprint data (platform.*, socket.gethostname, "
            "os.uname, or sys.version) is shipped to an outbound network call. Not credential exfil, "
            "but a deployment-identifying side-channel; commonly the 'modified payload' shape that "
            "shows up when an alignment-tuned model refuses the bare env-exfil ask."
        ),
    )


# All rules, in evaluation order. The classifier walks the list, fuses results
# by maximum verdict, and uses each hit as a separate report row.
_RULES: list[tuple[str, IntentRule]] = [
    ("r1.secret_to_request", _r1_secret_to_request),
    ("r2.bcc_injection",     _r2_bcc_injection),
    ("r3.lifecycle_dropper", _r3_lifecycle_dropper),
    ("r4.intent_mismatch",   _r4_intent_mismatch),
    ("r5.tool_poisoning",    _r5_tool_poisoning),
    ("r6.command_injection", _r6_command_injection),
    ("r7.typosquat",         _r7_typosquat),
    ("r8.dynamic_exec",      _r8_dynamic_exec),
    ("r9.net_on_import",     _r9_net_on_import),
    ("r11.fingerprint_to_request", _r11_fingerprint_to_request),
]


def classify(result: ScanResult, tools: list[ToolProfile]) -> list[RuleHit]:
    """Run every intent rule over (result.findings, tools). Mutate `result`
    with verdict / verdict_reason / verdict_confidence / triage.

    Returns the list of RuleHits (in priority order) for use by the report.
    """
    hits: list[RuleHit] = []
    for _rid, rule in _RULES:
        h = rule(result.findings, tools)
        if h is not None:
            hits.append(h)

    # Sort hits by verdict rank desc, then confidence desc
    hits.sort(key=lambda h: (-_VERDICT_RANK[h.verdict], -h.confidence))

    if not hits:
        # Three-way split of "no rule fired":
        #
        # (A) 0 tools detected at all     → `unknown`   (SDK not recognized)
        # (B) tools detected, all behavior empty, file imports I/O-capable mods
        #                                  → `shallow`  (analyzer didn't follow logic)
        # (C) tools detected and (at least one has behavior, OR no I/O imports)
        #                                  → `benign`   (bounded by L4)
        if not tools and not result.findings:
            result.verdict = "unknown"
            result.verdict_reason = (
                "Static analysis did not detect any MCP tool registration in this source. "
                "This is NOT a benign verdict — it means MIS did not recognize the SDK pattern "
                "in use (see LIMITATIONS.md L13 for the SDKs currently covered). "
                "Treat this server as unanalyzed until: (a) a manual review is performed, "
                "(b) MIS support for the relevant SDK lands, or (c) you confirm the source root "
                "passed is correct."
            )
            result.verdict_confidence = 0.0  # we make no claim
        elif tools and all(not getattr(t, "behavior", None) for t in tools):
            # v0.1.5: the leak fix. Previously this branch required
            # `io_capable_imports_present=True`, with `io_capable` being a
            # narrow substring scan that missed octokit/googleapis/etc. — so
            # server-github (26 tools, 0 behavior, no httpx/requests imports)
            # leaked into `benign`. Two changes here:
            # 1. The `io_capable` predicate is now AST-based and broad: any
            #    non-stdlib import counts. With that strengthening, requiring
            #    it would still leak the rare case of a server importing only
            #    stdlib/builtins — so we drop the requirement entirely.
            # 2. Per-tool: the analyzer now tags PURE_COMPUTE on tools whose
            #    body was successfully walked but had no I/O. Those tools
            #    have non-empty behavior, so this branch is reached ONLY when
            #    NO tool was successfully analyzed — the actual coverage gap.
            result.verdict = "shallow"
            result.verdict_reason = (
                f"Tools were detected ({len(tools)}) but MIS extracted ZERO behavior signals from "
                "any of them — not even PURE_COMPUTE. This means the analyzer recognized the tool "
                "names but failed to follow ANY of their implementation logic — typically because "
                "tool bodies route through class methods (L18), helpers across modules, or other "
                "unrecognized dispatch shapes. Treat this as 'analyzed-but-shallow': the verdict "
                "is NOT a safety statement, only a coverage statement. Manual review required."
            )
            result.verdict_confidence = 0.0
        else:
            result.verdict = "benign"
            result.verdict_reason = (
                "Tools were detected and no intent-classifier rule fired. Be aware: a benign "
                "verdict is bounded by what the v0.1 ruleset covers (see LIMITATIONS.md L4); "
                "novel attack shapes may pass through."
            )
            # Confidence in 'benign' is lower than in 'malicious' — calibration of static analysis
            result.verdict_confidence = 0.6
    else:
        top = hits[0]
        result.verdict = top.verdict
        # Top reason verbatim; additional hits appended in compact form
        if len(hits) == 1:
            result.verdict_reason = top.reason
        else:
            extras = "; ".join(f"[{h.rule_id}] {h.reason}" for h in hits[1:])
            result.verdict_reason = f"{top.reason} Also fired: {extras}"
        # Confidence = max single-rule confidence (we don't multiply — over-confidence is harmful)
        result.verdict_confidence = max(h.confidence for h in hits)

    # Triage: pick the top 3 findings by severity, tie-break by OWASP MCP id (lower first)
    result.triage = _select_triage(result.findings, n=3)
    return hits


def _select_triage(findings: list[Finding], *, n: int = 3) -> list[Finding]:
    """Return the top `n` findings to act on first.

    Selection: highest severity first; on ties, prefer findings tagged with
    the "more actionable" OWASP categories (MCP03, MCP05, MCP09 are
    user-facing — the user can decide to uninstall — vs MCP04 which is
    publisher-facing).
    """
    if not findings:
        return []
    actionable_owasp_order = {
        "MCP09:DataExposure": 0,
        "MCP05:CommandInjectionExecution": 1,
        "MCP03:ToolPoisoning": 2,
        "MCP06:IntentFlowSubversion": 3,
        "MCP04:SupplyChain": 4,
        "MCP02:PrivilegeEscalation": 5,
        "MCP01:PromptInjection": 6,
    }
    def sort_key(f: Finding) -> tuple[int, int]:
        return (
            -int(f.severity),
            actionable_owasp_order.get(f.owasp, 99),
        )
    return sorted(findings, key=sort_key)[:n]
