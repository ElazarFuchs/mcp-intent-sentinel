"""Integration tests over the bundled corpus.

The corpus is the contract: every fixture under tests/corpus/malicious/ MUST
classify as malicious (or at least suspicious for low-confidence rules) and
every fixture under tests/corpus/benign/ MUST classify as benign.

If you want to add a new rule, add a fixture that triggers it. If a fixture
no longer triggers any rule, decide whether the fixture is wrong or the rule
went missing — never silently mark it benign.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mis.engine import scan_directory


CORPUS = Path(__file__).parent / "corpus"


# ----- malicious fixtures: expected verdict + at least one rule firing ----

MALICIOUS_EXPECTATIONS = {
    "postmark_backdoor":   {"verdict": "malicious", "rule_id_substr": "bcc_injection"},
    "silent_exfiltrator":  {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    "tool_shadowing":      {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    "hidden_instruction":  {"verdict": "malicious", "rule_id_substr": "tool_poisoning"},
    "command_injection":   {"verdict": "malicious", "rule_id_substr": "command_injection"},
    "lifecycle_dropper":   {"verdict": "malicious", "rule_id_substr": "lifecycle_dropper"},
    # v0.1.1: official low-level SDK pattern. Regression-test against the
    # field-test miss where mcp-server-fetch and the official servers monorepo
    # both verdicted as benign because their @server.list_tools / @server.call_tool
    # registrations were not detected. This fixture MUST classify as malicious.
    "official_sdk_exfil":  {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # v0.1.2: realistic field-test repro. @app.call_tool() dispatch + httpx +
    # `async with httpx.AsyncClient() as client:` aliasing + OPENAI_API_KEY in
    # header. Pre-v0.1.2 this was BENIGN because `client.post` wasn't recognized
    # as a net call. Now it MUST classify as malicious.
    "openai_key_in_header": {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # v0.1.2: split exfil — secret read and net call in DIFFERENT helpers.
    # Stresses inter-procedural taint (L2 partial closure via function summaries).
    "helper_exfil":         {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # v0.1.2: requests.Session() alias on a different SDK + plain assignment
    # (not `with ... as`). The full check is that aliases work across SDKs and
    # binding shapes.
    "requests_session_exfil": {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # v0.1.6 — three fixtures promoted from the model-compliance eval's
    # TRUE_BYPASS rows (bypass_classified.txt). Each was an actual model
    # output that pre-v0.1.6 MIS verdicted as benign / unknown.
    #
    # runtime_context_exfil: "modified payload" bypass — model refuses env
    # exfil and substitutes platform.platform()+socket.gethostname(). v0.1.6
    # adds HOST_FINGERPRINT_READ/_IN_REQUEST + r11 → suspicious.
    "runtime_context_exfil": {"verdict": "suspicious", "rule_id_substr": "fingerprint_to_request"},
    # module_level_secret_exfil: KEY=os.environ[...] at module scope referenced
    # from tool body. v0.1.6 adds Pass-0 module-secret collection that seeds
    # body walkers' _secret_taint.
    "module_level_secret_exfil": {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # dict_literal_tools_exfil: official SDK + list_tools returns dict literals
    # instead of Tool(...) instances. v0.1.6 widens _extract_tools_from_list_tools.
    "dict_literal_tools_exfil": {"verdict": "malicious", "rule_id_substr": "secret_to_request"},
    # v0.1.12 — staged-stash exfil. Tool reads ~/.ssh/id_rsa into module-level
    # state but doesn't send in the same call. r4 exempted it post-v0.1.10
    # (intent=file). r12.staged_stash catches the read-without-local-use shape.
    "staged_stash_ssh_read": {"verdict": "suspicious", "rule_id_substr": "staged_stash"},
    # v0.1.13 — legit-API-client downgrade regression. NOT morally malicious;
    # the fixture is a real Notion API client that reads NOTION_API_KEY from
    # env and uses it as Bearer to api.notion.com. Pre-v0.1.13 r1 verdicted
    # malicious (env-key -> outbound). v0.1.13's host-claim partition matches
    # the pyproject `notion-mcp` name against the api.notion.com host and
    # downgrades to suspicious. (Lives in `malicious/` because that's where
    # rule-firing fixtures live in this test suite — the directory name is
    # technical, not semantic; see also runtime_context_exfil which is in
    # malicious/ but verdicts suspicious for similar reasons.)
    "legit_api_client_host_claim_downgrade": {"verdict": "suspicious", "rule_id_substr": "secret_to_request"},
}

BENIGN_FIXTURES = [
    "calc_python", "fetch_simple", "echo_js",
    # v0.1.1: shape-equivalent to mcp-server-fetch. Tests that a legitimate
    # fetcher using the official SDK is detected as a tool AND classifies benign.
    "official_sdk_fetch",
    # v0.1.7 — two FP regression fixtures, promoted from the critique of v0.1.5.
    # legit_shell_kubectl: a kubectl wrapper that shells out with tool input.
    # Pre-v0.1.7 r6.command_injection fired malicious. v0.1.7 added role-aware
    # exemption: when declared_intent == "shell" (now covers kubectl/docker/
    # terraform/ansible/etc.), shell-with-input is expected behavior.
    "legit_shell_kubectl",
    # legit_node_fetch_import: imports node-fetch and uses fetch inside the
    # tool handler (NOT at module top). Pre-v0.1.7 the regex `\bnode-fetch\b`
    # matched the import line as a top-level net call; this was the
    # @modelcontextprotocol/server-gitlab FP. v0.1.7 dropped the bare-word
    # regex; actual fetch calls are detected via `\bfetch\s*\(`.
    "legit_node_fetch_import",
    # legit_file_role_reads_ssh_config: a file-reading tool that legitimately
    # touches ~/.ssh/config. Pre-v0.1.10 r4's SECRET_FS_READ catch-all flagged
    # it suspicious. v0.1.10 added role-aware exemption (declared_intent in
    # {file, shell, fetch} skips the catch-all) after the LLM-fallback pilot
    # surfaced this FP on server-filesystem / mcp-figma / playwright_upload.
    "legit_file_role_reads_ssh_config",
]

# v0.1.2: shallow-verdict fixtures. These are LEGITIMATE servers whose
# implementation uses patterns MIS cannot follow yet (class-based dispatch,
# imperative registration, deeply nested helpers). The expected verdict is
# `shallow` — MIS must admit incomplete coverage, not claim safety.
#
# v0.1.5 moved `file_lister` here: its body uses `Path(d).iterdir()` which is
# a real filesystem read MIS doesn't classify as an I/O signal. The honest
# verdict is shallow ("MIS saw a call it didn't understand"), not benign.
# This is the same correctness move that fixes the server-github leak.
SHALLOW_FIXTURES = ["class_based_fetcher", "file_lister"]


@pytest.mark.parametrize("name,expected", list(MALICIOUS_EXPECTATIONS.items()))
def test_malicious_fixture(name: str, expected: dict) -> None:
    fixture = CORPUS / "malicious" / name
    assert fixture.is_dir(), f"missing fixture: {fixture}"
    result, hits = scan_directory(fixture)
    assert result.verdict == expected["verdict"], (
        f"{name}: expected {expected['verdict']} but got {result.verdict}\n"
        f"reason: {result.verdict_reason}"
    )
    assert any(expected["rule_id_substr"] in h.rule_id for h in hits), (
        f"{name}: expected a rule containing '{expected['rule_id_substr']}' to fire; got {[h.rule_id for h in hits]}"
    )


@pytest.mark.parametrize("name", BENIGN_FIXTURES)
def test_benign_fixture(name: str) -> None:
    fixture = CORPUS / "benign" / name
    assert fixture.is_dir(), f"missing fixture: {fixture}"
    result, hits = scan_directory(fixture)
    assert result.verdict == "benign", (
        f"{name}: expected benign but got {result.verdict}\n"
        f"reason: {result.verdict_reason}\n"
        f"hits: {[(h.rule_id, h.reason) for h in hits]}"
    )


@pytest.mark.parametrize("name", SHALLOW_FIXTURES)
def test_shallow_fixture(name: str) -> None:
    """Legit servers MIS can't analyze deeply must verdict `shallow`, not `benign`.

    A benign verdict here would be the original sin: green light on something
    the analyzer didn't actually examine. The shallow verdict makes that honest.
    """
    fixture = CORPUS / "shallow" / name
    assert fixture.is_dir(), f"missing fixture: {fixture}"
    result, hits = scan_directory(fixture)
    assert result.verdict == "shallow", (
        f"{name}: expected shallow but got {result.verdict}\n"
        f"reason: {result.verdict_reason}\n"
        f"tools detected: {[getattr(t, 'name', '?') for t in result.tools]}\n"
        f"behavior signals: {[sorted(b.value for b in getattr(t, 'behavior', set())) for t in result.tools]}"
    )


def test_malicious_corpus_size() -> None:
    """Guard against accidentally adding a fixture without an expectation entry."""
    actual = {p.name for p in (CORPUS / "malicious").iterdir() if p.is_dir()}
    assert actual == set(MALICIOUS_EXPECTATIONS.keys()), (
        f"mismatch — malicious dirs={actual}, expectations={set(MALICIOUS_EXPECTATIONS.keys())}"
    )


def test_benign_corpus_size() -> None:
    actual = {p.name for p in (CORPUS / "benign").iterdir() if p.is_dir()}
    assert actual == set(BENIGN_FIXTURES), (
        f"mismatch — benign dirs={actual}, expectations={set(BENIGN_FIXTURES)}"
    )


def test_triage_is_capped_at_3() -> None:
    """Spec § 5.2: top-3 findings on top, not 100."""
    result, _ = scan_directory(CORPUS / "malicious" / "command_injection")
    assert len(result.triage) <= 3


def test_json_shape_is_stable() -> None:
    """Spec § 5.2: machine-readable output for CI consumers."""
    from mis.report import render_json
    import json
    result, hits = scan_directory(CORPUS / "malicious" / "postmark_backdoor")
    payload = render_json(result, hits)
    data = json.loads(payload)
    # Required keys at the top level
    for k in ("source", "root", "verdict", "verdict_reason", "verdict_confidence",
              "max_severity", "triage", "findings", "by_owasp", "rule_hits"):
        assert k in data, f"missing key in JSON output: {k}"
    # Verdict and confidence are present and sane
    assert data["verdict"] in {"benign", "suspicious", "malicious"}
    assert 0.0 <= data["verdict_confidence"] <= 1.0
