"""Fase 4 — Demo ejecutable y SARIF: la vitrina comercial del rule pack."""
import json
from pathlib import Path

from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine

DEMO = Path(__file__).resolve().parent.parent / "examples" / "roblox-demo"
RULEPACK = Path(__file__).resolve().parent.parent / "rulepacks" / "roblox.yaml"

EXPECTED_IN_BACKDOOR = {"RBX-BD-001", "RBX-BD-002", "RBX-BD-003", "RBX-BD-005", "RBX-EXF-002"}
EXPECTED_IN_REMOTES = {"RBX-TRUST-001", "RBX-TRUST-002", "RBX-ECON-001", "RBX-ECON-002"}


def _scan_demo():
    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = str(RULEPACK)
    engine = CodeAuditEngine(config=cfg)
    return engine.scan(str(DEMO))


def test_demo_project_exists():
    assert (DEMO / "backdoor.luau").exists()
    assert (DEMO / "remotes.luau").exists()
    assert (DEMO / "clean.luau").exists()


def test_demo_scan_finds_expected_roblox_issues():
    result = _scan_demo()
    by_file = {}
    for f in result.findings:
        name = Path(str(f.file_path)).name
        by_file.setdefault(name, set()).add(f.rule_id)
    assert EXPECTED_IN_BACKDOOR <= by_file.get("backdoor.luau", set())
    assert EXPECTED_IN_REMOTES <= by_file.get("remotes.luau", set())


def test_demo_clean_file_has_zero_roblox_findings():
    result = _scan_demo()
    bad = [f.rule_id for f in result.findings
           if Path(str(f.file_path)).name == "clean.luau" and f.rule_id.startswith("RBX-")]
    assert bad == [], f"clean.luau genero falsos positivos: {bad}"


def test_sarif_export_contains_roblox_rules(tmp_path):
    from src.sarif_exporter import generate_sarif

    result = _scan_demo()
    out = tmp_path / "roblox.sarif"
    generate_sarif(result, str(out))
    text = out.read_text()
    assert "RBX-BD-001" in text
    assert "RBX-TRUST-001" in text
