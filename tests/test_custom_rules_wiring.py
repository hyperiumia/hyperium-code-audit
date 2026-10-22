"""Regression: las custom rules deben llegar al PatternScanner (engine wiring)."""
from pathlib import Path

from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine


def test_custom_rules_loaded_and_applied(tmp_path):
    rules = tmp_path / "custom.yaml"
    rules.write_text(
        "\nrules:\n"
        "  - id: CUSTOM-TEST-001\n"
        "    title: Backdoor sink pattern\n"
        "    severity: high\n"
        "    category: security_misconfig\n"
        "    languages: [python]\n"
        "    pattern: 'evil_backdoor_function\\('\n"
        "    confidence: 0.9\n"
    )
    (tmp_path / "app.py").write_text("def run():\n    evil_backdoor_function()\n")

    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = str(rules)
    engine = CodeAuditEngine(config=cfg)

    scanner_ids = [r.id for r in engine.pattern_scanner.rules]
    assert "CUSTOM-TEST-001" in scanner_ids, \
        "custom rules no llegaron al PatternScanner"

    result = engine.scan(str(tmp_path))
    assert any(f.rule_id == "CUSTOM-TEST-001" for f in result.findings), \
        "la regla custom no produjo hallazgo en el scan"
