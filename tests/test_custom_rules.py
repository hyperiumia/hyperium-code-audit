"""Tests for custom rules engine."""

import pytest
from pathlib import Path
from src.custom_rules import load_custom_rules, generate_example_rules


class TestCustomRules:
    def test_load_valid_rules(self, tmp_path):
        f = tmp_path / "rules.yaml"
        f.write_text(
            "rules:\n"
            "  - id: TEST-001\n"
            "    title: Test rule\n"
            "    severity: high\n"
            "    category: injection\n"
            "    languages: [python]\n"
            '    pattern: \'os\\.system\\(\'\n'
            "    confidence: 0.8\n"
        )
        rules = load_custom_rules(str(f))
        assert len(rules) == 1
        assert rules[0].id == "TEST-001"

    def test_load_multiple(self, tmp_path):
        f = tmp_path / "multi.yaml"
        f.write_text(
            "rules:\n"
            "  - id: M-001\n"
            "    title: R1\n"
            "    severity: low\n"
            "    category: xss\n"
            '    pattern: \'innerHTML\'\n'
            "  - id: M-002\n"
            "    title: R2\n"
            "    severity: high\n"
            "    category: injection\n"
            '    pattern: \'eval\\(\'\n'
        )
        rules = load_custom_rules(str(f))
        assert len(rules) == 2

    def test_invalid_severity_skipped(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(
            "rules:\n"
            "  - id: B-001\n"
            "    title: Bad\n"
            "    severity: supercritical\n"
            "    category: injection\n"
            '    pattern: \'test\'\n'
        )
        rules = load_custom_rules(str(f))
        assert len(rules) == 0

    def test_invalid_regex_skipped(self, tmp_path):
        f = tmp_path / "badregex.yaml"
        f.write_text(
            "rules:\n"
            "  - id: BR-001\n"
            "    title: Bad regex\n"
            "    severity: medium\n"
            "    category: injection\n"
            '    pattern: \'[invalid(\'\n'
        )
        rules = load_custom_rules(str(f))
        assert len(rules) == 0

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_custom_rules("/nonexistent/rules.yaml")

    def test_empty_rules(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("rules: []")
        rules = load_custom_rules(str(f))
        assert len(rules) == 0

    def test_generate_example(self, tmp_path):
        path = generate_example_rules(str(tmp_path / "example.yaml"))
        assert path.exists()
        rules = load_custom_rules(str(path))
        assert len(rules) >= 2

    def test_custom_rule_detection(self, tmp_path):
        rules_f = tmp_path / "rules.yaml"
        rules_f.write_text(
            "rules:\n"
            "  - id: CUSTOM-OS\n"
            "    title: OS system call\n"
            "    severity: high\n"
            "    category: command_injection\n"
            "    languages: [python]\n"
            '    pattern: \'os\\.system\\(\'\n'
        )
        code = tmp_path / "test.py"
        code.write_text("import os\nos.system('ls')\n")
        from src.pattern_scanner import PatternScanner
        from src.custom_rules import load_custom_rules
        custom = load_custom_rules(str(rules_f))
        scanner = PatternScanner(rules=custom)
        findings = scanner.scan_file(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "CUSTOM-OS"
