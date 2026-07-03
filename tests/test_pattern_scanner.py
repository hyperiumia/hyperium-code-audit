"""Tests for the OWASP pattern scanner."""

import pytest
from pathlib import Path
from src.pattern_scanner import PatternScanner, detect_language, ALL_RULES
from src.models import FindingCategory, Language, Severity


class TestPatternScanner:
    def test_scanner_creation(self):
        scanner = PatternScanner()
        assert scanner.rule_count > 0

    def test_detect_sql_injection(self, tmp_source_dir):
        scanner = PatternScanner()
        findings = scanner.scan_file(tmp_source_dir / "vulnerable.py")
        sql_findings = [f for f in findings if f.category == FindingCategory.INJECTION]
        assert len(sql_findings) >= 1
        assert any("SQL" in f.title for f in sql_findings)

    def test_detect_command_injection(self, tmp_source_dir):
        scanner = PatternScanner()
        findings = scanner.scan_file(tmp_source_dir / "vulnerable.py")
        # Should detect os.system(f'ping {user_input}') or eval(user_data)
        cmd_findings = [f for f in findings
                        if f.category == FindingCategory.COMMAND_INJECTION]
        assert len(cmd_findings) >= 1

    def test_detect_xss_js(self, tmp_source_dir):
        scanner = PatternScanner()
        findings = scanner.scan_file(tmp_source_dir / "app.js")
        xss_findings = [f for f in findings if f.category == FindingCategory.XSS]
        assert len(xss_findings) >= 1

    def test_detect_eval(self, tmp_source_dir):
        scanner = PatternScanner()
        findings = scanner.scan_file(tmp_source_dir / "app.js")
        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert len(eval_findings) >= 1

    def test_min_confidence_filter(self):
        # All current rules have confidence >= 0.5, so filter by 0.9 to exclude some
        high = PatternScanner(min_confidence=0.9)
        low = PatternScanner(min_confidence=0.5)
        assert high.rule_count <= low.rule_count

    def test_exclude_rules(self):
        scanner = PatternScanner(exclude_rules=["GEN-SEC-001"])
        for rules in scanner._rules_by_lang.values():
            assert all(r.id != "GEN-SEC-001" for r in rules)

    def test_language_detection(self):
        assert detect_language(Path("app.py")) == Language.PYTHON
        assert detect_language(Path("app.js")) == Language.JAVASCRIPT
        assert detect_language(Path("app.php")) == Language.PHP
        assert detect_language(Path("app.java")) == Language.JAVA
        assert detect_language(Path("file.txt")) == Language.UNKNOWN

    def test_scan_returns_finding_details(self, tmp_source_dir):
        scanner = PatternScanner()
        findings = scanner.scan_file(tmp_source_dir / "vulnerable.py")
        assert len(findings) > 0
        f = findings[0]
        assert f.file_path
        assert f.line_number > 0
        assert f.code_snippet
        assert f.remediation
        assert f.cwe_id

    def test_all_rules_valid_regex(self):
        for rule in ALL_RULES:
            assert rule._compiled is not None, f"Rule {rule.id} has invalid regex"
