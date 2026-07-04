"""Tests for the SARIF exporter."""

import json
import pytest
from pathlib import Path
from src.sarif_exporter import generate_sarif, SARIF_VERSION
from src.models import (
    ScanResult, Finding, FindingCategory, Severity, Language,
    SecretFinding, RiskScore, ScanStats,
)


class TestSarifExporter:
    def _make_result(self):
        return ScanResult(
            target_path="./src",
            findings=[
                Finding(
                    rule_id="GEN-SEC-001",
                    title="SQL Injection",
                    category=FindingCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    file_path="src/db.py",
                    line_number=47,
                    code_snippet='execute("SELECT * WHERE id=" + uid)',
                    language=Language.PYTHON,
                    cwe_id="CWE-89",
                    owasp_id="A03",
                    description="SQL injection via string concat",
                    remediation="Use parameterized queries",
                ),
            ],
            secrets=[
                SecretFinding(
                    secret_type="STRIPE_KEY",
                    file_path=".env",
                    line_number=3,
                    redacted_value="sk_l***AB",
                    confidence=0.95,
                    is_live_key=True,
                ),
            ],
            risk_score=RiskScore(
                overall_score=78,
                risk_level=Severity.HIGH,
                critical_count=1,
                high_count=1,
            ),
            stats=ScanStats(total_files_scanned=100, scan_duration_seconds=5.2),
        )

    def test_generates_valid_json(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())

        assert data["version"] == SARIF_VERSION
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_contains_tool_info(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        driver = data["runs"][0]["tool"]["driver"]

        assert driver["name"] == "hyperium-code-audit"
        assert driver["version"] == "1.0.0"

    def test_contains_results(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        results = data["runs"][0]["results"]

        # 1 finding + 1 secret = 2 results
        assert len(results) == 2

    def test_finding_mapped_correctly(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        finding_result = data["runs"][0]["results"][0]

        assert finding_result["ruleId"] == "GEN-SEC-001"
        assert finding_result["level"] == "error"  # CRITICAL maps to error
        assert "sql injection" in finding_result["message"]["text"].lower()

    def test_secret_mapped_correctly(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        secret_result = data["runs"][0]["results"][1]

        assert "STRIPE" in secret_result["ruleId"]
        assert secret_result["level"] == "error"  # live key = error

    def test_rules_collected(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        rules = data["runs"][0]["tool"]["driver"]["rules"]

        rule_ids = [r["id"] for r in rules]
        assert "GEN-SEC-001" in rule_ids

    def test_properties_contain_scan_info(self, tmp_path):
        result = self._make_result()
        output = generate_sarif(result, tmp_path / "test.sarif")
        data = json.loads(output.read_text())
        props = data["runs"][0]["properties"]

        assert props["totalFindings"] > 0
        assert props["filesScanned"] == 100
        assert "riskScore" in props

    def test_empty_result(self, tmp_path):
        result = ScanResult(target_path=".")
        output = generate_sarif(result, tmp_path / "empty.sarif")
        data = json.loads(output.read_text())

        assert data["version"] == SARIF_VERSION
        assert data["runs"][0]["results"] == []
