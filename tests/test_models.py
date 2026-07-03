"""Tests for data models."""

import pytest
from src.models import (
    Finding, Severity, FindingCategory, Language,
    SecretFinding, PaymentFinding, DepVulnerability,
    RiskScore, ScanResult, ComplianceReport, ComplianceFramework,
)


class TestFinding:
    def test_create_finding(self, sample_finding):
        assert sample_finding.severity == Severity.CRITICAL
        assert sample_finding.cwe_id == "CWE-89"
        assert sample_finding.confidence == 0.9

    def test_finding_auto_id(self):
        f1 = Finding(rule_id="TEST", title="Test", category=FindingCategory.INJECTION,
                     severity=Severity.HIGH, file_path="a.py")
        f2 = Finding(rule_id="TEST", title="Test", category=FindingCategory.INJECTION,
                     severity=Severity.HIGH, file_path="b.py")
        assert f1.id != f2.id

    def test_severity_weights(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.INFO.weight == 0


class TestScanResult:
    def test_total_findings(self):
        result = ScanResult(target_path=".")
        assert result.total_findings == 0

    def test_total_findings_with_data(self):
        result = ScanResult(
            target_path=".",
            findings=[Finding(rule_id="R", title="T", category=FindingCategory.XSS,
                              severity=Severity.HIGH, file_path="f.py")],
            secrets=[SecretFinding(secret_type="KEY", file_path="f", line_number=1,
                                   redacted_value="***", confidence=0.9)],
        )
        assert result.total_findings == 2

    def test_has_critical(self):
        result = ScanResult(
            target_path=".",
            risk_score=RiskScore(overall_score=90, risk_level=Severity.CRITICAL, critical_count=3),
        )
        assert result.has_critical is True


class TestRiskScore:
    def test_score_clamp(self):
        score = RiskScore(overall_score=95.5, risk_level=Severity.CRITICAL)
        assert 0 <= score.overall_score <= 100
