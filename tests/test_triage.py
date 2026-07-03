"""Tests for the triage engine."""

import pytest
from src.triage_engine import TriageEngine
from src.models import Finding, FindingCategory, Severity


class TestTriageEngine:
    def test_empty_scan(self):
        engine = TriageEngine()
        score = engine.score([])
        assert score.overall_score == 0
        assert score.total_findings == 0

    def test_critical_findings_high_score(self):
        engine = TriageEngine()
        findings = [
            Finding(rule_id="R", title="T", category=FindingCategory.INJECTION,
                    severity=Severity.CRITICAL, confidence=0.9, file_path="app.py")
            for _ in range(5)
        ]
        score = engine.score(findings)
        assert score.overall_score > 50
        assert score.risk_level in (Severity.CRITICAL, Severity.HIGH)

    def test_prioritize_critical_first(self):
        engine = TriageEngine()
        findings = [
            Finding(rule_id="R1", title="Low", category=FindingCategory.XSS,
                    severity=Severity.LOW, file_path="a.py"),
            Finding(rule_id="R2", title="Critical", category=FindingCategory.INJECTION,
                    severity=Severity.CRITICAL, file_path="b.py"),
            Finding(rule_id="R3", title="Medium", category=FindingCategory.CRYPTO_FAILURE,
                    severity=Severity.MEDIUM, file_path="c.py"),
        ]
        prioritized = engine.prioritize(findings)
        assert prioritized[0].severity == Severity.CRITICAL
