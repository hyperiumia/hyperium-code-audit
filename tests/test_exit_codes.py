"""Tests for exit code logic."""

import pytest
from src.cli import _calculate_exit_code
from src.models import RiskScore, Severity


class TestExitCodes:
    def test_no_risk_returns_zero(self):
        assert _calculate_exit_code(None, "critical") == 0

    def test_fail_never_returns_zero(self):
        risk = RiskScore(overall_score=100, risk_level=Severity.CRITICAL, critical_count=10)
        assert _calculate_exit_code(risk, "never") == 0

    def test_critical_with_findings_returns_one(self):
        risk = RiskScore(overall_score=90, risk_level=Severity.CRITICAL, critical_count=3)
        assert _calculate_exit_code(risk, "critical") == 1

    def test_critical_clean_returns_zero(self):
        risk = RiskScore(overall_score=50, risk_level=Severity.MEDIUM, critical_count=0, high_count=5)
        assert _calculate_exit_code(risk, "critical") == 0

    def test_high_threshold(self):
        risk = RiskScore(overall_score=60, risk_level=Severity.HIGH, critical_count=0, high_count=2)
        assert _calculate_exit_code(risk, "high") == 1
        assert _calculate_exit_code(risk, "critical") == 0

    def test_medium_threshold(self):
        risk = RiskScore(overall_score=40, risk_level=Severity.MEDIUM, medium_count=5)
        assert _calculate_exit_code(risk, "medium") == 1
        assert _calculate_exit_code(risk, "high") == 0

    def test_low_threshold(self):
        risk = RiskScore(
            overall_score=10, risk_level=Severity.LOW,
            critical_count=0, high_count=0, medium_count=0, low_count=1,
            total_findings=1,
        )
        assert _calculate_exit_code(risk, "low") == 1
