"""Tests for scan history and trending."""

import json
import pytest
from pathlib import Path
from src.scan_history import ScanHistory, format_trend_report
from src.models import ScanResult, RiskScore, Severity, Finding, FindingCategory


class TestScanHistory:
    def _make_result(self, score=50, critical=0, high=1, medium=2, low=3):
        return ScanResult(
            target_path="./test",
            risk_score=RiskScore(
                overall_score=score, risk_level=Severity.MEDIUM,
                critical_count=critical, high_count=high,
                medium_count=medium, low_count=low,
                total_findings=critical + high + medium + low,
            ),
            findings=[
                Finding(rule_id=f"R{i}", title=f"Finding {i}", category=FindingCategory.XSS,
                        severity=Severity.MEDIUM, file_path=f"f{i}.py", line_number=i)
                for i in range(critical + high + medium + low)
            ],
        )

    def test_save_and_load(self, tmp_path):
        history = ScanHistory(str(tmp_path / "history"))
        result = self._make_result()
        history.save_scan(result)

        all_scans = history.get_history()
        assert len(all_scans) == 1
        assert all_scans[0]["risk_score"] == 50

    def test_multiple_scans(self, tmp_path):
        history = ScanHistory(str(tmp_path / "history"))
        history.save_scan(self._make_result(score=70))
        history.save_scan(self._make_result(score=50))
        history.save_scan(self._make_result(score=30))

        assert len(history.get_history()) == 3
        assert history.get_latest()["risk_score"] == 30

    def test_compare_improving(self, tmp_path):
        history = ScanHistory(str(tmp_path / "history"))
        history.save_scan(self._make_result(score=80, critical=5))
        current = self._make_result(score=40, critical=1)

        delta = history.compare(current)
        assert delta["trend"] == "improving"
        assert delta["score"]["delta"] < 0

    def test_compare_degrading(self, tmp_path):
        history = ScanHistory(str(tmp_path / "history"))
        history.save_scan(self._make_result(score=30))
        current = self._make_result(score=70, critical=5)

        delta = history.compare(current)
        assert delta["trend"] == "degrading"

    def test_first_scan_no_history(self, tmp_path):
        history = ScanHistory(str(tmp_path / "empty"))
        result = self._make_result()
        delta = history.compare(result)
        assert delta["status"] == "first_scan"

    def test_format_report(self):
        delta = {
            "trend": "improving",
            "score": {"previous": 80, "current": 40, "delta": -40, "change_pct": -50},
            "findings": {"previous": 30, "current": 15, "new": 2, "fixed": 17},
            "severity": {
                "critical": {"prev": 5, "curr": 1},
                "high": {"prev": 10, "curr": 5},
            },
        }
        report = format_trend_report(delta)
        assert "improving" in report.lower()
        assert "80" in report
        assert "40" in report
