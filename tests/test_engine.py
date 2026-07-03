"""Tests for the scan engine."""

import pytest
from pathlib import Path
from src.engine import CodeAuditEngine
from src.config import CodeAuditConfig


class TestEngine:
    def test_scan_returns_result(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        cfg.scanners.check_cisa_kev = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))

        assert result.scan_id
        assert result.total_findings > 0
        assert result.risk_score is not None
        assert result.stats.total_files_scanned > 0
        assert result.completed_at

    def test_scan_finds_secrets(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))
        assert len(result.secrets) > 0

    def test_scan_finds_payment_issues(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))
        assert len(result.payment_findings) > 0

    def test_scan_finds_dep_vulns(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))
        assert len(result.dep_vulnerabilities) > 0

    def test_risk_score_calculated(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))
        assert result.risk_score.overall_score > 0
        assert result.risk_score.total_findings > 0

    def test_compliance_mapped(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        cfg.analysis.frameworks = ["owasp_top_10"]
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))
        assert len(result.compliance_reports) == 1
        assert result.compliance_reports[0].compliance_percentage < 100

    def test_progress_callback(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)

        phases = []
        def on_progress(phase, msg, pct):
            phases.append(phase)

        engine.set_progress_callback(on_progress)
        engine.scan(str(tmp_source_dir))
        assert len(phases) > 0
        assert "DONE" in phases
