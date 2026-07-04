"""Integration tests for v2.0 features."""

import json
import pytest
from pathlib import Path
from src.engine import CodeAuditEngine
from src.config import CodeAuditConfig
from src.sarif_exporter import generate_sarif


class TestV2Integration:
    def test_engine_with_taint(self, tmp_source_dir):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        cfg.scanners.taint_analyzer = True
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))

        assert result.total_findings > 0
        assert result.completed_at

    def test_sarif_export_from_scan(self, tmp_source_dir, tmp_path):
        cfg = CodeAuditConfig()
        cfg.scanners.check_epss = False
        engine = CodeAuditEngine(cfg)
        result = engine.scan(str(tmp_source_dir))

        sarif_path = generate_sarif(result, tmp_path / "test.sarif")
        assert sarif_path.exists()

        data = json.loads(sarif_path.read_text())
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_cli_sarif_format(self, tmp_source_dir):
        from click.testing import CliRunner
        from src.cli import main

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(main, [
                "scan", str(tmp_source_dir),
                "--format", "sarif", "--no-deps",
            ])
            assert result.exit_code in (0, 1)
