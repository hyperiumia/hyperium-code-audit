"""Tests for the CLI."""

import pytest
from click.testing import CliRunner
from src.cli import main


class TestCLI:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "4.0.0" in result.output

    def test_scan_runs(self, tmp_source_dir):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(tmp_source_dir), "--no-deps"])
        # Should complete (exit 1 if critical findings found)
        assert result.exit_code in (0, 1)
        assert "Risk Score" in result.output or "Scan" in result.output
