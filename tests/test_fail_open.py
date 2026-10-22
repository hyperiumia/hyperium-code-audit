"""Fase 6.1 (P0) — Errores operativos nunca terminan como analisis limpio.

Convencion de codigos de salida:
  0 = completado (hallazgos segun --fail-on)
  1 = hallazgos al nivel del gate
  2 = error operativo/configuracion (analisis incompleto o no ejecutado)
"""
from unittest.mock import patch

from click.testing import CliRunner

from src.cli import main


def _scan(tmp_path, extra_args):
    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    args = ["scan", str(target), "--no-deps", "--format", "json",
            "-o", str(tmp_path / "out")] + extra_args
    return CliRunner().invoke(main, args)


def test_missing_pack_exits_operational_error(tmp_path):
    r = _scan(tmp_path, ["--custom-rules", str(tmp_path / "missing.yaml")])
    assert r.exit_code == 2, f"pack ausente dio exit {r.exit_code}"
    assert "Exit 0: clean" not in r.output


def test_malformed_pack_exits_operational_error(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [broken\n")
    r = _scan(tmp_path, ["--custom-rules", str(bad)])
    assert r.exit_code == 2, f"pack invalido dio exit {r.exit_code}"
    assert "Exit 0: clean" not in r.output


def test_internal_error_never_reports_clean(tmp_path):
    from src.pattern_scanner import PatternScanner

    with patch.object(PatternScanner, "scan_file",
                      side_effect=RuntimeError("REVIEW_SYNTHETIC")):
        r = _scan(tmp_path, [])
    assert r.exit_code == 2, f"error interno dio exit {r.exit_code}"
    assert "Exit 0: clean" not in r.output
    assert "partial" in r.output.lower() or "failed" in r.output.lower(), \
        "el estado operativo debe hacerse visible"


def test_luau_without_rulepack_warns_about_coverage(tmp_path):
    target = tmp_path / "game"
    target.mkdir()
    (target / "main.luau").write_text("local x = loadstring(payload)\n")
    r = CliRunner().invoke(main,
        ["scan", str(target), "--no-deps", "--format", "json",
         "-o", str(tmp_path / "out2")])
    assert "no custom rule pack active" in r.output.lower(), \
        "sin pack, la cobertura Luau vacia debe comunicarse al usuario"


def test_operational_errors_recorded_in_result(tmp_path):
    from src.config import CodeAuditConfig
    from src.engine import CodeAuditEngine

    target = tmp_path / "proj2"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")

    class RaisingHistory:
        def save_scan(self, result):
            raise PermissionError("REVIEW_SYNTHETIC")

    cfg = CodeAuditConfig()
    engine = CodeAuditEngine(cfg)
    engine.scan_history = RaisingHistory()
    result = engine.scan(str(target))
    assert result.stats.errors, "errores operativos deben persistirse en stats"
