"""Fase 6.4 (P1, casos 1-6) — Calidad de deteccion del rule pack.

1. Espacios validos no evaden deteccion.
2-3. Comentarios y literales no disparan alertas de codigo.
4-5. Reglas de contexto = puntos de revision, sin afirmar ausencias.
6. Configuracion deshabilitada no dispara la regla.
"""
from src.models import Severity
from src.pattern_scanner import PatternScanner
from src.custom_rules import load_custom_rules

PACK = "roblox"


def _findings(snippet: str, tmp_path, name: str = "f.luau"):
    p = tmp_path / name
    p.write_text(snippet)
    scanner = PatternScanner(rules=load_custom_rules(PACK))
    return scanner.scan_file(p)


def _by_rule(findings, rid):
    return [f for f in findings if f.rule_id == rid]


# Caso 1: espacios y variantes triviales
def test_require_with_spaces_detected(tmp_path):
    hits = _findings("local m = require ( 1234567890 )\n", tmp_path)
    assert _by_rule(hits, "RBX-BD-003"), "require con espacios no detectado"


def test_loadstring_with_spaces_detected(tmp_path):
    hits = _findings("local f = loadstring ( payload )\n", tmp_path)
    assert _by_rule(hits, "RBX-BD-001"), "loadstring con espacios no detectado"


# Casos 2-3: comentarios y literales no son codigo ejecutable
def test_comment_does_not_trigger_backdoor(tmp_path):
    hits = _findings("-- Example of forbidden code: loadstring(payload)\nreturn {}\n", tmp_path)
    assert not _by_rule(hits, "RBX-BD-001"), "comentario disparo alerta critica"


def test_string_literal_does_not_trigger_backdoor(tmp_path):
    hits = _findings('local help = "Do not use loadstring(payload)"\n', tmp_path)
    assert not _by_rule(hits, "RBX-BD-001"), "literal de texto disparo alerta critica"


def test_comment_does_not_hide_real_call(tmp_path):
    hits = _findings(
        "-- harmless comment with require(999)\nlocal f = loadstring(payload)\n", tmp_path)
    assert _by_rule(hits, "RBX-BD-001"), "la llamada real tras comentario no detectada"


# Caso 4: handler validado = punto de revision, sin afirmar ausencia
def test_validated_handler_is_review_point(tmp_path):
    src = (
        "remote.OnServerEvent:Connect(function(player, amount)\n"
        '    if typeof(amount) ~= "number" or amount ~= amount then return end\n'
        "    if amount < 0 or amount > 100 then return end\n"
        "    if not Permissions.CanUse(player) or not Limiter.Allow(player) then return end\n"
        "    doSomething(player, amount)\n"
        "end)\n"
    )
    hits = _findings(src, tmp_path)
    flagged = _by_rule(hits, "RBX-TRUST-001")
    assert flagged, "punto de revision TRUST-001 ausente"
    f = flagged[0]
    assert f.severity == Severity.LOW, "punto de revision con severidad alta"
    text = (f.title + " " + f.description).lower()
    assert "review" in text, "el hallazgo debe presentarse como punto de revision"


# Caso 5: SetAsync con pcall no afirma ausencia de manejo de errores
def test_setasync_in_pcall_is_review_point(tmp_path):
    src = (
        "local ok, err = pcall(function()\n"
        '    store:SetAsync("example", value)\n'
        "end)\n"
        "if not ok then warn(err) end\n"
    )
    hits = _findings(src, tmp_path)
    flagged = _by_rule(hits, "RBX-ECON-002")
    assert flagged, "punto de revision ECON-002 ausente"
    f = flagged[0]
    assert f.severity == Severity.LOW
    text = (f.title + " " + f.description).lower()
    assert "review" in text or "verify" in text, \
        "no debe afirmar ausencia de manejo de errores"


# Caso 6: configuracion deshabilitada vs habilitada
def test_disabled_setting_not_flagged(tmp_path):
    hits = _findings("local config = {LoadStringEnabled = false}\n", tmp_path)
    assert not _by_rule(hits, "RBX-CFG-001"), "LoadStringEnabled=false no debe disparar"


def test_enabled_setting_flagged(tmp_path):
    hits = _findings("local config = {LoadStringEnabled = true}\n", tmp_path)
    assert _by_rule(hits, "RBX-CFG-001"), "LoadStringEnabled=true debe disparar"
