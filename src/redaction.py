"""Central redaction — secretos nunca llegan a persistencia ni exportacion.

Fase 6.3 (P1): todo texto adjunto a hallazgos pasa por redact_text()
antes de guardarse o exportarse (JSON, SARIF, HTML, PDF).
"""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"

_WEBHOOK = re.compile(r"(discord(?:app)?[.]com/api/webhooks/[0-9]+/)([A-Za-z0-9_-]{6,})")
_AWSKEY = re.compile(r"AKIA[0-9A-Z]{16}")
_BEARER = re.compile(r"(Bearer[ ]+)([A-Za-z0-9_.-]{8,})")
_GENERIC = re.compile(r"(?i)(token|secret|password|api[_-]?key)[ :=]+[\"']?([A-Za-z0-9_.-]{8,})")


def _keep_prefix(m):
    return m.group(1) + _REDACTED


def _drop(m):
    return _REDACTED


def redact_text(text):
    """Mask secret-looking content while preserving surrounding context."""
    if not isinstance(text, str) or not text:
        return text
    out = _WEBHOOK.sub(_keep_prefix, text)
    out = _AWSKEY.sub(_drop, out)
    out = _BEARER.sub(_keep_prefix, out)
    out = _GENERIC.sub(_keep_prefix, out)
    return out


def redact_result(result) -> None:
    """Redact in place: findings, secrets y payment findings."""
    for bucket in (getattr(result, "findings", None) or [],
                   getattr(result, "secrets", None) or [],
                   getattr(result, "payment_findings", None) or []):
        for obj in bucket:
            _redact_obj(obj)


def _redact_obj(obj, depth: int = 0) -> None:
    if obj is None or depth > 8:
        return
    if isinstance(obj, (list, tuple, set)):
        for item in obj:
            _redact_obj(item, depth + 1)
        return
    if isinstance(obj, dict):
        for key, val in list(obj.items()):
            if type(val) is str:
                obj[key] = redact_text(val)
            else:
                _redact_obj(val, depth + 1)
        return
    names = []
    mf = getattr(type(obj), "model_fields", None)
    if mf:
        names = list(mf.keys())
    elif hasattr(obj, "__dict__"):
        names = list(vars(obj).keys())
    for name in names:
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        if type(val) is str:
            try:
                setattr(obj, name, redact_text(val))
            except Exception:
                pass
        else:
            _redact_obj(val, depth + 1)
