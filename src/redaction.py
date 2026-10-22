"""Central redaction — secretos nunca llegan a persistencia ni exportacion.

v2: redaccion por lista blanca de campos, sin recursion profunda
(los enums y objetos internos no se recorren).
"""

from __future__ import annotations

import re

_REDACTED = "[REDACTED]"

_WEBHOOK = re.compile(r"(discord(?:app)?[.]com/api/webhooks/[0-9]+/)([A-Za-z0-9_-]{6,})")
_AWSKEY = re.compile(r"AKIA[0-9A-Z]{16}")
_BEARER = re.compile(r"(Bearer[ ]+)([A-Za-z0-9_.-]{8,})")
_GENERIC = re.compile(r"(?i)(token|secret|password|api[_-]?key)[ :=]+[\"']?([A-Za-z0-9_.-]{8,})")

_TEXT_FIELDS = {"code_snippet", "title", "description", "remediation",
                "impact", "value", "raw", "snippet", "evidence", "message"}
_LIST_FIELDS = {"references", "tags"}
_DICT_FIELDS = {"metadata", "context", "extra"}


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
    for bucket in ("findings", "secrets", "payment_findings"):
        for obj in getattr(result, bucket, None) or []:
            _redact_obj(obj)


def _redact_obj(obj) -> None:
    fields = getattr(type(obj), "model_fields", None)
    if fields:
        names = list(fields.keys())
    elif hasattr(obj, "__dict__"):
        names = [k for k in vars(obj).keys() if not k.startswith("_")]
    else:
        return
    for name in names:
        try:
            val = getattr(obj, name)
        except Exception:
            continue
        if name in _TEXT_FIELDS and type(val) is str:
            try:
                setattr(obj, name, redact_text(val))
            except Exception:
                pass
        elif name in _LIST_FIELDS and isinstance(val, list):
            for i, item in enumerate(val):
                if type(item) is str:
                    val[i] = redact_text(item)
        elif name in _DICT_FIELDS and isinstance(val, dict):
            for k, v in list(val.items()):
                if type(v) is str:
                    val[k] = redact_text(v)
