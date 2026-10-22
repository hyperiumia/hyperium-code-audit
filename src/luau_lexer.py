"""Minimal Luau masking (Fase 6.4) - comentarios y literales enmascarados.

Preserva longitud y saltos de linea: las posiciones de los hallazgos no
se desplazan. Solo lo usa el scope 'code' de las reglas; el scope
'content' sigue analizando el texto crudo (URLs, literales).
"""

from __future__ import annotations

ESC = chr(92)   # barra invertida literal
NL = chr(10)   # salto de linea literal


def _long_bracket_end(src: str, i: int):
    """src[i] == '[' — devuelve fin de [[...]] / [=[...]=] o None."""
    j = i + 1
    eq = 0
    while j < len(src) and src[j] == "=":
        eq += 1
        j += 1
    if j < len(src) and src[j] == "[":
        close = "]" + "=" * eq + "]"
        k = src.find(close, j + 1)
        return (k + len(close)) if k != -1 else len(src)
    return None


def mask_comments_and_strings(source: str) -> str:
    """Enmascara comentarios y literales por espacios (newlines intactas)."""
    out = list(source)
    n = len(source)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != NL:
                out[k] = " "

    i = 0
    while i < n:
        ch = source[i]
        if ch == "-" and source[i:i + 2] == "--":
            end = None
            if source[i + 2:i + 3] == "[":
                end = _long_bracket_end(source, i + 2)
            if end is None:
                j = source.find(NL, i)
                end = n if j == -1 else j
            blank(i, end)
            i = end
            continue
        if ch == '"' or ch == "'":
            j = i + 1
            while j < n:
                if source[j] == ESC:
                    j += 2
                    continue
                if source[j] == ch:
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        if ch == "[":
            end = _long_bracket_end(source, i)
            if end is not None:
                blank(i, end)
                i = end
                continue
        i += 1
    return "".join(out)
