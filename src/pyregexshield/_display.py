"""Terminal display sanitization helpers."""

from __future__ import annotations

import unicodedata


def terminal_safe(value: object) -> str:
    """Return text with control and format characters visibly escaped."""

    text = str(value)
    pieces = []
    short = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for char in text:
        if char in short:
            pieces.append(short[char])
            continue
        category = unicodedata.category(char)
        if category in ("Cc", "Cf", "Cs"):
            value_ord = ord(char)
            if value_ord <= 0xFF:
                pieces.append("\\x%02X" % value_ord)
            elif value_ord <= 0xFFFF:
                pieces.append("\\u%04X" % value_ord)
            else:
                pieces.append("\\U%08X" % value_ord)
            continue
        pieces.append(char)
    return "".join(pieces)
