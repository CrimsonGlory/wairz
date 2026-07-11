"""Helpers that neutralize log-injection vectors (CR/LF/control chars).

CodeQL ``py/log-injection`` treats path params, filenames, and exception
messages as attacker-controlled. Newline characters in those values can
forge multi-line log entries. Explicit ``str.replace`` of ``\\r``/``\\n``
is recognized as a sanitizer barrier by the CodeQL Python library.
"""

from __future__ import annotations

import re

# Strip remaining C0 controls (except the ones we already escaped) so a
# crafted value cannot smuggle BEL/ESC sequences into operator terminals.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_for_log(value: object, *, max_len: int = 500) -> str:
    """Return a single-line, length-bounded string safe for log interpolation.

    Parameters
    ----------
    value:
        Any object; converted with ``str()``.
    max_len:
        Hard cap so a multi-megabyte path/payload cannot blow up log volume.
    """
    text = str(value)
    # Order matters for CodeQL: explicit replace of CR/LF is the barrier.
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text
