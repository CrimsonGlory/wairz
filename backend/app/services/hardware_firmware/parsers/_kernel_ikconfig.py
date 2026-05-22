"""Shared IKCFG (embedded kernel-config) extraction helpers.

A Linux kernel built with ``CONFIG_IKCONFIG=y`` embeds the ``.config``
file used to build it into the kernel binary itself, bracketed by two
8-byte magic markers ``IKCFG_ST`` / ``IKCFG_ED`` (the inner payload is
always gzipped, per ``kernel/configs.c``).  The upstream extraction
contract is documented in ``linux/scripts/extract-ikconfig``.

This module is imported by:

* ``parsers/kernel_image.py`` — the per-blob parser that populates
  ``HardwareFirmwareBlob.metadata.kernel_config`` so the
  ``linux_kernel_hardening_walker`` can emit Findings later.
* ``app/ai/tools/security.py`` — the MCP-tool path that lets an
  operator ad-hoc audit a firmware via Claude.

Both surfaces share the same byte-scan + bounded decompression so a
single mitigation against IKCFG-payload gzip bombs covers both.

Wave-2 critique attack F mitigation
-----------------------------------
``gzip.decompress(blob)`` reads the FULL decompressed output into
memory with no upper bound.  A malicious kernel image can include a
small (~kB) gzip payload that expands to many GB.  We use
``gzip.GzipFile.read(_MAX_CONFIG_BYTES)`` to cap output at 4 MB — well
above any real ``.config`` (typical 100-300 kB) but bounded enough
to prevent OOM.
"""

from __future__ import annotations

import gzip
import io
import re
from typing import Any

# Magic markers bracketing the embedded gzipped .config.  Defined in
# linux/kernel/configs.c via inline asm bracketing a .incbin of the
# compiled-out config_data.gz.
IKCFG_ST = b"IKCFG_ST"
IKCFG_ED = b"IKCFG_ED"

# Per Scout B + Scout D: typical .config is 100-300 kB decompressed; cap
# at 4 MB to prevent a gzip-bomb payload from exhausting worker memory.
_MAX_CONFIG_BYTES = 4 * 1024 * 1024  # 4 MB

# Cap the COMPRESSED slice we feed to gzip — even at maximum ratio,
# 16 MB compressed should yield <4 MB decompressed after our read cap.
_MAX_GZIP_BLOB_BYTES = 16 * 1024 * 1024  # 16 MB

# `Linux version ` banner prefix used by init/version.c:linux_banner.
_LINUX_BANNER_PREFIX = b"Linux version "

# Parse the leading SemVer (major.minor.patch) from a Linux banner so
# downstream CVE matching can correlate against linux_kernel CPE rows.
_KERNEL_BANNER_SEMVER_RE = re.compile(rb"Linux version (\d+\.\d+\.\d+)")


def extract_ikconfig(data: bytes) -> str | None:
    """Extract the embedded kernel .config text from a kernel image blob.

    Returns the full ``.config`` text on success, ``None`` when no valid
    IKCFG payload is present.  Idempotent — safe to call on any input;
    a non-kernel binary just returns ``None`` quickly.

    The scan walks every ``IKCFG_ST`` occurrence (a synthetic-marker
    false positive at offset N falls through to the next match).
    Decompression is bounded at ``_MAX_CONFIG_BYTES`` to mitigate the
    Wave-2 attack F gzip-bomb path.
    """
    offset = 0
    while True:
        idx = data.find(IKCFG_ST, offset)
        if idx == -1:
            return None
        gz_start = idx + len(IKCFG_ST)
        end_idx = data.find(IKCFG_ED, gz_start)
        if end_idx == -1:
            # No closing marker found; cap the slice at _MAX_GZIP_BLOB_BYTES.
            gz_blob = data[gz_start : gz_start + _MAX_GZIP_BLOB_BYTES]
        else:
            gz_blob = data[gz_start:end_idx]
            if len(gz_blob) > _MAX_GZIP_BLOB_BYTES:
                gz_blob = gz_blob[:_MAX_GZIP_BLOB_BYTES]

        try:
            with gzip.GzipFile(fileobj=io.BytesIO(gz_blob)) as gz:
                raw = gz.read(_MAX_CONFIG_BYTES + 1)
            # If we hit the cap exactly + 1 byte, the payload was
            # oversized — treat as suspect and skip (Rule #45 parse-only
            # discipline + W2-β attack F mitigation).
            if len(raw) > _MAX_CONFIG_BYTES:
                offset = idx + 1
                continue
            config_text = raw.decode("utf-8", errors="replace")
            if "CONFIG_" in config_text:
                return config_text
        except Exception:  # noqa: BLE001
            pass

        offset = idx + 1


def parse_kernel_config_lines(config_text: str) -> dict[str, str]:
    """Parse a ``.config`` text into ``{CONFIG_FOO: 'y'|'m'|'n'|'<value>'}``.

    Line shapes handled:

    * ``CONFIG_FOO=y``                   → ``'y'``
    * ``CONFIG_FOO=m``                   → ``'m'``
    * ``CONFIG_FOO="some string"``       → ``'"some string"'`` (raw)
    * ``CONFIG_FOO=0x1000``              → ``'0x1000'``
    * ``# CONFIG_FOO is not set``        → ``'n'``

    Comment lines and blanks are skipped.  Malformed lines are skipped
    silently — a kernel ``.config`` is large + occasionally has stray
    comments; raising would break the whole parser run for one bad line.
    """
    config_map: dict[str, str] = {}
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            # `# CONFIG_FOO is not set` → 'n'
            m = re.match(r"#\s*(CONFIG_\w+)\s+is not set", line)
            if m:
                config_map[m.group(1)] = "n"
            continue
        if line.startswith("CONFIG_"):
            m = re.match(r"(CONFIG_\w+)=(.+)", line)
            if m:
                config_map[m.group(1)] = m.group(2)
    return config_map


def find_linux_banner(data: bytes) -> dict[str, Any] | None:
    """Return ``{'banner': str, 'kernel_semver': str | None}`` for a kernel image.

    Scans for the first ``Linux version `` ASCII banner emitted by
    ``init/version.c:linux_banner`` and captures the next ~256 bytes
    (typical banner len 150-200) up to the first NUL.

    Returns ``None`` when no banner is present (the file is not a
    Linux kernel, or the banner was stripped).
    """
    idx = data.find(_LINUX_BANNER_PREFIX)
    if idx == -1:
        return None
    # Banner is NUL-terminated in nearly all kernels; cap at 512 bytes
    # to bound the slice + tolerate kernels that pad with spaces.
    tail = data[idx : idx + 512]
    nul = tail.find(b"\x00")
    if nul != -1:
        tail = tail[:nul]
    try:
        banner = tail.decode("utf-8", errors="replace").strip()
    except Exception:  # noqa: BLE001
        return None

    semver: str | None = None
    m = _KERNEL_BANNER_SEMVER_RE.search(data[idx : idx + 256])
    if m:
        try:
            semver = m.group(1).decode("ascii")
        except Exception:  # noqa: BLE001
            semver = None

    return {"banner": banner, "kernel_semver": semver}
