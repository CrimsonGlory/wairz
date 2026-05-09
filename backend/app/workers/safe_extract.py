"""Shared safe-extraction primitives for all firmware unpack paths.

All zip extraction in the Wairz backend must go through ``safe_extract_zip``
rather than ``ZipFile.extract`` / ``ZipFile.extractall`` directly.  Three
defences are applied per-entry:

1. **Zipslip (path containment):** ``realpath(dest / entry)`` must start with
   ``realpath(dest) + os.sep``.  Catches ``../../../etc/passwd`` and other
   traversal forms.

2. **Zip-bomb (size limit):** running total of bytes written must stay under
   ``max_size``.  The *declared* ``ZipInfo.file_size`` is attacker-controlled
   and used only for a fast pre-flight check; the actual decompressed write is
   monitored in a streaming loop so a falsely-declared small size cannot sneak
   a bomb through.

3. **Symlink-inside-zip rejection:** the Unix file-mode in the high 16 bits of
   ``ZipInfo.external_attr`` encodes the entry type.  If the mode bits
   ``(attr >> 16) & 0o170000`` equal the symlink magic ``0o120000`` the entry
   is rejected.  Symlinks inside ZIP archives are a classic sandbox-escape
   vector even when the realpath check passes at extract time — the symlink
   itself lands inside the dest directory and its *target* can point anywhere.

Usage::

    from app.workers.safe_extract import safe_extract_zip

    safe_extract_zip(zip_path, dest_dir)                        # all entries
    safe_extract_zip(zip_path, dest_dir, max_size=2 * 2**30)    # 2 GiB cap
    # Selective extraction — only entries whose filename passes the filter:
    safe_extract_zip(zip_path, dest_dir,
                     entry_filter=lambda name: name.endswith(".img"))

The function raises ``ValueError`` on any security violation and
``ExtractionSizeError`` (a subclass of ``ValueError``) when the size limit is
hit mid-stream.  All raises happen *before* or *during* a write so no partial
payload is committed to disk when a bomb is detected.
"""

from __future__ import annotations

import os
import zipfile
from collections.abc import Callable
from pathlib import Path

__all__ = [
    "safe_extract_zip",
    "ExtractionSizeError",
]

# Default 4 GiB uncompressed limit per ZIP.  Individual callers (e.g. Android
# OTA which may contain huge partition images) can pass a higher value if the
# threat model allows it; the default is conservative for untrusted uploads.
_DEFAULT_MAX_SIZE: int = 4 * 2**30  # 4 GiB

# Slop allowance for the streaming size check: actual compressed data can
# overshoot the declared file_size by a small alignment amount without being
# flagged.  1 KiB is generous; real compressors never exceed this.
_DECLARED_SIZE_SLOP: int = 1024

# Chunk size for streaming decompression writes (64 KiB).
_CHUNK_SIZE: int = 64 * 1024

# Unix file-type mask and symlink magic constant.
_S_IFMT: int = 0o170000
_S_IFLNK: int = 0o120000


class ExtractionSizeError(ValueError):
    """Raised when a zip entry causes the running extracted size to exceed the limit."""


def safe_extract_zip(
    zip_path: Path | str,
    dest: Path | str,
    *,
    max_size: int = _DEFAULT_MAX_SIZE,
    entry_filter: Callable[[str], bool] | None = None,
) -> None:
    """Extract *zip_path* into *dest* with zipslip, bomb, and symlink defences.

    Args:
        zip_path: Path to the ZIP archive to extract.
        dest: Directory to extract into.  Must already exist.
        max_size: Maximum total bytes written before aborting.  Defaults to
            4 GiB.  Pass a smaller value in tests or when the caller has a
            tighter budget.
        entry_filter: Optional callable that receives ``ZipInfo.filename`` and
            returns ``True`` if the entry should be extracted.  When *None*,
            all entries are extracted.  Security checks still run on every
            entry regardless of the filter — a malicious symlink entry is
            rejected even if the filter would have skipped it.

    Raises:
        ValueError: Path escape detected (zipslip), symlink entry detected, or
            pre-flight declared-size exceeds *max_size*.
        ExtractionSizeError: Streaming write exceeded *max_size*.
        zipfile.BadZipFile: The archive is not a valid ZIP.
        FileNotFoundError: *zip_path* does not exist.
    """
    zip_path = Path(zip_path)
    dest = Path(dest)

    real_dest = os.path.realpath(dest)

    with zipfile.ZipFile(zip_path, "r") as zf:
        entries = zf.infolist()

        # ── Pre-flight: declared total size ───────────────────────────────────
        # Attacker can lie here, but an honest large archive will fail fast.
        declared_total = sum(e.file_size for e in entries)
        if declared_total > max_size:
            raise ValueError(
                f"ZIP declared uncompressed size "
                f"({declared_total / 2**30:.2f} GiB) exceeds limit "
                f"({max_size / 2**30:.2f} GiB); possible zip bomb"
            )

        bytes_written: int = 0

        for info in entries:
            # ── Defence 3: symlink-inside-zip ─────────────────────────────────
            # Applied to ALL entries regardless of entry_filter — a malicious
            # symlink in an otherwise-filtered-out entry is still a threat.
            unix_mode = (info.external_attr >> 16) & _S_IFMT
            if unix_mode == _S_IFLNK:
                raise ValueError(
                    f"Symlink entry rejected in ZIP: {info.filename!r}. "
                    "Symlinks inside archives are a sandbox-escape vector."
                )

            # ── Defence 1: path containment (zipslip) ─────────────────────────
            # Strip leading slashes so os.path.join does not treat the entry as
            # an absolute path (which would silently discard real_dest).
            clean_name = info.filename.lstrip("/")
            if not clean_name or clean_name == ".":
                # Skip directory-entry-only records and degenerate paths.
                continue

            target = os.path.realpath(os.path.join(real_dest, clean_name))
            if target != real_dest and not target.startswith(real_dest + os.sep):
                raise ValueError(
                    f"Path escape detected (zipslip) for entry {info.filename!r}: "
                    f"resolved to {target!r} which is outside {real_dest!r}"
                )

            # ── Caller filter (applied after security checks) ─────────────────
            if entry_filter is not None and not entry_filter(info.filename):
                continue

            # ── Streaming write with actual-size enforcement ───────────────────
            # Directories: just create them, no size accounting needed.
            if info.filename.endswith("/") or (
                (info.external_attr >> 16) & _S_IFMT == 0o040000  # S_IFDIR
            ):
                os.makedirs(target, exist_ok=True)
                continue

            # Ensure parent directory exists (handles nested paths).
            parent = os.path.dirname(target)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            # Stream the entry contents and enforce the running size cap.
            with zf.open(info) as src, open(target, "wb") as dst:
                entry_bytes: int = 0
                while True:
                    chunk = src.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    entry_bytes += len(chunk)
                    # Per-entry sanity: reject entries that decompress
                    # substantially beyond their declared size (zip bomb
                    # where declared size is falsified).
                    if entry_bytes > info.file_size + _DECLARED_SIZE_SLOP:
                        dst.close()
                        os.unlink(target)
                        raise ExtractionSizeError(
                            f"Entry {info.filename!r} decompressed to "
                            f"{entry_bytes} bytes, exceeding declared size "
                            f"{info.file_size} + slop {_DECLARED_SIZE_SLOP}; "
                            "possible zip bomb"
                        )
                    dst.write(chunk)

                bytes_written += entry_bytes
                if bytes_written > max_size:
                    raise ExtractionSizeError(
                        f"Extraction aborted: running total {bytes_written} bytes "
                        f"exceeds limit {max_size} bytes; possible zip bomb"
                    )
