"""Per-firmware memory-dump-image row (Phase λ.α.A — first memory-forensic stream).

One row per RAM acquisition file (``.raw`` / ``.dmp`` / ``.vmem`` /
``.lime`` / ``.mem`` / ``.crash``) discovered inside a firmware's
detection roots, with a minimum size gate of 100 MB (smaller files
are almost always not memory images — driver dumps, BIOS images,
or partial captures).

The row is the landing zone for Volatility 3 walker outputs (λ.β
onwards). It captures the minimum identifying metadata so a Vol3
``windows.info`` / ``linux.banners`` / ``mac.kevents`` probe can
classify the image's kernel + symbol-bundle (ISF) profile WITHOUT
re-walking the firmware tree.

Per CLAUDE.md Rule #16: writers populate from a paths helper that
resolves detection roots via ``get_detection_roots(firmware)`` —
NEVER ``firmware.extracted_path`` alone. The ``image_path`` column
stores the path RELATIVE to the detection root that contained the
file so multi-root firmware re-extraction yields stable identifiers.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — memory images are parsed via Vol3's pure-Python framework
(read-only file open + struct unpack of the underlying layers).
Wairz NEVER invokes any binary or VM resume primitive on a memory
image; the no-execute rule extends to "never `qemu-system -hda
<dump>` a memory image" exactly as it does to MSI Custom Actions.

Per CLAUDE.md Rule #45 metadata-walker discipline: future Vol3 walkers
that extract credentials / decrypt protected payloads (``hashdump``,
``lsadump``, ``cachedump``, ``truecrypt``) are DEFERRED. The Vol3
chain wairz wires is metadata-surfacing only (processes, network
endpoints, modules, persistence indicators).

Per CLAUDE.md Rule #37 offline-trust-anchor discipline: Vol3 symbol
bundles (ISF) MUST be baked into the worker image at build time
(``backend/vol3-symbols/`` directory under ``ARG INCLUDE_VOL3=1``
gate, served at ``/opt/wairz/vol3-symbols`` runtime). The
``isf_profile_guess`` column records WHICH bundle ID matched at
classification time so operators can confirm the offline-anchor
discipline held.

Indexes:

- ``ix_memory_dump_image_firmware_filename`` —
  ``(firmware_id, image_filename)`` covers the common "find the
  memory image whose basename starts with X" filter.
- ``ix_memory_dump_image_firmware_os_family`` —
  ``(firmware_id, os_family)`` covers the "all Windows / all Linux
  images for this firmware" filter used by the per-family Vol3
  walker dispatch.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MemoryDumpImage(Base):
    """Per-image row for a RAM acquisition discovered inside a firmware."""

    __tablename__ = "memory_dump_image"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this image was discovered in.
    # Cascade DELETE so removing a firmware row removes its images.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute path on the worker's view of the firmware tree. Stored
    # absolute (NOT detection-root-relative) because Vol3's CLI takes
    # an absolute ``-f`` argument and the runner subprocess will pass
    # this verbatim. Multi-root re-extraction recomputes — image rows
    # are dropped + re-added when the enumerator runs, so stable
    # cross-run identity is via ``(firmware_id, image_filename,
    # file_size)`` not by path.
    image_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Basename of the image file (e.g. ``memory.raw``, ``crash.dmp``).
    # Used in the (firmware_id, image_filename) covering index for the
    # common operator filter ("find dump named X").
    image_filename: Mapped[str] = mapped_column(String(256), nullable=False)

    # File size in bytes — BigInteger because memory images are
    # typically 4-128 GB. Used by the auto-detect threshold
    # (``MIN_MEMORY_IMAGE_BYTES`` in ``memory_image_paths.py``) and
    # surfaces in the firmware UI for capacity-planning hints.
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Magic-byte signature detected by the head probe — short string
    # (typically 4-16 bytes) describing the image format. Examples:
    # ``MDMP`` (Windows minidump), ``PAGEDU64`` (Windows kernel dump
    # 64-bit), ``PAGEDUMP`` (Windows kernel dump 32-bit),
    # ``LiME`` (Linux LiME format), ``raw`` (no recognisable magic —
    # treated as a flat acquisition; Vol3's automagic LayerStacker
    # handles it).
    magic_detected: Mapped[str] = mapped_column(String(48), nullable=False)

    # Coarse OS family guess based on magic + heuristic head bytes.
    # Values: ``windows``, ``linux``, ``mac``, ``unknown``. The full
    # kernel-version fingerprint goes into ``kernel_hint`` once a
    # walker runs ``windows.info`` / ``linux.banners`` / ``mac.kevents``.
    os_family: Mapped[str] = mapped_column(String(32), nullable=False)

    # Kernel version string from Vol3 ``windows.info`` /
    # ``linux.banners`` / ``mac.kevents`` after the first walker pass.
    # Examples: ``Windows 10 19045 x64``, ``Linux 5.15.0-91-generic``.
    # Nullable because pre-walker-pass rows are valid (the table is
    # populated by the enumerator first; walkers stamp this field
    # after).
    kernel_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # ISF symbol bundle ID that Vol3's automagic matched against this
    # image. Bundle IDs are SHA1 hashes truncated to 16 chars; values
    # like ``a1b2c3d4e5f60a1b``. NULL pre-walker-pass; stamped after.
    # Surfaces in ``vol3_runner`` for "did the right bundle match" QA.
    isf_profile_guess: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Most-recent timestamp when ANY Vol3 walker (windows.info or any
    # plugin from a windows_*_walker / linux_*_walker family) ran
    # against this image. Updated by each walker on success. NULL
    # until the first walker pass completes.
    last_walked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # Common filter: "find the dump named X for firmware Y".
        Index(
            "ix_memory_dump_image_firmware_filename",
            "firmware_id",
            "image_filename",
        ),
        # OS-family dispatch: walkers iterate "all Windows images" or
        # "all Linux images" per firmware. Composite covers the filter
        # without a table scan even on a 100-image firmware.
        Index(
            "ix_memory_dump_image_firmware_os_family",
            "firmware_id",
            "os_family",
        ),
    )
